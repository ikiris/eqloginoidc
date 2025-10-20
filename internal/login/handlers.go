package login

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//go:embed templates/*
var templates embed.FS

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.ParseFS(templates, "templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

// handleHome serves the home page
func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.ExecuteTemplate(w, "home.html", nil); err != nil {
		slog.Error("Failed to execute template", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// getBaseURL returns the base URL for the current request
func getBaseURL(r *http.Request) string {
	scheme := "https"
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

// handleDiscovery serves the OIDC discovery document
func (s *server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	baseURL := getBaseURL(r)

	discovery := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/auth",
		"token_endpoint":                        baseURL + "/token",
		"userinfo_endpoint":                     baseURL + "/userinfo",
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		slog.Error("Failed to encode discovery", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleJWKS serves the JSON Web Key Set
func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.keyManager.getJWKS()
	if err != nil {
		slog.Error("Failed to get JWKS", "error", err)

		http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		slog.Error("Failed to encode JWKS", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleAuth handles the authorization endpoint
func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	// Get OAuth2 parameters
	clientID := r.URL.Query().Get("client_id")
	responseType := r.URL.Query().Get("response_type")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// Validate client
	if _, err := s.clients.validateClient(clientID); err != nil {
		s.writeOAuthError(w, "invalid_client", "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate response type
	if err := s.clients.ValidateResponseType(clientID, responseType); err != nil {
		s.writeOAuthError(w, "unsupported_response_type", "Unsupported response_type", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	if err := s.clients.validateRedirectURI(clientID, redirectURI); err != nil {
		s.writeOAuthError(w, "invalid_request", "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Check PKCE requirements
	if s.clients.requiresPKCE(clientID) {
		if codeChallenge == "" {
			s.writeOAuthError(w, "invalid_request", "code_challenge is required for this client", http.StatusBadRequest)
			return
		}

		// Validate challenge method
		if err := validateCodeChallengeMethod(codeChallengeMethod); err != nil {
			s.writeOAuthError(w, "invalid_request", err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Show login form
	data := map[string]interface{}{
		"RedirectURI":         redirectURI,
		"State":               state,
		"ClientID":            clientID,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		slog.Error("Failed to execute template", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleLogin processes the login form
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	clientID := r.FormValue("client_id")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	if username == "" || password == "" {
		data := map[string]interface{}{
			"Error":               "Username and password required",
			"RedirectURI":         redirectURI,
			"State":               state,
			"ClientID":            clientID,
			"CodeChallenge":       codeChallenge,
			"CodeChallengeMethod": codeChallengeMethod,
		}
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
			slog.Error("Failed to execute template", "error", err)

			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		return
	}

	// Validate credentials against EQ database
	account, err := s.db.ValidateCredentials(r.Context(), username, password)
	if err != nil {
		log.Printf("Authentication failed for user %s: %v", username, err)
		data := map[string]interface{}{
			"Error":               "Invalid credentials",
			"RedirectURI":         redirectURI,
			"State":               state,
			"ClientID":            clientID,
			"CodeChallenge":       codeChallenge,
			"CodeChallengeMethod": codeChallengeMethod,
		}
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
			slog.Error("Failed to execute template", "error", err)

			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		return
	}

	if account.Revoked {
		data := map[string]interface{}{
			"Error":               "Account is revoked",
			"RedirectURI":         redirectURI,
			"State":               state,
			"ClientID":            clientID,
			"CodeChallenge":       codeChallenge,
			"CodeChallengeMethod": codeChallengeMethod,
		}
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
			slog.Error("Failed to execute template", "error", err)

			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		return
	}

	// Generate authorization code using real user data
	authCode, err := s.authCodeManager.GenerateAuthCode(
		account.ID,
		account.Name, // Using Name field as username
		"",           // Email not available in current Account struct
		clientID,
		redirectURI,
		codeChallenge,
		codeChallengeMethod,
		getBaseURL(r),
	)
	if err != nil {
		log.Printf("Failed to generate authorization code: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Redirect back to client with authorization code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken handles the token endpoint
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Log token exchange attempt
	slog.Info("Token exchange attempt",
		"grant_type", grantType,
		"client_id", clientID,
		"redirect_uri", redirectURI,
		"has_code", code != "",
		"has_verifier", codeVerifier != "",
	)

	// Validate client
	if _, err := s.clients.validateClient(clientID); err != nil {
		slog.Error("Token exchange failed: invalid client", "client_id", clientID, "error", err)
		s.writeOAuthError(w, "invalid_client", "Invalid client_id", http.StatusBadRequest)
		return
	}
	slog.Info("Client validation passed", "client_id", clientID)

	// Validate client authentication (handles both confidential and public clients)
	if err := s.clients.validateClientAuthentication(clientID, clientSecret); err != nil {
		slog.Error("Token exchange failed: client authentication", "client_id", clientID, "error", err)
		s.writeOAuthError(w, "invalid_client", err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("Client authentication passed", "client_id", clientID)

	// Validate grant type
	if err := s.clients.ValidateGrantType(clientID, grantType); err != nil {
		slog.Error("Token exchange failed: unsupported grant type", "client_id", clientID, "grant_type", grantType, "error", err)
		s.writeOAuthError(w, "unsupported_grant_type", "Unsupported grant_type", http.StatusBadRequest)
		return
	}
	slog.Info("Grant type validation passed", "grant_type", grantType)

	if grantType == "refresh_token" {
		s.handleRefreshToken(w, r)
		return
	}

	// For authorization_code grant, validate redirect URI
	if grantType == "authorization_code" {
		if err := s.clients.validateRedirectURI(clientID, redirectURI); err != nil {
			slog.Error("Token exchange failed: invalid redirect URI", "client_id", clientID, "redirect_uri", redirectURI, "error", err)
			s.writeOAuthError(w, "invalid_request", "Invalid redirect_uri", http.StatusBadRequest)
			return
		}
		slog.Info("Redirect URI validation passed", "redirect_uri", redirectURI)
	}

	// Validate authorization code
	authCodeClaims, err := s.authCodeManager.ValidateAuthCode(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		slog.Error("Token exchange failed: invalid auth code", "client_id", clientID, "error", err)
		s.writeOAuthError(w, "invalid_grant", "Invalid or expired authorization code", http.StatusBadRequest)
		return
	}
	slog.Info("Auth code validation passed", "account_id", authCodeClaims.AccountID)

	// Extract user data from validated authorization code
	now := time.Now()
	userID := fmt.Sprintf("%d", authCodeClaims.AccountID)
	userEmail := authCodeClaims.Email
	userName := authCodeClaims.Username

	// Get signing key
	signingKey, err := s.keyManager.getSigningKey()
	if err != nil {
		http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
		return
	}

	// Create ID token (this is what the Resource Server will verify)
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                getBaseURL(r),
		"sub":                userID,                    // User identifier
		"aud":                clientID,                  // Client ID
		"exp":                now.Add(time.Hour).Unix(), // 1 hour expiry
		"iat":                now.Unix(),
		"email":              userEmail,
		"name":               userName,
		"preferred_username": userName,
		"email_verified":     true,
	})

	// Set key ID in header
	idToken.Header["kid"] = s.keyManager.getKeyID()

	idTokenString, err := idToken.SignedString(signingKey)
	if err != nil {
		http.Error(w, "Failed to create ID token", http.StatusInternalServerError)
		return
	}

	// Create access token (shorter expiry)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   getBaseURL(r),
		"sub":   userID,
		"aud":   clientID,
		"exp":   now.Add(15 * time.Minute).Unix(), // 15 minute expiry
		"iat":   now.Unix(),
		"scope": "openid profile email",
	})

	// Set key ID in header
	accessToken.Header["kid"] = s.keyManager.getKeyID()

	accessTokenString, err := accessToken.SignedString(signingKey)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	// Create refresh token (longer expiry)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":  getBaseURL(r),
		"sub":  userID,
		"aud":  clientID,
		"exp":  now.Add(7 * 24 * time.Hour).Unix(), // 7 day expiry
		"iat":  now.Unix(),
		"type": "refresh",
	})

	// Set key ID in header
	refreshToken.Header["kid"] = s.keyManager.getKeyID()

	refreshTokenString, err := refreshToken.SignedString(signingKey)
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	// Return tokens
	response := map[string]interface{}{
		"access_token":  accessTokenString,
		"id_token":      idTokenString,
		"refresh_token": refreshTokenString,
		"token_type":    "Bearer",
		"expires_in":    900, // 15 minutes
		"scope":         "openid profile email",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode response", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleRefreshToken handles refresh token requests
func (s *server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenString := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if refreshTokenString == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}

	// Validate client
	if _, err := s.clients.validateClient(clientID); err != nil {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate client authentication (handles both confidential and public clients)
	if err := s.clients.validateClientAuthentication(clientID, clientSecret); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get signing key for verification
	signingKey, err := s.keyManager.getSigningKey()
	if err != nil {
		http.Error(w, "Failed to get signing key", http.StatusInternalServerError)
		return
	}

	// Parse and validate refresh token
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &signingKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		return
	}

	// Check if it's actually a refresh token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "refresh" {
		http.Error(w, "Invalid token type", http.StatusBadRequest)
		return
	}

	// Generate new access token
	now := time.Now()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   getBaseURL(r),
		"sub":   claims["sub"],
		"aud":   clientID,
		"exp":   now.Add(15 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"scope": "openid profile email",
	})

	// Set key ID in header
	accessToken.Header["kid"] = s.keyManager.getKeyID()

	accessTokenString, err := accessToken.SignedString(signingKey)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	// Generate new refresh token (rotate for security)
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":  getBaseURL(r),
		"sub":  claims["sub"],
		"aud":  clientID,
		"exp":  now.Add(7 * 24 * time.Hour).Unix(),
		"iat":  now.Unix(),
		"type": "refresh",
	})

	// Set key ID in header
	newRefreshToken.Header["kid"] = s.keyManager.getKeyID()

	newRefreshTokenString, err := newRefreshToken.SignedString(signingKey)
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)

		return
	}

	// Return new tokens
	response := map[string]interface{}{
		"access_token":  accessTokenString,
		"refresh_token": newRefreshTokenString,
		"token_type":    "Bearer",
		"expires_in":    900, // 15 minutes
		"scope":         "openid profile email",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode response", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleUserInfo handles the userinfo endpoint
func (s *server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Get authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)

		return
	}

	// Extract token from "Bearer <token>" format
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)

		return
	}

	// Get signing key for verification
	signingKey, err := s.keyManager.getSigningKey()
	if err != nil {
		http.Error(w, "Failed to get signing key", http.StatusInternalServerError)

		return
	}

	// Parse and validate the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &signingKey.PublicKey, nil
	})

	if err != nil || !parsedToken.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)

		return
	}

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)

		return
	}

	// Return user info
	userInfo := map[string]interface{}{
		"sub":                claims["sub"],
		"email":              claims["email"],
		"name":               claims["name"],
		"preferred_username": claims["preferred_username"],
		"email_verified":     claims["email_verified"],
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		slog.Error("Failed to encode user info", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// writeOAuthError writes OAuth2 standard error response
func (s *server) writeOAuthError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	}); err != nil {
		slog.Error("Failed to encode error", "error", err)

		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
