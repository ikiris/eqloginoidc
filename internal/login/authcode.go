package login

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthCodeManager manages stateless JWT authorization codes
type AuthCodeManager struct {
	keyManager *keyManager
}

// AuthCodeClaims represents the claims in an authorization code JWT
type AuthCodeClaims struct {
	AccountID           int32  `json:"account_id"`
	Username            string `json:"username"`
	Email               string `json:"email"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	jwt.RegisteredClaims
}

// NewAuthCodeManager creates a new authorization code manager
func NewAuthCodeManager(keyManager *keyManager) *AuthCodeManager {
	return &AuthCodeManager{
		keyManager: keyManager,
	}
}

// GenerateAuthCode creates a stateless JWT authorization code
func (acm *AuthCodeManager) GenerateAuthCode(accountID int32, username, email, clientID, redirectURI, codeChallenge, codeChallengeMethod, baseURL string) (string, error) {
	// Get signing key
	signingKey, err := acm.keyManager.getSigningKey()
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	now := time.Now()

	// Create claims
	claims := AuthCodeClaims{
		AccountID:           accountID,
		Username:            username,
		Email:               email,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    baseURL,
			Subject:   fmt.Sprintf("%d", accountID),
			Audience:  []string{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)), // 60 second expiry
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set key ID in header
	token.Header["kid"] = acm.keyManager.getKeyID()

	// Sign token
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign authorization code: %w", err)
	}

	return tokenString, nil
}

// ValidateAuthCode validates and parses an authorization code JWT
func (acm *AuthCodeManager) ValidateAuthCode(code, clientID, redirectURI, codeVerifier string) (*AuthCodeClaims, error) {
	// Get public key for verification
	signingKey, err := acm.keyManager.getSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(code, &AuthCodeClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &signingKey.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization code: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid authorization code")
	}

	// Extract claims
	claims, ok := token.Claims.(*AuthCodeClaims)
	if !ok {
		return nil, fmt.Errorf("invalid authorization code claims")
	}

	// Validate client ID
	if claims.ClientID != clientID {
		return nil, fmt.Errorf("authorization code client_id mismatch")
	}

	// Validate redirect URI
	if claims.RedirectURI != redirectURI {
		return nil, fmt.Errorf("authorization code redirect_uri mismatch")
	}

	// Validate PKCE if challenge is present
	if claims.CodeChallenge != "" {
		if err := validateCodeChallenge(codeVerifier, claims.CodeChallenge, claims.CodeChallengeMethod); err != nil {
			return nil, fmt.Errorf("PKCE validation failed: %w", err)
		}
	}

	return claims, nil
}
