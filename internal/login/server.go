package login

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/ikiris/eqmaclib/eqdb"
)

// eqDBClient interface for dependency injection and testing
type eqDBClient interface {
	ValidateCredentials(ctx context.Context, username, password string) (*eqdb.Account, error)
	GetAccount(ctx context.Context, name string) (*eqdb.Account, error)
}

// server represents the OIDC provider server
type server struct {
	db              eqDBClient
	clients         *clientRegistry
	keyManager      *keyManager
	authCodeManager *AuthCodeManager
	corsOrigin      string
}

// New creates a new OIDC provider server
func New(ctx context.Context, db *sql.DB, configPath, certPath, keyPath, corsOrigin string) (*server, error) {
	eqDB, err := eqdb.New(db)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	clients, err := loadClientConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client config: %w", err)
	}

	// Initialize key manager with certificate and private key
	keyManager, err := newKeyManager(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}

	// Initialize authorization code manager
	authCodeManager := NewAuthCodeManager(keyManager)

	return &server{
		db:              eqDB,
		clients:         clients,
		keyManager:      keyManager,
		authCodeManager: authCodeManager,
		corsOrigin:      corsOrigin,
	}, nil
}

// Register sets up the OIDC provider routes
func (s *server) Register() {
	// OIDC Discovery endpoint
	http.HandleFunc("/.well-known/openid-configuration", s.corsMiddleware(s.handleDiscovery))

	// JWKS endpoint
	http.HandleFunc("/.well-known/jwks.json", s.corsMiddleware(s.handleJWKS))

	// Authorization endpoint
	http.HandleFunc("/auth", s.handleAuth)

	// Token endpoint with CORS validation based on redirect URI
	http.HandleFunc("/token", s.tokenCorsMiddleware(s.handleToken))

	// UserInfo endpoint
	http.HandleFunc("/userinfo", s.corsMiddleware(s.handleUserInfo))

	// Login page
	http.HandleFunc("/login", s.handleLogin)

	// Home page
	http.HandleFunc("/", s.handleHome)
}

// corsMiddleware adds CORS headers for cross-origin requests
func (s *server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// For OIDC discovery and JWKS endpoints, allow all origins
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

// tokenCorsMiddleware adds CORS headers for token endpoint based on redirect URI
func (s *server) tokenCorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// For token endpoint, validate CORS based on the redirect_uri in the request
		origin := r.Header.Get("Origin")
		redirectURI := r.FormValue("redirect_uri")

		if origin != "" && redirectURI != "" {
			// Extract origin from redirect URI
			if strings.HasPrefix(redirectURI, "https://") || strings.HasPrefix(redirectURI, "http://") {
				// Simple origin extraction - in production you'd want more robust parsing
				parts := strings.Split(redirectURI[8:], "/")
				if len(parts) > 0 {
					redirectOrigin := "https://" + parts[0]
					if origin == redirectOrigin {
						w.Header().Set("Access-Control-Allow-Origin", origin)
					}
				}
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

// isOriginAllowed checks if the given origin is in the allowed list
func (s *server) isOriginAllowed(origin string) bool {
	// Split the corsOrigin by comma and check if the origin matches any allowed origin
	allowedOrigins := strings.Split(s.corsOrigin, ",")
	for _, allowedOrigin := range allowedOrigins {
		if strings.TrimSpace(allowedOrigin) == origin {
			return true
		}
	}
	return false
}

// GetTLSConfig returns the TLS configuration using the server's certificate
func (s *server) GetTLSConfig() (*tls.Config, error) {
	return s.keyManager.GetTLSConfig()
}
