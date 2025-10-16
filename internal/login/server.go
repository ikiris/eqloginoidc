package login

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"

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
}

// New creates a new OIDC provider server
func New(ctx context.Context, db *sql.DB, configPath, certPath, keyPath string) (*server, error) {
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

	// Token endpoint with CORS
	http.HandleFunc("/token", s.corsMiddleware(s.handleToken))

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
		// Set CORS headers BEFORE any other headers or response
		w.Header().Set("Access-Control-Allow-Origin", "https://localhost:3000")
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

// GetTLSConfig returns the TLS configuration using the server's certificate
func (s *server) GetTLSConfig() (*tls.Config, error) {
	return s.keyManager.GetTLSConfig()
}
