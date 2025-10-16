package login

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/ikiris/eqmaclib/eqdb"
)

func TestDiscoveryEndpoint(t *testing.T) {
	// Create a test server with mock dependencies
	server, err := createTestServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		path           string
		host           string
		tls            bool
		expectedStatus int
		expectedIssuer string
	}{
		{
			name:           "HTTPS discovery request",
			method:         "GET",
			path:           "/.well-known/openid-configuration",
			host:           "localhost:8443",
			tls:            true,
			expectedStatus: 200,
			expectedIssuer: "https://localhost:8443",
		},
		{
			name:           "HTTP discovery request",
			method:         "GET",
			path:           "/.well-known/openid-configuration",
			host:           "localhost:8080",
			tls:            false,
			expectedStatus: 200,
			expectedIssuer: "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(tt.method, fmt.Sprintf("http://%s%s", tt.host, tt.path), nil)
			if tt.tls {
				req.TLS = &tls.ConnectionState{} // Mock TLS
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call discovery handler
			server.handleDiscovery(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check content type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
			}

			// Parse response body
			var discovery map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &discovery); err != nil {
				t.Errorf("Failed to parse JSON response: %v", err)
				t.Logf("Response body: %s", w.Body.String())
				return
			}

			// Check issuer
			issuer, ok := discovery["issuer"].(string)
			if !ok {
				t.Errorf("Expected issuer to be a string, got %T", discovery["issuer"])
				return
			}

			if issuer != tt.expectedIssuer {
				t.Errorf("Expected issuer '%s', got '%s'", tt.expectedIssuer, issuer)
			}

			// Log the full response for debugging
			t.Logf("Discovery response: %s", w.Body.String())
		})
	}
}

// mockDB implements the eqDBClient interface for testing
type mockDB struct{}

func (m *mockDB) ValidateCredentials(ctx context.Context, username, password string) (*eqdb.Account, error) {
	// Mock implementation - return a test account for any credentials
	return &eqdb.Account{
		Name: username,
		// Add other required fields as needed
	}, nil
}

func (m *mockDB) GetAccount(ctx context.Context, name string) (*eqdb.Account, error) {
	// Mock implementation - return a test account
	return &eqdb.Account{
		Name: name,
		// Add other required fields as needed
	}, nil
}

func createTestServer() (*server, error) {
	// Create a mock database instead of connecting to real MySQL
	mockDB := &mockDB{}

	// Create mock key manager
	keyManager, err := newMockKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create mock key manager: %w", err)
	}

	// Create auth code manager
	authCodeManager := NewAuthCodeManager(keyManager)

	// Create mock clients
	clients := &clientRegistry{
		clients: map[string]ClientConfig{
			"test-client": {
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"http://localhost:8081/callback"},
			},
		},
	}

	return &server{
		db:              mockDB,
		clients:         clients,
		keyManager:      keyManager,
		authCodeManager: authCodeManager,
	}, nil
}

func newMockKeyManager() (*keyManager, error) {
	// Create a minimal mock key manager for testing
	// This is a simplified version that just needs to not panic
	return &keyManager{}, nil
}
