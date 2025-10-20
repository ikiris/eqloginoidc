package login

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// createMockDB creates a mock *sql.DB for testing
func createMockDB() *sql.DB {
	// Create a minimal in-memory database that can be used with eqdb.New
	// We'll use a simple approach: create a real sql.DB but with a mock driver
	return &sql.DB{}
}

func setupTestServer(t *testing.T) (*server, func()) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "eqloginoidc-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create test client config file
	configPath := filepath.Join(tempDir, "clients.yaml")
	configContent := `clients:
  - id: "test-client"
    name: "Test Client"
    client_type: "public"
    redirect_uris:
      - "https://example.com/callback"
      - "https://example.com/callback/"
    grant_types:
      - "authorization_code"
      - "refresh_token"
    response_types:
      - "code"
    scopes:
      - "openid"
      - "profile"
      - "email"
    require_https: true
    pkce_required: true
  - id: "eqtestcopy-spa"
    name: "EQ Test Copy"
    client_type: "public"
    redirect_uris:
      - "https://xevcopy.teraptra.net/callback"
    grant_types:
      - "authorization_code"
      - "refresh_token"
    response_types:
      - "code"
    scopes:
      - "openid"
      - "profile"
      - "email"
    require_https: true
    pkce_required: true`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create test certificate and key files
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")

	// Generate self-signed certificate for testing
	if err := generateTestCert(certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	// Create server with mock SQL DB
	mockDB := createMockDB()
	server, err := New(context.Background(), mockDB, configPath, certPath, keyPath, "https://test.example.com")
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return server, cleanup
}

func generateTestCert(certPath, keyPath string) error {
	// For now, create dummy files - in a real test you'd generate actual certs
	certContent := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAK7L4Q==
-----END CERTIFICATE-----`
	keyContent := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7y4Q==
-----END PRIVATE KEY-----`

	if err := os.WriteFile(certPath, []byte(certContent), 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, []byte(keyContent), 0644)
}

func TestServer_HandleAuth_RedirectURI(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	tests := []struct {
		name           string
		queryParams    map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "valid redirect URI - exact match",
			queryParams: map[string]string{
				"client_id":             "eqtestcopy-spa",
				"response_type":         "code",
				"redirect_uri":          "https://xevcopy.teraptra.net/callback",
				"scope":                 "openid profile email",
				"state":                 "test-state",
				"code_challenge":        "test-challenge",
				"code_challenge_method": "S256",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "valid redirect URI - with trailing slash",
			queryParams: map[string]string{
				"client_id":             "eqtestcopy-spa",
				"response_type":         "code",
				"redirect_uri":          "https://xevcopy.teraptra.net/callback/",
				"scope":                 "openid profile email",
				"state":                 "test-state",
				"code_challenge":        "test-challenge",
				"code_challenge_method": "S256",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "valid redirect URI - different case",
			queryParams: map[string]string{
				"client_id":             "eqtestcopy-spa",
				"response_type":         "code",
				"redirect_uri":          "https://XEVCOPY.TERAPTRA.NET/CALLBACK",
				"scope":                 "openid profile email",
				"state":                 "test-state",
				"code_challenge":        "test-challenge",
				"code_challenge_method": "S256",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid redirect URI - not in allowed list",
			queryParams: map[string]string{
				"client_id":             "eqtestcopy-spa",
				"response_type":         "code",
				"redirect_uri":          "https://malicious.com/callback",
				"scope":                 "openid profile email",
				"state":                 "test-state",
				"code_challenge":        "test-challenge",
				"code_challenge_method": "S256",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "invalid redirect URI - wrong domain",
			queryParams: map[string]string{
				"client_id":             "eqtestcopy-spa",
				"response_type":         "code",
				"redirect_uri":          "https://xevcopy.teraptra.net/wrong",
				"scope":                 "openid profile email",
				"state":                 "test-state",
				"code_challenge":        "test-challenge",
				"code_challenge_method": "S256",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query string
			values := url.Values{}
			for key, value := range tt.queryParams {
				values.Set(key, value)
			}

			req := httptest.NewRequest("GET", "/auth?"+values.Encode(), nil)
			rr := httptest.NewRecorder()

			server.handleAuth(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handleAuth() status = %v, want %v", rr.Code, tt.expectedStatus)
			}

			if tt.expectedError != "" {
				var errorResponse map[string]string
				if err := json.Unmarshal(rr.Body.Bytes(), &errorResponse); err != nil {
					t.Errorf("handleAuth() invalid JSON error response: %v", err)
					return
				}
				if errorResponse["error"] != tt.expectedError {
					t.Errorf("handleAuth() error = %v, want %v", errorResponse["error"], tt.expectedError)
				}
			}
		})
	}
}

func TestServer_HandleAuth_YourSpecificCase(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test the exact URL from your issue
	queryParams := map[string]string{
		"response_type":         "code",
		"client_id":             "eqtestcopy-spa",
		"redirect_uri":          "https://xevcopy.teraptra.net/callback",
		"scope":                 "openid profile email",
		"code_challenge":        "yRCiPcjb9g0_IA6sNqtcFy_lhQe_y2s2RWNH0ab99v8",
		"code_challenge_method": "S256",
		"state":                 "xB9mPkw0t3rXeuPT_b8qMA",
	}

	values := url.Values{}
	for key, value := range queryParams {
		values.Set(key, value)
	}

	req := httptest.NewRequest("GET", "/auth?"+values.Encode(), nil)
	rr := httptest.NewRecorder()

	server.handleAuth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Your specific case failed with status %v", rr.Code)
		if rr.Body.Len() > 0 {
			t.Errorf("Error response: %s", rr.Body.String())
		}
	}
}

func TestServer_HandleDiscovery(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/.well-known/openid_configuration", nil)
	rr := httptest.NewRecorder()

	server.handleDiscovery(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleDiscovery() status = %v, want %v", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("handleDiscovery() invalid JSON response: %v", err)
		return
	}

	expectedFields := []string{"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint"}
	for _, field := range expectedFields {
		if _, exists := response[field]; !exists {
			t.Errorf("handleDiscovery() missing field: %s", field)
		}
	}
}
