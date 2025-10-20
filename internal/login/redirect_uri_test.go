package login

import (
	"testing"
)

func TestValidateRedirectURI_YourSpecificCase(t *testing.T) {
	// Create a client registry with your specific client
	clients := &clientRegistry{
		clients: map[string]ClientConfig{
			"eqtestcopy-spa": {
				ID:           "eqtestcopy-spa",
				Name:         "EQ Test Copy",
				ClientType:   "public",
				RedirectURIs: []string{"https://xevcopy.teraptra.net/callback"},
				RequireHTTPS: true,
			},
		},
	}

	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		wantErr     bool
	}{
		{
			name:        "your exact case - exact match",
			clientID:    "eqtestcopy-spa",
			redirectURI: "https://xevcopy.teraptra.net/callback",
			wantErr:     false,
		},
		{
			name:        "your exact case - with trailing slash",
			clientID:    "eqtestcopy-spa",
			redirectURI: "https://xevcopy.teraptra.net/callback/",
			wantErr:     false,
		},
		{
			name:        "your exact case - different case",
			clientID:    "eqtestcopy-spa",
			redirectURI: "https://XEVCOPY.TERAPTRA.NET/CALLBACK",
			wantErr:     false,
		},
		{
			name:        "your exact case - mixed case",
			clientID:    "eqtestcopy-spa",
			redirectURI: "https://XevCopy.Teraptra.Net/Callback",
			wantErr:     false,
		},
		{
			name:        "invalid - wrong domain",
			clientID:    "eqtestcopy-spa",
			redirectURI: "https://malicious.com/callback",
			wantErr:     true,
		},
		{
			name:        "invalid - wrong path",
			clientID:    "eqtestcopy-spa",
			redirectURI: "https://xevcopy.teraptra.net/wrong",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := clients.validateRedirectURI(tt.clientID, tt.redirectURI)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateRedirectURI() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("validateRedirectURI() unexpected error = %v", err)
				}
			}
		})
	}
}
