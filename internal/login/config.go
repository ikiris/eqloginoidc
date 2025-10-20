package login

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ClientConfig represents a single OAuth client configuration
type ClientConfig struct {
	ID            string   `yaml:"id"`
	Secret        string   `yaml:"secret,omitempty"` // Optional for public clients
	Name          string   `yaml:"name"`
	ClientType    string   `yaml:"client_type"` // "confidential" or "public"
	RedirectURIs  []string `yaml:"redirect_uris"`
	GrantTypes    []string `yaml:"grant_types"`
	ResponseTypes []string `yaml:"response_types"`
	Scopes        []string `yaml:"scopes"`
	RequireHTTPS  bool     `yaml:"require_https"`
	PKCERequired  bool     `yaml:"pkce_required"` // Required for public clients
}

// ClientsConfig represents the complete clients configuration
type ClientsConfig struct {
	Clients []ClientConfig `yaml:"clients"`
}

// clientRegistry holds the loaded client configurations
type clientRegistry struct {
	clients map[string]ClientConfig
}

// SafeClientConfig represents a client configuration for logging (without secrets)
type SafeClientConfig struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ClientType    string   `json:"client_type"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scopes        []string `json:"scopes"`
	RequireHTTPS  bool     `json:"require_https"`
	PKCERequired  bool     `json:"pkce_required"`
	HasSecret     bool     `json:"has_secret"` // Indicates if a secret is configured
}

// SafeClientsConfig represents the complete clients configuration for logging
type SafeClientsConfig struct {
	Clients []SafeClientConfig `json:"clients"`
}

// loadClientConfig loads client configurations from a YAML file
func loadClientConfig(configPath string) (*clientRegistry, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ClientsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Log the loaded configuration (without secrets)
	logLoadedConfig(config)

	registry := &clientRegistry{
		clients: make(map[string]ClientConfig),
	}

	for _, client := range config.Clients {
		registry.clients[client.ID] = client
	}

	return registry, nil
}

// validateClient checks if a client ID is registered
func (cr *clientRegistry) validateClient(clientID string) (*ClientConfig, error) {
	client, exists := cr.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("invalid client_id: %s", clientID)
	}

	return &client, nil
}

// validateRedirectURI checks if a redirect URI is allowed for the client
func (cr *clientRegistry) validateRedirectURI(clientID, redirectURI string) error {
	client, err := cr.validateClient(clientID)
	if err != nil {
		return fmt.Errorf("invalid client_id: %w", err)
	}

	// Parse the redirect URI to validate format
	parsedURI, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %w", err)
	}

	// Check if HTTPS is required
	if client.RequireHTTPS && parsedURI.Scheme != "https" {
		return fmt.Errorf("redirect_uri must use HTTPS")
	}

	// Check if the redirect URI is in the allowed list
	for _, allowedURI := range client.RedirectURIs {
		if normalizeURI(redirectURI) == normalizeURI(allowedURI) {
			return nil
		}
	}

	return fmt.Errorf("redirect_uri not allowed for client")
}

// ValidateGrantType checks if the grant type is supported by the client
func (cr *clientRegistry) ValidateGrantType(clientID, grantType string) error {
	client, err := cr.validateClient(clientID)
	if err != nil {
		return err
	}

	for _, allowedType := range client.GrantTypes {
		if allowedType == grantType {
			return nil
		}
	}

	return fmt.Errorf("grant_type not supported by client")
}

// ValidateResponseType checks if the response type is supported by the client
func (cr *clientRegistry) ValidateResponseType(clientID, responseType string) error {
	client, err := cr.validateClient(clientID)
	if err != nil {
		return err
	}

	for _, allowedType := range client.ResponseTypes {
		if allowedType == responseType {
			return nil
		}
	}

	return fmt.Errorf("response_type not supported by client")
}

// normalizeURI normalizes a URI for comparison by removing trailing slashes and converting to lowercase
func normalizeURI(uri string) string {
	uri = strings.ToLower(uri)
	uri = strings.TrimRight(uri, "/")
	return uri
}

// requiresPKCE checks if the client requires PKCE
func (cr *clientRegistry) requiresPKCE(clientID string) bool {
	client, err := cr.validateClient(clientID)
	if err != nil {
		return false
	}

	return client.PKCERequired
}

// validateClientAuthentication validates client authentication based on client type
func (cr *clientRegistry) validateClientAuthentication(clientID, clientSecret string) error {
	client, err := cr.validateClient(clientID)
	if err != nil {
		return err
	}

	// Public clients don't need client secrets
	if client.ClientType == "public" {
		if clientSecret != "" {
			return fmt.Errorf("public clients should not provide client_secret")
		}

		return nil
	}

	// Confidential clients must provide correct client secret
	if client.ClientType == "confidential" {
		if clientSecret == "" {
			return fmt.Errorf("confidential clients must provide client_secret")
		}
		if client.Secret != clientSecret {
			return fmt.Errorf("invalid client_secret")
		}

		return nil
	}

	return fmt.Errorf("unknown client_type: %s", client.ClientType)
}

// logLoadedConfig logs the loaded client configuration without exposing secrets
func logLoadedConfig(config ClientsConfig) {
	safeConfig := SafeClientsConfig{
		Clients: make([]SafeClientConfig, len(config.Clients)),
	}

	for i, client := range config.Clients {
		safeConfig.Clients[i] = SafeClientConfig{
			ID:            client.ID,
			Name:          client.Name,
			ClientType:    client.ClientType,
			RedirectURIs:  client.RedirectURIs,
			GrantTypes:    client.GrantTypes,
			ResponseTypes: client.ResponseTypes,
			Scopes:        client.Scopes,
			RequireHTTPS:  client.RequireHTTPS,
			PKCERequired:  client.PKCERequired,
			HasSecret:     client.Secret != "",
		}
	}

	slog.Info("Client configuration loaded",
		slog.Int("client_count", len(config.Clients)),
		slog.Any("clients", safeConfig.Clients))
}
