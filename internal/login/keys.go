package login

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"
)

// keyManager manages certificate-based JWT signing
type keyManager struct {
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	certificate      *x509.Certificate
	certificateChain []*x509.Certificate
	keyID            string
	mu               sync.RWMutex
}

// newKeyManager creates a new key manager loading certificate and private key from files
func newKeyManager(certPath, keyPath string) (*keyManager, error) {
	// Load certificate chain
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
	}

	// Parse certificate chain
	certChain, err := parseCertificateChain(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate certificate is not expired
	if time.Now().After(certChain[0].NotAfter) {
		return nil, fmt.Errorf("certificate has expired")
	}

	// Load private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", keyPath, err)
	}

	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Verify private key matches certificate
	if !privateKey.PublicKey.Equal(certChain[0].PublicKey) {
		return nil, fmt.Errorf("private key does not match certificate public key")
	}

	// Generate key ID from certificate fingerprint
	keyID := generateKeyID(certChain[0])

	km := &keyManager{
		privateKey:       privateKey,
		publicKey:        &privateKey.PublicKey,
		certificate:      certChain[0],
		certificateChain: certChain,
		keyID:            keyID,
	}

	return km, nil
}

// getSigningKey returns the private key for signing tokens
func (km *keyManager) getSigningKey() (*rsa.PrivateKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.privateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}

	return km.privateKey, nil
}

// getKeyID returns the key ID
func (km *keyManager) getKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// getJWKS returns the JSON Web Key Set for public key distribution
func (km *keyManager) getJWKS() (map[string]interface{}, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.publicKey == nil || km.certificate == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	// Create certificate chain in base64
	certChain := make([]string, len(km.certificateChain))
	for i, cert := range km.certificateChain {
		certChain[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	// Generate certificate thumbprints
	x5t := sha1Thumbprint(km.certificate)
	x5tS256 := sha256Thumbprint(km.certificate)

	// Create JWK with certificate information
	jwk := map[string]interface{}{
		"kty":      "RSA",
		"kid":      km.keyID,
		"use":      "sig",
		"alg":      "RS256",
		"n":        encodeBase64URL(km.publicKey.N.Bytes()),
		"e":        encodeBase64URL([]byte{1, 0, 1}), // Standard RSA exponent
		"x5c":      certChain,
		"x5t":      x5t,
		"x5t#S256": x5tS256,
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	return jwks, nil
}

// GetTLSConfig returns a TLS configuration using the loaded certificate and private key
func (km *keyManager) GetTLSConfig() (*tls.Config, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.certificate == nil || km.privateKey == nil {
		return nil, fmt.Errorf("no certificate or private key available")
	}

	// Create a tls.Certificate from the loaded certificate and private key
	cert := tls.Certificate{
		Certificate: make([][]byte, len(km.certificateChain)),
		PrivateKey:  km.privateKey,
		Leaf:        km.certificate,
	}

	// Add all certificates in the chain
	for i, certBytes := range km.certificateChain {
		cert.Certificate[i] = certBytes.Raw
	}

	// Create TLS config with the certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}

// encodeBase64URL encodes bytes to base64url without padding
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// parseCertificateChain parses a PEM certificate chain
func parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block

	for {
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}

// parsePrivateKey parses a PEM private key
func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// generateKeyID generates a key ID from certificate fingerprint
func generateKeyID(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return encodeBase64URL(hash[:8]) // Use first 8 bytes as key ID
}

// sha1Thumbprint generates SHA-1 thumbprint of certificate
func sha1Thumbprint(cert *x509.Certificate) string {
	hash := crypto.SHA1.New()
	hash.Write(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// sha256Thumbprint generates SHA-256 thumbprint of certificate
func sha256Thumbprint(cert *x509.Certificate) string {
	hash := crypto.SHA256.New()
	hash.Write(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
