package login

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// validateCodeChallenge validates PKCE code challenge against code verifier
func validateCodeChallenge(verifier, challenge, method string) error {
	if verifier == "" {
		return fmt.Errorf("code_verifier is required for PKCE")
	}

	if challenge == "" {
		return fmt.Errorf("code_challenge is required for PKCE")
	}

	// Validate code_verifier format (RFC 7636)
	if len(verifier) < 43 || len(verifier) > 128 {
		return fmt.Errorf("code_verifier must be between 43 and 128 characters")
	}

	// Check for valid characters (unreserved characters from RFC 3986)
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for _, char := range verifier {
		if !strings.ContainsRune(validChars, char) {
			return fmt.Errorf("code_verifier contains invalid characters")
		}
	}

	// Validate based on method
	switch strings.ToUpper(method) {
	case "S256":
		return validateS256Challenge(verifier, challenge)
	case "PLAIN":
		return validatePlainChallenge(verifier, challenge)
	default:
		return fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
}

// validateS256Challenge validates S256 (SHA256) challenge method
func validateS256Challenge(verifier, challenge string) error {
	// Compute SHA256 hash of verifier
	hash := sha256.Sum256([]byte(verifier))

	// Encode as base64url without padding
	computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Compare with provided challenge
	if computedChallenge != challenge {
		return fmt.Errorf("code_challenge does not match code_verifier")
	}

	return nil
}

// validatePlainChallenge validates plain challenge method
func validatePlainChallenge(verifier, challenge string) error {
	if verifier != challenge {
		return fmt.Errorf("code_challenge does not match code_verifier")
	}

	return nil
}

// validateCodeChallengeMethod validates that the challenge method is supported
func validateCodeChallengeMethod(method string) error {
	switch strings.ToUpper(method) {
	case "S256", "PLAIN":
		return nil
	default:
		return fmt.Errorf("unsupported code_challenge_method: %s. Supported methods: S256, plain", method)
	}
}
