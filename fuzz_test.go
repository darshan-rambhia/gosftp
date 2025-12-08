package gosftp

import (
	"strings"
	"testing"
	"time"
)

// FuzzExpandPath tests the ExpandPath function with random inputs.
func FuzzExpandPath(f *testing.F) {
	// Seed corpus with interesting cases.
	seeds := []string{
		"",
		"~",
		"~/",
		"~/.ssh/id_rsa",
		"/absolute/path",
		"relative/path",
		"~user/path",
		"~/path with spaces",
		"~/../../../etc/passwd",
		strings.Repeat("a", 10000),
		"~/" + strings.Repeat("../", 100),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := ExpandPath(input)

		// Invariants that should always hold:
		// 1. Result should never be empty if input starts with ~
		if strings.HasPrefix(input, "~") && len(input) > 0 && result == "" {
			t.Errorf("ExpandPath(%q) returned empty string", input)
		}

		// 2. Non-tilde paths should be returned unchanged
		if len(input) > 0 && input[0] != '~' && result != input {
			t.Errorf("ExpandPath(%q) = %q, expected unchanged", input, result)
		}

		// 3. Result should not panic (implicit - if we get here, no panic)
	})
}

// FuzzConfigValidation tests Config validation with random inputs.
// Validation happens inside NewClient, so we test that it doesn't panic.
func FuzzConfigValidation(f *testing.F) {
	// Seed with edge cases.
	f.Add("", 0, "", "", "")
	f.Add("localhost", 22, "root", "", "")
	f.Add("localhost", 22, "root", "key-content", "")
	f.Add("localhost", 22, "root", "", "/path/to/key")
	f.Add("192.168.1.1", 2222, "deploy", "", "~/.ssh/id_rsa")
	f.Add(strings.Repeat("a", 1000), 65535, strings.Repeat("b", 100), "", "")
	f.Add("host\x00with\x00nulls", 22, "user", "", "")

	f.Fuzz(func(t *testing.T, host string, port int, user, privateKey, keyPath string) {
		config := Config{
			Host:       host,
			Port:       port,
			User:       user,
			PrivateKey: privateKey,
			KeyPath:    keyPath,
		}

		// WithDefaults should not panic with any input.
		_ = config.WithDefaults()

		// buildAuthMethods should not panic (validation happens here).
		// We don't check the error since invalid configs are expected to fail.
		_, _ = buildAuthMethods(config)
	})
}

// FuzzPrivateKeyParsing tests SSH private key parsing with random inputs.
func FuzzPrivateKeyParsing(f *testing.F) {
	// Seed with various key-like inputs.
	seeds := []string{
		"",
		"not a key",
		"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----\ngarbage\n-----END EC PRIVATE KEY-----",
		strings.Repeat("A", 10000),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, keyContent string) {
		config := Config{
			Host:                  "localhost",
			Port:                  22,
			User:                  "test",
			PrivateKey:            keyContent,
			InsecureIgnoreHostKey: true,
		}

		// This should not panic, even with garbage input.
		// We're not testing that it succeeds, just that it doesn't crash.
		_, _ = buildAuthMethods(config)
	})
}

// FuzzConnectionKey tests the connection pool key generation.
func FuzzConnectionKey(f *testing.F) {
	f.Add("host1", 22, "user1")
	f.Add("", 0, "")
	f.Add("host:with:colons", 2222, "user@domain")
	f.Add(strings.Repeat("x", 1000), 65535, strings.Repeat("y", 1000))

	// Create a pool to test key generation.
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	f.Fuzz(func(t *testing.T, host string, port int, user string) {
		config := Config{
			Host: host,
			Port: port,
			User: user,
		}

		key := pool.connectionKey(config)

		// Key should be deterministic.
		key2 := pool.connectionKey(config)
		if key != key2 {
			t.Errorf("connectionKey() not deterministic: %q != %q", key, key2)
		}

		// Key should be non-empty (it's a hash).
		if key == "" {
			t.Error("connectionKey() returned empty string")
		}

		// Different configs should produce different keys.
		differentConfig := Config{
			Host: host + "different",
			Port: port,
			User: user,
		}
		differentKey := pool.connectionKey(differentConfig)
		if host != "" && key == differentKey {
			t.Errorf("connectionKey() should differ for different hosts")
		}
	})
}
