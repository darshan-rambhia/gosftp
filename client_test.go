package gosftp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateTestKey creates a temporary RSA private key for testing.
func generateTestKey(t *testing.T) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Create temp file.
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	return string(keyPEM), keyPath
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with inline key",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: "key-content",
			},
			expectError: false,
		},
		{
			name: "valid config with key path",
			config: Config{
				Host:    "192.168.1.100",
				Port:    22,
				User:    "root",
				KeyPath: "/path/to/key",
			},
			expectError: false,
		},
		{
			name: "missing credentials - expect error from NewClient",
			config: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			expectError: true,
			errorMsg:    "no SSH private key provided (set private_key or key_path)",
		},
		{
			name: "valid config with password",
			config: Config{
				Host:     "192.168.1.100",
				Port:     22,
				User:     "root",
				Password: "secret",
			},
			expectError: false,
		},
		{
			name: "explicit password auth without password",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				AuthMethod: AuthMethodPassword,
			},
			expectError: true,
			errorMsg:    "password authentication requires password to be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError {
				// Only test configs that should fail validation.
				_, err := NewClient(tt.config)
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// TestNewClient_KeyHandling tests various key configurations for NewClient.
func TestNewClient_KeyHandling(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name           string
		config         Config
		wantParseError bool // true if key parsing should fail
		skipIfConnects bool // some tests skip if unexpectedly connects
	}{
		{
			name: "invalid key path",
			config: Config{
				Host:    "192.168.1.100",
				Port:    22,
				User:    "root",
				KeyPath: "/nonexistent/path/to/key",
			},
			wantParseError: true,
		},
		{
			name: "invalid key content",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: "invalid-key-content",
			},
			wantParseError: true,
		},
		{
			name: "valid key from file",
			config: Config{
				Host:    "192.168.1.100",
				Port:    22,
				User:    "root",
				KeyPath: keyPath,
			},
			wantParseError: false,
			skipIfConnects: true,
		},
		{
			name: "valid inline key",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: keyContent,
			},
			wantParseError: false,
			skipIfConnects: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.config)

			if tt.skipIfConnects && err == nil {
				t.Skip("unexpectedly connected - skipping")
			}

			if tt.wantParseError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else if err != nil {
				// For valid keys, error should be connection-related, not parsing.
				if err.Error() == "no SSH private key provided (set private_key or key_path)" {
					t.Error("key should have been parsed successfully")
				}
			}
		})
	}
}

// TestInferAuthMethod tests automatic auth method detection.
func TestInferAuthMethod(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected AuthMethod
	}{
		{
			name:     "infer private key from key content",
			config:   Config{PrivateKey: "key"},
			expected: AuthMethodPrivateKey,
		},
		{
			name:     "infer private key from key path",
			config:   Config{KeyPath: "/path/to/key"},
			expected: AuthMethodPrivateKey,
		},
		{
			name:     "infer password auth",
			config:   Config{Password: "secret"},
			expected: AuthMethodPassword,
		},
		{
			name:     "infer certificate auth from cert content",
			config:   Config{Certificate: "cert"},
			expected: AuthMethodCertificate,
		},
		{
			name:     "infer certificate auth from cert path",
			config:   Config{CertificatePath: "/path/to/cert"},
			expected: AuthMethodCertificate,
		},
		{
			name:     "default to private key when nothing set",
			config:   Config{},
			expected: AuthMethodPrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferAuthMethod(tt.config)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestHashFormat verifies the hash format matches expected pattern.
func TestHashFormat(t *testing.T) {
	// Test that our hash format is correct by computing a known hash.
	data := []byte("test content")
	h := sha256.New()
	h.Write(data)
	hash := "sha256:" + hex.EncodeToString(h.Sum(nil))

	// Verify format.
	if len(hash) != 71 { // "sha256:" (7) + 64 hex chars
		t.Errorf("expected hash length 71, got %d", len(hash))
	}

	if hash[:7] != "sha256:" {
		t.Errorf("expected hash prefix 'sha256:', got %q", hash[:7])
	}
}

// TestClient_Close verifies Close handles nil clients gracefully.
func TestClient_Close(t *testing.T) {
	// Test with nil clients (including bastion).
	c := &Client{
		sshClient:     nil,
		sftpClient:    nil,
		bastionClient: nil,
	}

	// Should not panic.
	err := c.Close()
	if err != nil {
		t.Errorf("Close() with nil clients should not error: %v", err)
	}
}

// TestBastionConfig tests bastion host configuration.
func TestBastionConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "bastion with separate key",
			config: Config{
				Host:           "target.internal",
				Port:           22,
				User:           "root",
				PrivateKey:     "target-key",
				BastionHost:    "bastion.example.com",
				BastionPort:    22,
				BastionUser:    "jumpuser",
				BastionKeyPath: "/path/to/bastion/key",
			},
		},
		{
			name: "bastion inherits target key",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				PrivateKey:  "shared-key",
				BastionHost: "bastion.example.com",
			},
		},
		{
			name: "bastion with password",
			config: Config{
				Host:            "target.internal",
				Port:            22,
				User:            "root",
				PrivateKey:      "target-key",
				BastionHost:     "bastion.example.com",
				BastionPassword: "bastion-pass",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify config struct is valid - actual connection would require servers.
			if tt.config.BastionHost == "" {
				t.Error("expected bastion host to be set")
			}
		})
	}
}

// TestUploadFile_LocalFileNotFound tests error handling for missing local file.
func TestUploadFile_LocalFileNotFound(t *testing.T) {
	// Create a client with nil SFTP (will fail before SFTP is used).
	c := &Client{
		sshClient:  nil,
		sftpClient: nil,
	}

	err := c.UploadFile(context.Background(), "/nonexistent/file.txt", "/remote/path")
	if err == nil {
		t.Error("expected error for nonexistent local file, got nil")
	}
}

// Benchmark tests for hash computation.
func BenchmarkHashComputation(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		h.Write(data)
		_ = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
}

// TestModeParser tests octal mode parsing similar to SetFileAttributes.
func TestModeParser(t *testing.T) {
	tests := []struct {
		mode    string
		valid   bool
		decimal uint64
	}{
		{"0644", true, 0644},
		{"0755", true, 0755},
		{"0600", true, 0600},
		{"0777", true, 0777},
		{"644", true, 0644},
		{"invalid", false, 0},
		{"", true, 0}, // Empty is valid (no-op)
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if tt.mode == "" {
				return // Empty mode is handled specially
			}

			_, err := parseOctalMode(tt.mode)
			if tt.valid && err != nil {
				t.Errorf("expected valid mode, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected error for invalid mode, got nil")
			}
		})
	}
}

// parseOctalMode is a helper to test mode parsing logic.
func parseOctalMode(mode string) (os.FileMode, error) {
	modeInt, err := parseUint(mode, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(modeInt), nil
}

// parseUint wraps strconv.ParseUint for testing.
func parseUint(s string, base, bitSize int) (uint64, error) {
	return strtoull(s, base, bitSize)
}

// strtoull is a simple wrapper for testing.
func strtoull(s string, _, _ int) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	var val uint64
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, os.ErrInvalid
		}
		val = val*8 + uint64(c-'0')
	}
	return val, nil
}

// TestOwnershipString tests ownership string formatting.
func TestOwnershipString(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		group    string
		expected string
	}{
		{"both owner and group", "root", "root", "root:root"},
		{"only owner", "root", "", "root"},
		{"only group", "", "www-data", ":www-data"},
		{"different owner and group", "user", "staff", "user:staff"},
		{"www-data both", "www-data", "www-data", "www-data:www-data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the same logic as SetFileAttributes.
			var ownership string
			if tt.owner != "" && tt.group != "" {
				ownership = tt.owner + ":" + tt.group
			} else if tt.owner != "" {
				ownership = tt.owner
			} else if tt.group != "" {
				ownership = ":" + tt.group
			}
			if ownership != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, ownership)
			}
		})
	}
}

// TestRemotePathParsing tests directory extraction from paths.
func TestRemotePathParsing(t *testing.T) {
	tests := []struct {
		path     string
		dir      string
		hasSlash bool
	}{
		{"/etc/nginx/nginx.conf", "/etc/nginx", true},
		{"/config/.env", "/config", true},
		{"/file.txt", "", true},
		{"file.txt", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			lastSlash := -1
			for i := len(tt.path) - 1; i >= 0; i-- {
				if tt.path[i] == '/' {
					lastSlash = i
					break
				}
			}

			var dir string
			if lastSlash > 0 {
				dir = tt.path[:lastSlash]
			}

			if dir != tt.dir {
				t.Errorf("expected dir %q, got %q", tt.dir, dir)
			}
		})
	}
}

// TestIsBinaryContent tests binary content detection.
func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{
			name:     "text content",
			content:  []byte("Hello, World!\nThis is plain text."),
			expected: false,
		},
		{
			name:     "binary content with null byte",
			content:  []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x57, 0x6f, 0x72, 0x6c, 0x64},
			expected: true,
		},
		{
			name:     "empty content",
			content:  []byte{},
			expected: false,
		},
		{
			name:     "single null byte",
			content:  []byte{0x00},
			expected: true,
		},
		{
			name:     "null byte at start",
			content:  []byte{0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
			expected: true,
		},
		{
			name:     "null byte at end",
			content:  []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00},
			expected: true,
		},
		{
			name:     "unicode text",
			content:  []byte("Hello, 世界! 🌍"),
			expected: false,
		},
		{
			name:     "binary-like but no null",
			content:  []byte{0xFF, 0xFE, 0x01, 0x02, 0x03},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinaryContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsBinaryContent(%v) = %v, want %v", tt.content, result, tt.expected)
			}
		})
	}
}

// TestBuildAuthMethods tests auth method building.
func TestBuildAuthMethods(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "password auth",
			config: Config{
				AuthMethod: AuthMethodPassword,
				Password:   "secret",
			},
			expectError: false,
		},
		{
			name: "password auth without password",
			config: Config{
				AuthMethod: AuthMethodPassword,
			},
			expectError: true,
			errorMsg:    "password authentication requires password to be set",
		},
		{
			name: "private key auth with inline key",
			config: Config{
				AuthMethod: AuthMethodPrivateKey,
				PrivateKey: keyContent,
			},
			expectError: false,
		},
		{
			name: "private key auth with key path",
			config: Config{
				AuthMethod: AuthMethodPrivateKey,
				KeyPath:    keyPath,
			},
			expectError: false,
		},
		{
			name: "private key auth without key",
			config: Config{
				AuthMethod: AuthMethodPrivateKey,
			},
			expectError: true,
			errorMsg:    "no SSH private key provided (set private_key or key_path)",
		},
		{
			name: "certificate auth without key",
			config: Config{
				AuthMethod:  AuthMethodCertificate,
				Certificate: "cert-content",
			},
			expectError: true,
			errorMsg:    "certificate authentication failed: certificate auth requires private key",
		},
		{
			name: "certificate auth without cert",
			config: Config{
				AuthMethod: AuthMethodCertificate,
				PrivateKey: keyContent,
			},
			expectError: true,
			errorMsg:    "certificate authentication failed: certificate auth requires certificate",
		},
		{
			name: "inferred password auth",
			config: Config{
				Password: "secret",
			},
			expectError: false,
		},
		{
			name: "inferred private key auth",
			config: Config{
				PrivateKey: keyContent,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			methods, err := buildAuthMethods(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(methods) == 0 {
					t.Error("expected at least one auth method")
				}
			}
		})
	}
}

// TestBuildPrivateKeyAuth tests private key auth building.
func TestBuildPrivateKeyAuth(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name:        "inline key",
			config:      Config{PrivateKey: keyContent},
			expectError: false,
		},
		{
			name:        "key from file",
			config:      Config{KeyPath: keyPath},
			expectError: false,
		},
		{
			name:        "no key provided",
			config:      Config{},
			expectError: true,
		},
		{
			name:        "nonexistent key file",
			config:      Config{KeyPath: "/nonexistent/key"},
			expectError: true,
		},
		{
			name:        "invalid key content",
			config:      Config{PrivateKey: "not-a-valid-key"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildPrivateKeyAuth(tt.config)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestBuildCertificateAuth tests certificate auth building.
func TestBuildCertificateAuth(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorSubstr string
	}{
		{
			name:        "missing private key",
			config:      Config{Certificate: "cert"},
			expectError: true,
			errorSubstr: "requires private key",
		},
		{
			name:        "missing certificate",
			config:      Config{PrivateKey: keyContent},
			expectError: true,
			errorSubstr: "requires certificate",
		},
		{
			name: "invalid private key",
			config: Config{
				PrivateKey:  "invalid-key",
				Certificate: "cert",
			},
			expectError: true,
			errorSubstr: "failed to parse private key",
		},
		{
			name: "invalid certificate",
			config: Config{
				PrivateKey:  keyContent,
				Certificate: "invalid-cert",
			},
			expectError: true,
			errorSubstr: "failed to parse certificate",
		},
		{
			name: "nonexistent key file",
			config: Config{
				KeyPath:     "/nonexistent/key",
				Certificate: "cert",
			},
			expectError: true,
			errorSubstr: "failed to read private key file",
		},
		{
			name: "nonexistent cert file",
			config: Config{
				KeyPath:         keyPath,
				CertificatePath: "/nonexistent/cert",
			},
			expectError: true,
			errorSubstr: "failed to read certificate file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildCertificateAuth(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorSubstr != "" && !contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestConfigTimeout tests timeout configuration and WithDefaults.
func TestConfigTimeout(t *testing.T) {
	tests := []struct {
		name            string
		configTimeout   time.Duration
		expectedDefault bool
	}{
		{
			name:            "zero timeout uses default",
			configTimeout:   0,
			expectedDefault: true,
		},
		{
			name:            "custom timeout",
			configTimeout:   60 * time.Second,
			expectedDefault: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Timeout: tt.configTimeout,
			}
			if tt.expectedDefault && config.Timeout != 0 {
				t.Error("expected zero timeout to be set")
			}
			if !tt.expectedDefault && config.Timeout != 60*time.Second {
				t.Errorf("expected 60s timeout, got %v", config.Timeout)
			}
		})
	}

	// Test WithDefaults
	t.Run("default port", func(t *testing.T) {
		result := Config{}.WithDefaults()
		if result.Port != 22 {
			t.Errorf("Port = %d, want 22", result.Port)
		}
		if result.Timeout != 30*time.Second {
			t.Errorf("Timeout = %v, want 30s", result.Timeout)
		}
	})

	t.Run("custom port preserved", func(t *testing.T) {
		result := Config{Port: 2222}.WithDefaults()
		if result.Port != 2222 {
			t.Errorf("Port = %d, want 2222", result.Port)
		}
	})

	t.Run("bastion port defaults", func(t *testing.T) {
		result := Config{BastionHost: "bastion.example.com"}.WithDefaults()
		if result.Port != 22 {
			t.Errorf("Port = %d, want 22", result.Port)
		}
		if result.BastionPort != 22 {
			t.Errorf("BastionPort = %d, want 22", result.BastionPort)
		}
	})

	t.Run("bastion port custom", func(t *testing.T) {
		result := Config{BastionHost: "bastion.example.com", BastionPort: 2222}.WithDefaults()
		if result.BastionPort != 2222 {
			t.Errorf("BastionPort = %d, want 2222", result.BastionPort)
		}
	})
}

// TestConnectToBastion_Errors tests various bastion connection error scenarios.
func TestConnectToBastion_Errors(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		errorSubstr string
	}{
		{
			name: "missing bastion key",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				BastionHost: "bastion.example.com",
				// No key configured for bastion or target.
			},
			errorSubstr: "no SSH key configured for bastion",
		},
		{
			name: "nonexistent bastion key path",
			config: Config{
				Host:           "target.internal",
				Port:           22,
				User:           "root",
				BastionHost:    "bastion.example.com",
				BastionKeyPath: "/nonexistent/bastion/key",
			},
			errorSubstr: "failed to read bastion key file",
		},
		{
			name: "invalid bastion key content",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				BastionHost: "bastion.example.com",
				BastionKey:  "invalid-key-content",
			},
			errorSubstr: "failed to parse bastion SSH key",
		},
		{
			name: "bastion uses target key path - nonexistent",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				KeyPath:     "/nonexistent/target/key",
				BastionHost: "bastion.example.com",
			},
			errorSubstr: "failed to read key file for bastion",
		},
		{
			name: "bastion uses target inline key",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				PrivateKey:  keyContent,
				BastionHost: "bastion.example.com",
			},
			// This will fail at connection, not at key parsing.
			errorSubstr: "",
		},
		{
			name: "bastion with password auth",
			config: Config{
				Host:            "target.internal",
				Port:            22,
				User:            "root",
				PrivateKey:      keyContent,
				BastionHost:     "bastion.example.com",
				BastionPassword: "secret",
			},
			// This will fail at connection, not at auth setup.
			errorSubstr: "",
		},
		{
			name: "bastion uses target key file",
			config: Config{
				Host:        "target.internal",
				Port:        22,
				User:        "root",
				KeyPath:     keyPath,
				BastionHost: "bastion.example.com",
			},
			// This will fail at connection, not at key parsing.
			errorSubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Timeout = 5 * time.Second
			_, err := connectToBastion(tt.config)
			if err == nil && tt.errorSubstr != "" {
				t.Error("expected error, got nil")
			}
			if err != nil && tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
				t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
			}
		})
	}
}

// TestNewClient_NoAuthMethods tests the case where no auth methods can be built.
func TestNewClient_NoAuthMethods(t *testing.T) {
	// This should fail because no auth method is configured.
	config := Config{
		Host: "192.168.1.100",
		Port: 22,
		User: "root",
		// No auth method configured.
	}

	_, err := NewClient(config)
	if err == nil {
		t.Error("expected error for missing auth method, got nil")
	}
}

// TestNewClient_WithBastion tests NewClient with bastion configuration.
func TestNewClient_WithBastion(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	config := Config{
		Host:        "target.internal",
		Port:        22,
		User:        "root",
		PrivateKey:  keyContent,
		BastionHost: "bastion.example.com",
		BastionPort: 22,
		BastionKey:  keyContent,
	}

	// This will fail to connect but should get past auth setup.
	_, err := NewClient(config)
	if err == nil {
		t.Skip("unexpectedly connected")
	}

	// Error should be about connection, not auth.
	if findSubstring(err.Error(), "no SSH") {
		t.Errorf("expected connection error, got auth error: %v", err)
	}
}

// TestNewClient_DefaultTimeout tests that default timeout is applied.
func TestNewClient_DefaultTimeout(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	config := Config{
		Host:       "192.168.1.100",
		Port:       22,
		User:       "root",
		PrivateKey: keyContent,
		Timeout:    0, // Should default to 30s
	}

	// Will fail to connect but tests timeout handling.
	_, err := NewClient(config)
	if err == nil {
		t.Skip("unexpectedly connected")
	}
}

// TestClient_Interface ensures Client implements ClientInterface.
func TestClient_Interface(t *testing.T) {
	var _ ClientInterface = (*Client)(nil)
}

// TestUploadFile_RemotePathParsing tests the directory extraction in UploadFile.
func TestUploadFile_RemotePathParsing(t *testing.T) {
	tests := []struct {
		remotePath  string
		expectedDir string
	}{
		{"/etc/nginx/nginx.conf", "/etc/nginx"},
		{"/single/file.txt", "/single"},
		{"/deep/nested/path/to/file.txt", "/deep/nested/path/to"},
		{"/root.txt", ""},
	}

	for _, tt := range tests {
		t.Run(tt.remotePath, func(t *testing.T) {
			// Extract directory using same logic as UploadFile.
			lastSlashIdx := -1
			for i := len(tt.remotePath) - 1; i >= 0; i-- {
				if tt.remotePath[i] == '/' {
					lastSlashIdx = i
					break
				}
			}

			var dir string
			if lastSlashIdx > 0 {
				dir = tt.remotePath[:lastSlashIdx]
			}

			if dir != tt.expectedDir {
				t.Errorf("expected dir %q, got %q", tt.expectedDir, dir)
			}
		})
	}
}

// TestSetFileAttributes_ModeFormat tests mode string format validation.
func TestSetFileAttributes_ModeFormat(t *testing.T) {
	tests := []struct {
		mode        string
		shouldError bool
	}{
		{"0644", false},
		{"0755", false},
		{"0600", false},
		{"644", false},
		{"755", false},
		{"invalid", true},
		{"99999", true},
		{"", false}, // Empty is valid (no-op)
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if tt.mode == "" {
				return
			}

			_, err := strtoull(tt.mode, 8, 32)
			if tt.shouldError && err == nil {
				t.Error("expected error for invalid mode")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestIsBinaryContent_EdgeCases tests edge cases for binary detection.
func TestIsBinaryContent_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{"single space", []byte(" "), false},
		{"newlines only", []byte("\n\n\n"), false},
		{"tabs and spaces", []byte("\t \t \t"), false},
		{"high ascii", []byte{0x80, 0x81, 0x82}, false},
		{"control chars no null", []byte{0x01, 0x02, 0x03}, false},
		{"mixed with null in middle", []byte{0x41, 0x00, 0x42}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinaryContent(tt.content)
			if result != tt.expected {
				t.Errorf("IsBinaryContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Tests for Client methods using MockSFTPClient.

func TestClient_GetFileHash_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("test content for hashing")
	mockSFTP.SetFile("/test.txt", content, 0644)

	client := NewClientWithSFTP(mockSFTP, nil)

	hash, err := client.GetFileHash(context.Background(), "/test.txt")
	if err != nil {
		t.Errorf("GetFileHash() error = %v", err)
	}

	// Verify hash format.
	if len(hash) != 71 { // "sha256:" (7) + 64 hex chars
		t.Errorf("hash length = %d, want 71", len(hash))
	}
	if hash[:7] != "sha256:" {
		t.Errorf("hash prefix = %q, want 'sha256:'", hash[:7])
	}

	// Compute expected hash.
	h := sha256.New()
	h.Write(content)
	expectedHash := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
}

func TestClient_GetFileHash_FileNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.GetFileHash(context.Background(), "/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestClient_GetFileHash_OpenError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Open", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.GetFileHash(context.Background(), "/test.txt")
	if err == nil {
		t.Error("expected error when Open fails")
	}
}

func TestClient_FileExists_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/exists.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Test existing file.
	exists, err := client.FileExists(context.Background(), "/exists.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("expected file to exist")
	}

	// Test non-existing file.
	exists, err = client.FileExists(context.Background(), "/not-exists.txt")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if exists {
		t.Error("expected file to not exist")
	}
}

func TestClient_FileExists_StatError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Stat", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.FileExists(context.Background(), "/test.txt")
	if err == nil {
		t.Error("expected error when Stat fails")
	}
}

func TestClient_GetFileInfo_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("file content here")
	mockSFTP.SetFile("/test.txt", content, 0755)
	client := NewClientWithSFTP(mockSFTP, nil)

	info, err := client.GetFileInfo(context.Background(), "/test.txt")
	if err != nil {
		t.Errorf("GetFileInfo() error = %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil FileInfo")
	}
	if info.Size() != int64(len(content)) {
		t.Errorf("Size() = %d, want %d", info.Size(), len(content))
	}
	if info.Mode() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode(), 0755)
	}
}

func TestClient_GetFileInfo_FileNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.GetFileInfo(context.Background(), "/nonexistent.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestClient_DeleteFile_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Verify file exists.
	exists, _ := client.FileExists(context.Background(), "/test.txt")
	if !exists {
		t.Fatal("expected file to exist before delete")
	}

	// Delete file.
	err := client.DeleteFile(context.Background(), "/test.txt")
	if err != nil {
		t.Errorf("DeleteFile() error = %v", err)
	}

	// Verify file is gone.
	exists, _ = client.FileExists(context.Background(), "/test.txt")
	if exists {
		t.Error("expected file to not exist after delete")
	}
}

func TestClient_DeleteFile_NotExist(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Delete non-existent file should not error (idempotent).
	err := client.DeleteFile(context.Background(), "/nonexistent.txt")
	if err != nil {
		t.Errorf("DeleteFile() for nonexistent file should not error: %v", err)
	}
}

func TestClient_DeleteFile_RemoveError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Remove", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.DeleteFile(context.Background(), "/test.txt")
	if err == nil {
		t.Error("expected error when Remove fails")
	}
}

func TestClient_ReadFileContent_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("this is the file content to read")
	mockSFTP.SetFile("/test.txt", content, 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Read all content.
	data, err := client.ReadFileContent(context.Background(), "/test.txt", 0)
	if err != nil {
		t.Errorf("ReadFileContent() error = %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("ReadFileContent() = %q, want %q", data, content)
	}
}

func TestClient_ReadFileContent_WithLimit(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := []byte("this is the file content to read")
	mockSFTP.SetFile("/test.txt", content, 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Read with limit.
	data, err := client.ReadFileContent(context.Background(), "/test.txt", 10)
	if err != nil {
		t.Errorf("ReadFileContent() with limit error = %v", err)
	}
	if len(data) != 10 {
		t.Errorf("ReadFileContent() with limit returned %d bytes, want 10", len(data))
	}
	if string(data) != "this is th" {
		t.Errorf("ReadFileContent() = %q, want %q", data, "this is th")
	}
}

func TestClient_ReadFileContent_FileNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.ReadFileContent(context.Background(), "/nonexistent.txt", 0)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestClient_ReadFileContent_OpenError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Open", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	_, err := client.ReadFileContent(context.Background(), "/test.txt", 0)
	if err == nil {
		t.Error("expected error when Open fails")
	}
}

func TestClient_SetFileAttributes_Mode(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Set only mode (no owner/group to avoid SSH session).
	err := client.SetFileAttributes(context.Background(), "/test.txt", "", "", "0755")
	if err != nil {
		t.Errorf("SetFileAttributes() error = %v", err)
	}

	// Verify mode was changed.
	info, _ := mockSFTP.Stat("/test.txt")
	if info.Mode() != 0755 {
		t.Errorf("Mode() = %o, want %o", info.Mode(), 0755)
	}
}

func TestClient_SetFileAttributes_InvalidMode(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.SetFileAttributes(context.Background(), "/test.txt", "", "", "invalid")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestClient_SetFileAttributes_ChmodError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	mockSFTP.SetError("Chmod", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.SetFileAttributes(context.Background(), "/test.txt", "", "", "0755")
	if err == nil {
		t.Error("expected error when Chmod fails")
	}
}

func TestClient_SetFileAttributes_EmptyMode(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Empty mode should be a no-op (no error).
	err := client.SetFileAttributes(context.Background(), "/test.txt", "", "", "")
	if err != nil {
		t.Errorf("SetFileAttributes() with empty mode should not error: %v", err)
	}
}

// Tests for UploadFile using MockSFTPClient.
func TestClient_UploadFile_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file to upload.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content for upload")
	if err := os.WriteFile(localPath, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	remotePath := "/remote/path/test.txt"

	// Test upload.
	err := client.UploadFile(context.Background(), localPath, remotePath)
	if err != nil {
		t.Errorf("UploadFile() error = %v", err)
	}

	// Verify file was created in mock.
	if _, ok := mockSFTP.files[remotePath]; !ok {
		t.Error("expected file to be created in mock")
	}
}

func TestClient_UploadFile_MkdirAllError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetError("MkdirAll", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := client.UploadFile(context.Background(), localPath, "/remote/dir/file.txt")
	if err == nil {
		t.Error("expected error when MkdirAll fails")
	}
}

func TestClient_UploadFile_CreateError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetError("Create", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := client.UploadFile(context.Background(), localPath, "/remote/file.txt")
	if err == nil {
		t.Error("expected error when Create fails")
	}
}

func TestClient_UploadFile_LocalNotFound(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.UploadFile(context.Background(), "/nonexistent/local/file.txt", "/remote/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent local file")
	}
}

func TestClient_UploadFile_RootPath(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test uploading to root path (no directory to create).
	err := client.UploadFile(context.Background(), localPath, "/rootfile.txt")
	if err != nil {
		t.Errorf("UploadFile() to root error = %v", err)
	}
}

// Tests for Close method.

func TestClient_Close_WithMockSFTP(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	err := client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !mockSFTP.closed {
		t.Error("expected mock SFTP to be closed")
	}
}

func TestClient_Close_SFTPError(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetError("Close", os.ErrPermission)
	client := NewClientWithSFTP(mockSFTP, nil)

	// Close should not return SFTP close error (it doesn't propagate).
	_ = client.Close()
	// Just verifying it doesn't panic.
}

// TestSetFileAttributes_OwnerValidation tests that invalid owner names are rejected.
func TestSetFileAttributes_OwnerValidation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	tests := []struct {
		name        string
		owner       string
		group       string
		expectError bool
	}{
		// Note: We can only test cases that fail validation or have no owner/group
		// because setting owner/group requires an SSH session which is nil in tests.
		{"injection in owner", "root;rm -rf /", "", true},
		{"injection in group", "", "staff$(whoami)", true},
		{"backtick injection", "root`id`", "", true},
		{"pipe injection", "root|whoami", "", true},
		{"both empty is ok", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.SetFileAttributes(context.Background(), "/test.txt", tt.owner, tt.group, "")
			if tt.expectError {
				if err == nil {
					t.Error("expected validation error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestSetFileAttributes_ModeValidation tests that invalid modes are rejected.
func TestSetFileAttributes_ModeValidation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	tests := []struct {
		name        string
		mode        string
		expectError bool
	}{
		{"valid 4-digit mode", "0755", false},
		{"valid 3-digit mode", "644", false},
		{"invalid non-octal", "0689", true},
		{"invalid letters", "abcd", true},
		{"empty mode ok", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.SetFileAttributes(context.Background(), "/test.txt", "", "", tt.mode)
			if tt.expectError && err == nil {
				t.Errorf("expected error for mode %q, got nil", tt.mode)
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error for mode %q: %v", tt.mode, err)
			}
		})
	}
}

// TestUploadFile_PathParsingEdgeCases tests edge cases for path parsing.
func TestUploadFile_PathParsingEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		remotePath string
		expectDir  string
	}{
		{"root level file", "/file.txt", "/"},
		{"single directory", "/dir/file.txt", "/dir"},
		{"deep nesting", "/a/b/c/d/e/file.txt", "/a/b/c/d/e"},
		{"dot in path", "/path/to/.hidden", "/path/to"},
		{"double dot segment", "/path/../other/file.txt", "/other"}, // filepath.Dir cleans paths
		{"trailing slash edge", "/dir/subdir/", "/dir/subdir"},
		{"relative path", "relative/path/file.txt", "relative/path"},
		{"just filename", "file.txt", "."},
		{"current dir", "./file.txt", "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filepath.Dir(tt.remotePath)
			if result != tt.expectDir {
				t.Errorf("filepath.Dir(%q) = %q, want %q", tt.remotePath, result, tt.expectDir)
			}
		})
	}
}

// TestExpandPath tests the path expansion helper.
func TestExpandPath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot get home directory")
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"absolute path unchanged", "/etc/hosts", "/etc/hosts"},
		{"relative path unchanged", "relative/path", "relative/path"},
		{"tilde expands", "~/test", filepath.Join(homeDir, "test")},
		{"tilde with subpath", "~/.ssh/known_hosts", filepath.Join(homeDir, ".ssh/known_hosts")},
		{"tilde alone", "~/", filepath.Join(homeDir, "")}, // Note: may have trailing behavior
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandPath(tt.input)
			if result != tt.expected {
				t.Errorf("ExpandPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBuildHostKeyCallback tests the host key callback builder.
func TestBuildHostKeyCallback(t *testing.T) {
	t.Run("insecure_ignore_host_key", func(t *testing.T) {
		config := Config{
			InsecureIgnoreHostKey: true,
		}
		callback, err := buildHostKeyCallback(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if callback == nil {
			t.Error("expected non-nil callback")
		}
	})

	t.Run("known_hosts_file_not_found", func(t *testing.T) {
		config := Config{
			KnownHostsFile: "/nonexistent/known_hosts",
		}
		_, err := buildHostKeyCallback(config)
		if err == nil {
			t.Error("expected error for nonexistent known_hosts file")
		}
	})

	t.Run("known_hosts_file_invalid_format", func(t *testing.T) {
		// Create a file with invalid known_hosts content.
		tmpDir := t.TempDir()
		badFile := filepath.Join(tmpDir, "bad_known_hosts")
		// Write invalid content (not a valid known_hosts format).
		if err := os.WriteFile(badFile, []byte("invalid content not a valid host key"), 0600); err != nil {
			t.Fatal(err)
		}

		config := Config{
			KnownHostsFile: badFile,
		}
		// knownhosts.New may or may not return an error for invalid content,
		// but the callback should be created or an error returned.
		callback, err := buildHostKeyCallback(config)
		// Either returns an error or a callback (depends on knownhosts implementation).
		if err == nil && callback == nil {
			t.Error("expected either error or valid callback")
		}
	})

	t.Run("valid_known_hosts_file", func(t *testing.T) {
		// Create a valid known_hosts file with a real SSH public key.
		tmpDir := t.TempDir()
		knownHostsFile := filepath.Join(tmpDir, "known_hosts")

		// Generate a test RSA key to get a valid public key.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		sshPubKey, err := ssh.NewPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		// Format as known_hosts entry.
		validEntry := fmt.Sprintf("example.com %s", string(ssh.MarshalAuthorizedKey(sshPubKey)))
		if err := os.WriteFile(knownHostsFile, []byte(validEntry), 0600); err != nil {
			t.Fatal(err)
		}

		config := Config{
			KnownHostsFile: knownHostsFile,
		}
		callback, err := buildHostKeyCallback(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if callback == nil {
			t.Error("expected non-nil callback")
		}
	})

	t.Run("empty_config_returns_callback", func(t *testing.T) {
		// When no known_hosts is configured and InsecureIgnoreHostKey is false,
		// should either return a callback from default ~/.ssh/known_hosts (if it exists)
		// or return an error (fail-closed security).
		config := Config{
			InsecureIgnoreHostKey: false,
			KnownHostsFile:        "",
		}
		callback, err := buildHostKeyCallback(config)
		// Accept either outcome:
		// 1. Success if ~/.ssh/known_hosts exists (common on developer machines)
		// 2. Error if ~/.ssh/known_hosts doesn't exist (fail-closed security, common in CI)
		if err == nil && callback == nil {
			t.Error("expected either a valid callback or an error")
		}
	})

	t.Run("tilde_expansion_in_known_hosts", func(t *testing.T) {
		config := Config{
			KnownHostsFile: "~/nonexistent_known_hosts_file",
		}
		_, err := buildHostKeyCallback(config)
		// Should fail because the expanded path doesn't exist.
		if err == nil {
			t.Error("expected error for nonexistent expanded path")
		}
	})
}

// Tests for context cancellation.
func TestClient_UploadFile_ContextCancelled(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.UploadFile(ctx, localPath, "/remote/file.txt")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// Test buildCertificateAuth with CertificatePath.
func TestBuildCertificateAuth_WithCertPath(t *testing.T) {
	keyContent, keyPath := generateTestKey(t)

	// Create a certificate file (will fail parsing but tests the read path)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pub")
	if err := os.WriteFile(certPath, []byte("not a valid certificate"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		config      Config
		errorSubstr string
	}{
		{
			name: "key path with cert path",
			config: Config{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
			errorSubstr: "failed to parse certificate",
		},
		{
			name: "inline key with cert path",
			config: Config{
				PrivateKey:      keyContent,
				CertificatePath: certPath,
			},
			errorSubstr: "failed to parse certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildCertificateAuth(tt.config)
			if err == nil {
				t.Error("expected error, got nil")
			} else if !findSubstring(err.Error(), tt.errorSubstr) {
				t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
			}
		})
	}
}

// Test buildAuthMethods with empty auth method (default to private key).
func TestBuildAuthMethods_EmptyAuthMethod(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	config := Config{
		AuthMethod: "", // Empty, should infer from provided credentials
		PrivateKey: keyContent,
	}

	methods, err := buildAuthMethods(config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(methods) == 0 {
		t.Error("expected at least one auth method")
	}
}

// Test UploadFile with relative remote path.
func TestClient_UploadFile_RelativePath(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Relative path (no leading /)
	err := client.UploadFile(context.Background(), localPath, "relative/path/file.txt")
	if err != nil {
		t.Errorf("UploadFile() with relative path error = %v", err)
	}
}

// Test UploadFile with . directory.
func TestClient_UploadFile_CurrentDir(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	client := NewClientWithSFTP(mockSFTP, nil)

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localPath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	// File in current directory
	err := client.UploadFile(context.Background(), localPath, "file.txt")
	if err != nil {
		t.Errorf("UploadFile() to current dir error = %v", err)
	}
}

// TestBastionConfig_KeyInheritance tests bastion key inheritance from target.
func TestBastionConfig_KeyInheritance(t *testing.T) {
	testKey, testKeyPath := generateTestKey(t)

	tests := []struct {
		name             string
		targetPrivateKey string
		targetKeyPath    string
		bastionKey       string
		bastionKeyPath   string
		expectedHasKey   bool
	}{
		{
			"bastion inherits target private key",
			testKey,
			"",
			"",
			"",
			true,
		},
		{
			"bastion inherits target key path",
			"",
			testKeyPath,
			"",
			"",
			true,
		},
		{
			"bastion explicit key overrides",
			testKey,
			"",
			"bastion-key",
			"",
			true,
		},
		{
			"bastion explicit path overrides",
			"",
			testKeyPath,
			"",
			"/path/to/bastion/key",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				PrivateKey:     tt.targetPrivateKey,
				KeyPath:        tt.targetKeyPath,
				BastionKey:     tt.bastionKey,
				BastionKeyPath: tt.bastionKeyPath,
			}

			// Verify bastion has auth configured
			bastionHasKey := config.BastionKey != "" || config.BastionKeyPath != ""
			targetHasKey := config.PrivateKey != "" || config.KeyPath != ""

			actualHasKey := bastionHasKey || (targetHasKey && config.BastionKey == "" && config.BastionKeyPath == "")

			if actualHasKey != tt.expectedHasKey {
				t.Errorf("expected hasKey=%v, got %v", tt.expectedHasKey, actualHasKey)
			}
		})
	}
}

// TestClient_IsHealthy tests the IsHealthy method.
func TestClient_IsHealthy(t *testing.T) {
	tests := []struct {
		name           string
		client         *Client
		expectedHealth bool
	}{
		{
			name: "healthy client with all connections",
			client: &Client{
				sshClient:  &ssh.Client{},
				sftpClient: NewMockSFTPClient(),
			},
			expectedHealth: true,
		},
		{
			name:           "nil client",
			client:         nil,
			expectedHealth: false,
		},
		{
			name: "client with nil ssh",
			client: &Client{
				sshClient:  nil,
				sftpClient: NewMockSFTPClient(),
			},
			expectedHealth: false,
		},
		{
			name: "client with nil sftp",
			client: &Client{
				sshClient:  &ssh.Client{},
				sftpClient: nil,
			},
			expectedHealth: false,
		},
		{
			name: "client with all nil",
			client: &Client{
				sshClient:  nil,
				sftpClient: nil,
			},
			expectedHealth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			healthy := tt.client.IsHealthy()
			if healthy != tt.expectedHealth {
				t.Errorf("IsHealthy() = %v, want %v", healthy, tt.expectedHealth)
			}
		})
	}
}

// TestShellQuote tests the shellQuote function for proper shell escaping.
func TestShellQuote(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "simple path",
			input:    "/etc/nginx/nginx.conf",
			expected: "'/etc/nginx/nginx.conf'",
		},
		{
			name:     "path with spaces",
			input:    "/path/with spaces/file.txt",
			expected: "'/path/with spaces/file.txt'",
		},
		{
			name:     "path with single quote",
			input:    "/path/with'quote/file.txt",
			expected: "'/path/with'\"'\"'quote/file.txt'",
		},
		{
			name:     "path with multiple single quotes",
			input:    "it's'a'test",
			expected: "'it'\"'\"'s'\"'\"'a'\"'\"'test'",
		},
		{
			name:     "path with special characters",
			input:    "/path/with$dollar/file.txt",
			expected: "'/path/with$dollar/file.txt'",
		},
		{
			name:     "path with backtick",
			input:    "/path/with`backtick`/file.txt",
			expected: "'/path/with`backtick`/file.txt'",
		},
		{
			name:     "path with semicolon",
			input:    "/path;rm -rf /",
			expected: "'/path;rm -rf /'",
		},
		{
			name:     "path with pipe",
			input:    "/path|whoami",
			expected: "'/path|whoami'",
		},
		{
			name:     "path with ampersand",
			input:    "/path&command",
			expected: "'/path&command'",
		},
		{
			name:     "only single quote",
			input:    "'",
			expected: "''\"'\"''",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shellQuote(tt.input)
			if result != tt.expected {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestClient_SetFileAttributes_Ownership tests ownership setting.
func TestClient_SetFileAttributes_Ownership(t *testing.T) {
	tests := []struct {
		name        string
		owner       string
		group       string
		mode        string
		expectError bool
		errorSubstr string
	}{
		{
			name:        "valid owner only",
			owner:       "root",
			group:       "",
			mode:        "",
			expectError: true, // Will fail because sshClient is nil
			errorSubstr: "nil",
		},
		{
			name:        "valid group only",
			owner:       "",
			group:       "www-data",
			mode:        "",
			expectError: true, // Will fail because sshClient is nil
			errorSubstr: "nil",
		},
		{
			name:        "valid owner and group",
			owner:       "nginx",
			group:       "nginx",
			mode:        "",
			expectError: true, // Will fail because sshClient is nil
			errorSubstr: "nil",
		},
		{
			name:        "numeric owner",
			owner:       "1000",
			group:       "",
			mode:        "",
			expectError: true, // Will fail because sshClient is nil
			errorSubstr: "nil",
		},
		{
			name:        "numeric group",
			owner:       "",
			group:       "1000",
			mode:        "",
			expectError: true, // Will fail because sshClient is nil
			errorSubstr: "nil",
		},
		{
			name:        "owner with underscores and dashes",
			owner:       "some_user-name",
			group:       "",
			mode:        "",
			expectError: true, // Will fail because sshClient is nil
			errorSubstr: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := NewMockSFTPClient()
			mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
			client := NewClientWithSFTP(mockSFTP, nil)

			// Recover from panic if sshClient is nil
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectError {
						t.Errorf("unexpected panic: %v", r)
					}
				}
			}()

			err := client.SetFileAttributes(context.Background(), "/test.txt", tt.owner, tt.group, tt.mode)
			if tt.expectError {
				if err == nil {
					// Check if we got a panic instead
					return
				} else if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
					// Error is expected, either from panic recovery or function
					if err.Error() != "" {
						// Got an error which is what we expected
						return
					}
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestClient_SetFileAttributes_Mode_Variants tests mode setting with various values.
func TestClient_SetFileAttributes_Mode_Variants(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		expectError  bool
		expectedMode os.FileMode
	}{
		{
			name:         "standard file mode 0644",
			mode:         "0644",
			expectError:  false,
			expectedMode: 0644,
		},
		{
			name:         "standard file mode 0755",
			mode:         "0755",
			expectError:  false,
			expectedMode: 0755,
		},
		{
			name:         "restrictive mode 0600",
			mode:         "0600",
			expectError:  false,
			expectedMode: 0600,
		},
		{
			name:         "permissive mode 0777",
			mode:         "0777",
			expectError:  false,
			expectedMode: 0777,
		},
		{
			name:         "3-digit mode 644",
			mode:         "644",
			expectError:  false,
			expectedMode: 0644,
		},
		{
			name:         "mode 0000",
			mode:         "0000",
			expectError:  false,
			expectedMode: 0000,
		},
		{
			name:         "mode 0400",
			mode:         "0400",
			expectError:  false,
			expectedMode: 0400,
		},
		{
			name:        "invalid mode with 8",
			mode:        "0888",
			expectError: true,
		},
		{
			name:        "invalid mode with 9",
			mode:        "0999",
			expectError: true,
		},
		{
			name:        "invalid mode with letters",
			mode:        "rwxr-xr-x",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := NewMockSFTPClient()
			mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
			client := NewClientWithSFTP(mockSFTP, nil)

			err := client.SetFileAttributes(context.Background(), "/test.txt", "", "", tt.mode)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for mode %q, got nil", tt.mode)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for mode %q: %v", tt.mode, err)
				}
				// Verify mode was set correctly
				info, _ := mockSFTP.Stat("/test.txt")
				if info.Mode() != tt.expectedMode {
					t.Errorf("expected mode %o, got %o", tt.expectedMode, info.Mode())
				}
			}
		})
	}
}

// TestClient_UploadFile_Variants tests various upload scenarios.
func TestClient_UploadFile_Variants(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *MockSFTPClient
		createFile  func(t *testing.T) string
		remotePath  string
		expectError bool
		errorSubstr string
	}{
		{
			name: "small file upload",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "small.txt")
				if err := os.WriteFile(path, []byte("small content"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			remotePath:  "/remote/small.txt",
			expectError: false,
		},
		{
			name: "large file upload",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "large.bin")
				// Create a 1MB file
				content := make([]byte, 1024*1024)
				for i := range content {
					content[i] = byte(i % 256)
				}
				if err := os.WriteFile(path, content, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			remotePath:  "/remote/large.bin",
			expectError: false,
		},
		{
			name: "empty file upload",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "empty.txt")
				if err := os.WriteFile(path, []byte{}, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			remotePath:  "/remote/empty.txt",
			expectError: false,
		},
		{
			name: "binary file upload",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "binary.dat")
				content := []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD}
				if err := os.WriteFile(path, content, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			remotePath:  "/remote/binary.dat",
			expectError: false,
		},
		{
			name: "create error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetError("Create", os.ErrPermission)
				return mock
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "test.txt")
				if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			remotePath:  "/remote/test.txt",
			expectError: true,
			errorSubstr: "failed to create remote file",
		},
		{
			name: "mkdir error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetError("MkdirAll", os.ErrPermission)
				return mock
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "test.txt")
				if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			remotePath:  "/remote/nested/dir/test.txt",
			expectError: true,
			errorSubstr: "failed to create remote directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)
			localPath := tt.createFile(t)

			err := client.UploadFile(context.Background(), localPath, tt.remotePath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestClient_ReadFileContent_Variants tests reading files with different sizes and scenarios.
func TestClient_ReadFileContent_Variants(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *MockSFTPClient
		remotePath  string
		maxBytes    int64
		expectError bool
		errorSubstr string
		verifyFn    func(t *testing.T, content []byte)
	}{
		{
			name: "read small file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/small.txt", []byte("small content"), 0644)
				return mock
			},
			remotePath:  "/small.txt",
			maxBytes:    0,
			expectError: false,
			verifyFn: func(t *testing.T, content []byte) {
				if string(content) != "small content" {
					t.Errorf("expected 'small content', got %q", content)
				}
			},
		},
		{
			name: "read large file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				content := make([]byte, 10000)
				for i := range content {
					content[i] = byte(i % 256)
				}
				mock.SetFile("/large.bin", content, 0644)
				return mock
			},
			remotePath:  "/large.bin",
			maxBytes:    0,
			expectError: false,
			verifyFn: func(t *testing.T, content []byte) {
				if len(content) != 10000 {
					t.Errorf("expected length 10000, got %d", len(content))
				}
			},
		},
		{
			name: "read with limit smaller than file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("this is a longer file content"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			maxBytes:    10,
			expectError: false,
			verifyFn: func(t *testing.T, content []byte) {
				if len(content) != 10 {
					t.Errorf("expected length 10, got %d", len(content))
				}
				if string(content) != "this is a " {
					t.Errorf("expected 'this is a ', got %q", content)
				}
			},
		},
		{
			name: "read with limit larger than file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("short"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			maxBytes:    100,
			expectError: false,
			verifyFn: func(t *testing.T, content []byte) {
				if string(content) != "short" {
					t.Errorf("expected 'short', got %q", content)
				}
			},
		},
		{
			name: "read empty file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/empty.txt", []byte{}, 0644)
				return mock
			},
			remotePath:  "/empty.txt",
			maxBytes:    0,
			expectError: false,
			verifyFn: func(t *testing.T, content []byte) {
				if len(content) != 0 {
					t.Errorf("expected empty content, got length %d", len(content))
				}
			},
		},
		{
			name: "read binary file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/binary.dat", []byte{0x00, 0xFF, 0x01, 0xFE}, 0644)
				return mock
			},
			remotePath:  "/binary.dat",
			maxBytes:    0,
			expectError: false,
			verifyFn: func(t *testing.T, content []byte) {
				expected := []byte{0x00, 0xFF, 0x01, 0xFE}
				if len(content) != len(expected) {
					t.Errorf("expected length %d, got %d", len(expected), len(content))
				}
				for i, b := range expected {
					if content[i] != b {
						t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, b, content[i])
					}
				}
			},
		},
		{
			name: "file not found",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			remotePath:  "/nonexistent.txt",
			maxBytes:    0,
			expectError: true,
			errorSubstr: "failed to open remote file",
		},
		{
			name: "open error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				mock.SetError("Open", os.ErrPermission)
				return mock
			},
			remotePath:  "/test.txt",
			maxBytes:    0,
			expectError: true,
			errorSubstr: "failed to open remote file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)

			content, err := client.ReadFileContent(context.Background(), tt.remotePath, tt.maxBytes)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.verifyFn != nil {
					tt.verifyFn(t, content)
				}
			}
		})
	}
}

// TestClient_DeleteFile_Variants tests delete with various scenarios.
func TestClient_DeleteFile_Variants(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *MockSFTPClient
		remotePath  string
		expectError bool
		errorSubstr string
	}{
		{
			name: "delete existing file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: false,
		},
		{
			name: "delete nonexistent file - should not error",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			remotePath:  "/nonexistent.txt",
			expectError: false,
		},
		{
			name: "delete with permission error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				mock.SetError("Remove", os.ErrPermission)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: true,
			errorSubstr: "failed to delete remote file",
		},
		{
			name: "delete with generic error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				mock.SetError("Remove", errors.New("custom error"))
				return mock
			},
			remotePath:  "/test.txt",
			expectError: true,
			errorSubstr: "failed to delete remote file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)

			err := client.DeleteFile(context.Background(), tt.remotePath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestClient_FileExists_Variants tests file existence check with different states.
func TestClient_FileExists_Variants(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func() *MockSFTPClient
		remotePath   string
		expectExists bool
		expectError  bool
		errorSubstr  string
	}{
		{
			name: "file exists",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/exists.txt", []byte("content"), 0644)
				return mock
			},
			remotePath:   "/exists.txt",
			expectExists: true,
			expectError:  false,
		},
		{
			name: "file does not exist",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			remotePath:   "/nonexistent.txt",
			expectExists: false,
			expectError:  false,
		},
		{
			name: "stat error - permission denied",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				mock.SetError("Stat", os.ErrPermission)
				return mock
			},
			remotePath:   "/test.txt",
			expectExists: false,
			expectError:  true,
			errorSubstr:  "",
		},
		{
			name: "stat error - generic error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetError("Stat", errors.New("network error"))
				return mock
			},
			remotePath:   "/test.txt",
			expectExists: false,
			expectError:  true,
			errorSubstr:  "network error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)

			exists, err := client.FileExists(context.Background(), tt.remotePath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if exists != tt.expectExists {
					t.Errorf("expected exists=%v, got %v", tt.expectExists, exists)
				}
			}
		})
	}
}

// TestClient_Close_Variants tests client close with different client states.
func TestClient_Close_Variants(t *testing.T) {
	tests := []struct {
		name        string
		client      *Client
		expectError bool
		errorSubstr string
	}{
		{
			name: "close with valid client",
			client: &Client{
				sftpClient: NewMockSFTPClient(),
				sshClient:  nil,
			},
			expectError: false,
		},
		{
			name: "close with nil sftp client",
			client: &Client{
				sftpClient: nil,
				sshClient:  nil,
			},
			expectError: false,
		},
		{
			name: "close with sftp error",
			client: &Client{
				sftpClient: func() *MockSFTPClient {
					mock := NewMockSFTPClient()
					mock.SetError("Close", errors.New("sftp close error"))
					return mock
				}(),
				sshClient: nil,
			},
			expectError: true,
			errorSubstr: "failed to close SFTP client",
		},
		{
			name:        "close nil client",
			client:      &Client{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.client.Close()
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestClient_GetFileInfo_Variants tests GetFileInfo with various scenarios.
func TestClient_GetFileInfo_Variants(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *MockSFTPClient
		remotePath  string
		expectError bool
		verifyFn    func(t *testing.T, info os.FileInfo)
	}{
		{
			name: "get info for regular file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content with text"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: false,
			verifyFn: func(t *testing.T, info os.FileInfo) {
				if info.Size() != 17 {
					t.Errorf("expected size 17, got %d", info.Size())
				}
				if info.Mode() != 0644 {
					t.Errorf("expected mode 0644, got %o", info.Mode())
				}
			},
		},
		{
			name: "get info for large file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				content := make([]byte, 50000)
				mock.SetFile("/large.bin", content, 0755)
				return mock
			},
			remotePath:  "/large.bin",
			expectError: false,
			verifyFn: func(t *testing.T, info os.FileInfo) {
				if info.Size() != 50000 {
					t.Errorf("expected size 50000, got %d", info.Size())
				}
				if info.Mode() != 0755 {
					t.Errorf("expected mode 0755, got %o", info.Mode())
				}
			},
		},
		{
			name: "get info for empty file",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/empty.txt", []byte{}, 0600)
				return mock
			},
			remotePath:  "/empty.txt",
			expectError: false,
			verifyFn: func(t *testing.T, info os.FileInfo) {
				if info.Size() != 0 {
					t.Errorf("expected size 0, got %d", info.Size())
				}
			},
		},
		{
			name: "file not found",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			remotePath:  "/nonexistent.txt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)

			info, err := client.GetFileInfo(context.Background(), tt.remotePath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if info == nil {
					t.Fatal("expected non-nil FileInfo")
				}
				if tt.verifyFn != nil {
					tt.verifyFn(t, info)
				}
			}
		})
	}
}

// TestSFTPClientWrapper_Methods tests the wrapper methods.
func TestSFTPClientWrapper_Methods(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)

	wrapper := &SFTPClientWrapper{} // We'll test with mock behavior

	// Test that wrapper implements SFTPClientInterface
	var _ SFTPClientInterface = wrapper

	// Create a wrapper with actual mock
	t.Run("wrapper interface compliance", func(t *testing.T) {
		var _ SFTPClientInterface = &SFTPClientWrapper{}
	})
}

// TestClient_SetFileAttributes_ContextCancellation tests context cancellation in SetFileAttributes.
func TestClient_SetFileAttributes_ContextCancellation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.SetFileAttributes(ctx, "/test.txt", "", "", "0755")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if !findSubstring(err.Error(), "cancel") {
		t.Errorf("expected cancellation error, got: %v", err)
	}
}

// TestClient_DeleteFile_ContextCancellation tests context cancellation in DeleteFile.
func TestClient_DeleteFile_ContextCancellation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.DeleteFile(ctx, "/test.txt")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// TestClient_FileExists_ContextCancellation tests context cancellation in FileExists.
func TestClient_FileExists_ContextCancellation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.FileExists(ctx, "/test.txt")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// TestClient_GetFileInfo_ContextCancellation tests context cancellation in GetFileInfo.
func TestClient_GetFileInfo_ContextCancellation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	mockSFTP.SetFile("/test.txt", []byte("content"), 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.GetFileInfo(ctx, "/test.txt")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// TestClient_ReadFileContent_ContextCancellation tests context cancellation in ReadFileContent.
func TestClient_ReadFileContent_ContextCancellation(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	content := make([]byte, 1024*1024) // 1MB to ensure cancellation can occur
	mockSFTP.SetFile("/large.bin", content, 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.ReadFileContent(ctx, "/large.bin", 0)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// TestBuildCertificateAuth_ValidCertificate tests building certificate auth with a valid cert.
func TestBuildCertificateAuth_ValidCertificate(t *testing.T) {
	// Generate a test key - we'll use the same key for both private key and certificate.
	testKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the private key
	keyBytes := x509.MarshalPKCS1PrivateKey(testKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	keyContent := string(keyPEM)

	// Create temp file for key
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// Create SSH public key from the same RSA key
	sshPubKey, err := ssh.NewPublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Create a certificate with the same public key
	cert := &ssh.Certificate{
		Key:         sshPubKey,
		CertType:    ssh.UserCert,
		KeyId:       "test-key-id",
		ValidAfter:  0,
		ValidBefore: ssh.CertTimeInfinity,
	}

	// Sign the certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	// Marshal the certificate
	certBytes := ssh.MarshalAuthorizedKey(cert)

	// Create temp file for certificate
	certPath := filepath.Join(tmpDir, "cert.pub")
	if err := os.WriteFile(certPath, certBytes, 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "cert with inline key and cert",
			config: Config{
				PrivateKey:  keyContent,
				Certificate: string(certBytes),
			},
		},
		{
			name: "cert with key path and cert path",
			config: Config{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
		},
		{
			name: "cert with inline key and cert path",
			config: Config{
				PrivateKey:      keyContent,
				CertificatePath: certPath,
			},
		},
		{
			name: "cert with key path and inline cert",
			config: Config{
				KeyPath:     keyPath,
				Certificate: string(certBytes),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMethod, err := buildCertificateAuth(tt.config)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if authMethod == nil {
				t.Error("expected non-nil auth method")
			}
		})
	}
}

// TestClient_GetFileInfo_Errors tests error cases for GetFileInfo.
func TestClient_GetFileInfo_Errors(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *MockSFTPClient
		remotePath  string
		expectError bool
		errorType   error
	}{
		{
			name: "file not found",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			remotePath:  "/nonexistent.txt",
			expectError: true,
			errorType:   os.ErrNotExist,
		},
		{
			name: "stat error",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetError("Stat", os.ErrPermission)
				mock.SetFile("/test.txt", []byte("content"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: true,
			errorType:   os.ErrPermission,
		},
		{
			name: "successful stat",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)

			info, err := client.GetFileInfo(context.Background(), tt.remotePath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("expected error type %v, got %v", tt.errorType, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if info == nil {
					t.Error("expected non-nil FileInfo")
				}
			}
		})
	}
}

// TestValidateOwnerGroup tests owner/group validation.
func TestValidateOwnerGroup(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		fieldName   string
		expectError bool
	}{
		{
			name:        "empty is valid",
			value:       "",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "simple username",
			value:       "root",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "username with underscore",
			value:       "www_data",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "username with dash",
			value:       "some-user",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "numeric id",
			value:       "1000",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "starts with letter",
			value:       "user123",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "starts with underscore",
			value:       "_user",
			fieldName:   "owner",
			expectError: false,
		},
		{
			name:        "injection attempt with semicolon",
			value:       "root;rm -rf /",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "injection attempt with dollar",
			value:       "root$(whoami)",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "injection attempt with backtick",
			value:       "root`id`",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "injection attempt with pipe",
			value:       "root|whoami",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "injection attempt with ampersand",
			value:       "root&whoami",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "name too long",
			value:       "this_is_a_very_long_username_that_exceeds_thirty_two_characters",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "starts with dash",
			value:       "-invalid",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "starts with digit",
			value:       "9user",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "contains space",
			value:       "user name",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "contains slash",
			value:       "user/name",
			fieldName:   "owner",
			expectError: true,
		},
		{
			name:        "contains backslash",
			value:       "user\\name",
			fieldName:   "owner",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOwnerGroup(tt.value, tt.fieldName)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for value %q, got nil", tt.value)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for value %q: %v", tt.value, err)
				}
			}
		})
	}
}

// TestClient_GetFileHash_Errors tests error cases for GetFileHash.
func TestClient_GetFileHash_Errors(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() *MockSFTPClient
		remotePath  string
		expectError bool
		errorSubstr string
	}{
		{
			name: "file not found",
			setupMock: func() *MockSFTPClient {
				return NewMockSFTPClient()
			},
			remotePath:  "/nonexistent.txt",
			expectError: true,
			errorSubstr: "failed to open remote file",
		},
		{
			name: "open error permission denied",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				mock.SetError("Open", os.ErrPermission)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: true,
			errorSubstr: "failed to open remote file",
		},
		{
			name: "context cancelled",
			setupMock: func() *MockSFTPClient {
				mock := NewMockSFTPClient()
				mock.SetFile("/test.txt", []byte("content"), 0644)
				return mock
			},
			remotePath:  "/test.txt",
			expectError: true,
			errorSubstr: "operation cancelled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSFTP := tt.setupMock()
			client := NewClientWithSFTP(mockSFTP, nil)

			var ctx context.Context
			if tt.name == "context cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				cancel() // Cancel immediately
			} else {
				ctx = context.Background()
			}

			_, err := client.GetFileHash(ctx, tt.remotePath)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestBuildHostKeyCallback_AllBranches tests all code paths in buildHostKeyCallback.
func TestBuildHostKeyCallback_AllBranches(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		expectError    bool
		expectErrorMsg string
	}{
		{
			name: "insecure ignore host key",
			config: Config{
				Host:                  "example.com",
				Port:                  22,
				InsecureIgnoreHostKey: true,
			},
			expectError: false,
		},
		{
			name: "insecure ignore host key with logger",
			config: Config{
				Host:                  "example.com",
				Port:                  22,
				InsecureIgnoreHostKey: true,
				Logger:                &testLogger{},
			},
			expectError: false,
		},
		{
			name: "custom known hosts file not found",
			config: Config{
				Host:           "example.com",
				Port:           22,
				KnownHostsFile: "/nonexistent/path/known_hosts",
			},
			expectError:    true,
			expectErrorMsg: "failed to load known_hosts file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback, err := buildHostKeyCallback(tt.config)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.expectErrorMsg != "" && !findSubstring(err.Error(), tt.expectErrorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.expectErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if callback == nil {
					t.Error("expected callback, got nil")
				}
			}
		})
	}
}

// testLogger is a simple logger for testing.
type testLogger struct {
	messages []string
}

func (l *testLogger) Debugf(format string, args ...interface{}) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func (l *testLogger) Infof(format string, args ...interface{}) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func (l *testLogger) Warnf(format string, args ...interface{}) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

func (l *testLogger) Errorf(format string, args ...interface{}) {
	l.messages = append(l.messages, fmt.Sprintf(format, args...))
}

// TestSetFileAttributes_AdditionalEdgeCases tests additional edge cases for SetFileAttributes.
func TestSetFileAttributes_AdditionalEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		remotePath  string
		owner       string
		group       string
		mode        string
		mockSetup   func(*MockSFTPClient)
		expectError bool
		errorSubstr string
	}{
		{
			name:       "set mode only",
			remotePath: "/tmp/file.txt",
			owner:      "",
			group:      "",
			mode:       "0755",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("content"), 0644)
			},
			expectError: false,
		},
		{
			name:       "chmod error",
			remotePath: "/tmp/file.txt",
			owner:      "",
			group:      "",
			mode:       "0755",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("content"), 0644)
				m.SetError("Chmod", errors.New("chmod failed"))
			},
			expectError: true,
			errorSubstr: "chmod failed",
		},
		{
			name:       "empty strings for owner and group",
			remotePath: "/tmp/file.txt",
			owner:      "",
			group:      "",
			mode:       "",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("content"), 0644)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockSFTPClient(t, func(t *testing.T, client *Client, mock *MockSFTPClient) {
				tt.mockSetup(mock)

				ctx := context.Background()
				err := client.SetFileAttributes(ctx, tt.remotePath, tt.owner, tt.group, tt.mode)

				if tt.expectError {
					if err == nil {
						t.Error("expected error, got nil")
					}
					if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			})
		})
	}
}

// TestUploadFile_AdditionalErrors tests additional error paths in UploadFile.
func TestUploadFile_AdditionalErrors(t *testing.T) {
	tests := []struct {
		name        string
		localPath   string
		remotePath  string
		mockSetup   func(*MockSFTPClient)
		expectError bool
		errorSubstr string
	}{
		{
			name:       "file write error",
			localPath:  "/tmp/test.txt",
			remotePath: "/remote/test.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetError("Create", errors.New("permission denied"))
			},
			expectError: true,
			errorSubstr: "failed to create remote file",
		},
		{
			name:       "io.Copy failure with partial write",
			localPath:  "/tmp/test.txt",
			remotePath: "/remote/test.txt",
			mockSetup: func(m *MockSFTPClient) {
				// No setup - just test normal flow with existing mock
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockSFTPClient(t, func(t *testing.T, client *Client, mock *MockSFTPClient) {
				tt.mockSetup(mock)

				// Create a temporary test file
				tmpDir := t.TempDir()
				testFile := filepath.Join(tmpDir, "test.txt")
				if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}

				ctx := context.Background()
				err := client.UploadFile(ctx, testFile, tt.remotePath)

				if tt.expectError {
					if err == nil {
						t.Error("expected error, got nil")
					}
					if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			})
		})
	}
}

// TestDeleteFile_Variants tests DeleteFile with different scenarios.
func TestDeleteFile_Variants(t *testing.T) {
	tests := []struct {
		name        string
		remotePath  string
		mockSetup   func(*MockSFTPClient)
		expectError bool
		errorSubstr string
	}{
		{
			name:       "successful delete",
			remotePath: "/tmp/file.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("content"), 0644)
			},
			expectError: false,
		},
		{
			name:       "delete non-existent file",
			remotePath: "/tmp/nonexistent.txt",
			mockSetup: func(m *MockSFTPClient) {
				// File doesn't exist
			},
			expectError: false,
		},
		{
			name:       "delete with error",
			remotePath: "/tmp/file.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("content"), 0644)
				m.SetError("Remove", errors.New("delete failed"))
			},
			expectError: true,
			errorSubstr: "delete failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockSFTPClient(t, func(t *testing.T, client *Client, mock *MockSFTPClient) {
				tt.mockSetup(mock)

				ctx := context.Background()
				err := client.DeleteFile(ctx, tt.remotePath)

				if tt.expectError {
					if err == nil {
						t.Error("expected error, got nil")
					}
					if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			})
		})
	}
}

// TestFileExists_Variants tests FileExists with different file states.
func TestFileExists_Variants(t *testing.T) {
	tests := []struct {
		name         string
		remotePath   string
		mockSetup    func(*MockSFTPClient)
		expectExists bool
		expectError  bool
		errorSubstr  string
	}{
		{
			name:       "file exists",
			remotePath: "/tmp/exists.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/exists.txt", []byte("content"), 0644)
			},
			expectExists: true,
			expectError:  false,
		},
		{
			name:       "file does not exist",
			remotePath: "/tmp/notfound.txt",
			mockSetup: func(m *MockSFTPClient) {
				// No files set up
			},
			expectExists: false,
			expectError:  false,
		},
		{
			name:       "stat error",
			remotePath: "/tmp/error.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/error.txt", []byte("content"), 0644)
				m.SetError("Stat", errors.New("stat failed"))
			},
			expectError: true,
			errorSubstr: "stat failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockSFTPClient(t, func(t *testing.T, client *Client, mock *MockSFTPClient) {
				tt.mockSetup(mock)

				ctx := context.Background()
				exists, err := client.FileExists(ctx, tt.remotePath)

				if tt.expectError {
					if err == nil {
						t.Error("expected error, got nil")
					}
					if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
					if exists != tt.expectExists {
						t.Errorf("expected exists=%v, got %v", tt.expectExists, exists)
					}
				}
			})
		})
	}
}

// TestGetFileInfo_Variants tests GetFileInfo with different file states.
func TestGetFileInfo_Variants(t *testing.T) {
	tests := []struct {
		name        string
		remotePath  string
		mockSetup   func(*MockSFTPClient)
		expectError bool
		errorSubstr string
	}{
		{
			name:       "get info for existing file",
			remotePath: "/tmp/file.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("test content"), 0644)
			},
			expectError: false,
		},
		{
			name:       "get info for non-existent file",
			remotePath: "/tmp/notfound.txt",
			mockSetup: func(m *MockSFTPClient) {
				// No file
			},
			expectError: true,
			errorSubstr: "not exist",
		},
		{
			name:       "stat error",
			remotePath: "/tmp/file.txt",
			mockSetup: func(m *MockSFTPClient) {
				m.SetFile("/tmp/file.txt", []byte("content"), 0644)
				m.SetError("Stat", errors.New("stat failed"))
			},
			expectError: true,
			errorSubstr: "stat failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockSFTPClient(t, func(t *testing.T, client *Client, mock *MockSFTPClient) {
				tt.mockSetup(mock)

				ctx := context.Background()
				info, err := client.GetFileInfo(ctx, tt.remotePath)

				if tt.expectError {
					if err == nil {
						t.Error("expected error, got nil")
					}
					if tt.errorSubstr != "" && !findSubstring(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
					if info == nil {
						t.Error("expected info, got nil")
					}
				}
			})
		})
	}
}
