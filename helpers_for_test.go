package gosftp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// generateTestRSAKey creates a test RSA private key and returns both PEM-encoded
// key content and a path to a temp file containing the key.
func generateTestRSAKey(t *testing.T) (string, string) {
	t.Helper()

	// Generate RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	// Write to temp file.
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")
	if err := os.WriteFile(keyPath, []byte(privateKeyPEM), 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return privateKeyPEM, keyPath
}

// generateTestPublicKey generates a public key from an RSA private key for use in tests.
func generateTestPublicKey(t *testing.T, privateKeyPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		t.Fatal("failed to parse PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	publicKey, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}

	return string(gossh.MarshalAuthorizedKey(publicKey))
}

// createTempFile creates a temporary file with the given content.
func createTempFile(t *testing.T, content []byte) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_file")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	return tmpFile
}

// createTestFileStructure creates a directory structure with files for testing.
// Files is a map of relative path -> content.
func createTestFileStructure(t *testing.T, files map[string][]byte) string {
	t.Helper()

	tmpDir := t.TempDir()

	for relPath, content := range files {
		fullPath := filepath.Join(tmpDir, relPath)
		// Create parent directories if needed.
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
	}

	return tmpDir
}

// withTestClient creates a client and calls the provided function, ensuring cleanup.
func withTestClient(t *testing.T, config Config, fn func(t *testing.T, client *Client)) {
	t.Helper()

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	fn(t, client)
}

// withMockSFTPClient creates a client with a mock SFTP implementation for testing.
func withMockSFTPClient(t *testing.T, fn func(t *testing.T, client *Client, mock *MockSFTPClient)) {
	t.Helper()

	mock := NewMockSFTPClient()
	client := NewClientWithSFTP(mock, nil)
	defer client.Close()

	fn(t, client, mock)
}

// assertFileContents verifies that a file has the expected content.
func assertFileContents(t *testing.T, path string, expected []byte) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("failed to read file %s: %v", path, err)
		return
	}

	if string(content) != string(expected) {
		t.Errorf("file content mismatch:\nexpected: %q\ngot: %q", string(expected), string(content))
	}
}

// assertFileMode verifies that a file has the expected permissions.
func assertFileMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("failed to stat file %s: %v", path, err)
		return
	}

	if info.Mode().Perm() != expected.Perm() {
		t.Errorf("file mode mismatch:\nexpected: %o\ngot: %o", expected.Perm(), info.Mode().Perm())
	}
}

// assertFileExists verifies that a file exists.
func assertFileExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file to exist: %s", path)
	}
}

// assertFileNotExists verifies that a file does not exist.
func assertFileNotExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err == nil {
		t.Errorf("expected file to not exist: %s", path)
	}
}

// withTempDir creates a temporary directory and calls the provided function.
func withTempDir(t *testing.T, fn func(t *testing.T, tmpDir string)) {
	t.Helper()

	tmpDir := t.TempDir()
	fn(t, tmpDir)
}

// newTestConfig creates a Config with sensible defaults for testing.
func newTestConfig(t *testing.T) Config {
	t.Helper()

	privateKey, keyPath := generateTestRSAKey(t)

	return Config{
		Host:                  "localhost",
		Port:                  22,
		User:                  "testuser",
		PrivateKey:            privateKey,
		KeyPath:               keyPath,
		Timeout:               0, // Will use default
		InsecureIgnoreHostKey: true,
	}
}

// newTestConfigWithCustom creates a Config with custom fields applied.
func newTestConfigWithCustom(t *testing.T, customize func(*Config)) Config {
	t.Helper()

	config := newTestConfig(t)
	customize(&config)
	return config
}

// newTestBastionConfig creates a Config with bastion settings for testing.
func newTestBastionConfig(t *testing.T, bastionHost string) Config {
	t.Helper()

	privateKey, keyPath := generateTestRSAKey(t)
	bastionKey, bastionKeyPath := generateTestRSAKey(t)

	return Config{
		Host:                  "localhost",
		Port:                  22,
		User:                  "testuser",
		PrivateKey:            privateKey,
		KeyPath:               keyPath,
		BastionHost:           bastionHost,
		BastionPort:           22,
		BastionUser:           "bastionuser",
		BastionKey:            bastionKey,
		BastionKeyPath:        bastionKeyPath,
		Timeout:               0,
		InsecureIgnoreHostKey: true,
	}
}
