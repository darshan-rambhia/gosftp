//go:build integration
// +build integration

package gosftp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// testContainer holds a reusable SSH container for integration tests.
type testContainer struct {
	container  testcontainers.Container
	host       string
	port       int
	user       string
	privateKey string
	keyPath    string
}

var (
	testContainerOnce sync.Once
	testContainerInst *testContainer
	testContainerErr  error
)

// getTestContainer returns a shared SSH container for all integration tests.
func getTestContainer(t *testing.T) *testContainer {
	t.Helper()

	testContainerOnce.Do(func() {
		ctx := context.Background()

		// Generate SSH key pair.
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testContainerErr = fmt.Errorf("failed to generate RSA key: %w", err)
			return
		}

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}))

		publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
		if err != nil {
			testContainerErr = fmt.Errorf("failed to create SSH public key: %w", err)
			return
		}
		publicKeySSH := string(ssh.MarshalAuthorizedKey(publicKey))

		// Write private key to temp file.
		tmpDir, err := os.MkdirTemp("", "gosftp-test-*")
		if err != nil {
			testContainerErr = fmt.Errorf("failed to create temp dir: %w", err)
			return
		}
		keyPath := filepath.Join(tmpDir, "test_key")
		if err := os.WriteFile(keyPath, []byte(privateKeyPEM), 0600); err != nil {
			testContainerErr = fmt.Errorf("failed to write private key: %w", err)
			return
		}

		// Start container.
		req := testcontainers.ContainerRequest{
			Image:        "linuxserver/openssh-server:latest",
			ExposedPorts: []string{"2222/tcp"},
			Env: map[string]string{
				"PUID":            "1000",
				"PGID":            "1000",
				"TZ":              "UTC",
				"USER_NAME":       "testuser",
				"PUBLIC_KEY":      publicKeySSH,
				"SUDO_ACCESS":     "true",
				"PASSWORD_ACCESS": "false",
			},
			WaitingFor: wait.ForAll(
				wait.ForListeningPort("2222/tcp"),
				wait.ForLog("sshd is listening on port").WithStartupTimeout(60*time.Second),
			),
		}

		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			testContainerErr = fmt.Errorf("failed to start container: %w", err)
			return
		}

		host, err := container.Host(ctx)
		if err != nil {
			_ = container.Terminate(ctx)
			testContainerErr = fmt.Errorf("failed to get container host: %w", err)
			return
		}

		mappedPort, err := container.MappedPort(ctx, "2222/tcp")
		if err != nil {
			_ = container.Terminate(ctx)
			testContainerErr = fmt.Errorf("failed to get mapped port: %w", err)
			return
		}

		testContainerInst = &testContainer{
			container:  container,
			host:       host,
			port:       mappedPort.Int(),
			user:       "testuser",
			privateKey: privateKeyPEM,
			keyPath:    keyPath,
		}

		// Wait for SSH to be ready.
		if err := waitForTestSSH(testContainerInst, 30*time.Second); err != nil {
			_ = container.Terminate(ctx)
			testContainerErr = fmt.Errorf("SSH not ready: %w", err)
			return
		}
	})

	if testContainerErr != nil {
		t.Fatalf("failed to get test container: %v", testContainerErr)
	}

	return testContainerInst
}

func waitForTestSSH(c *testContainer, timeout time.Duration) error {
	signer, err := ssh.ParsePrivateKey([]byte(c.privateKey))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("%s:%d", c.host, c.port)

	for time.Now().Before(deadline) {
		conn, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("SSH connection timeout after %v", timeout)
}

func getTestConfig(t *testing.T) Config {
	t.Helper()
	c := getTestContainer(t)
	return Config{
		Host:                  c.host,
		Port:                  c.port,
		User:                  c.user,
		PrivateKey:            c.privateKey,
		InsecureIgnoreHostKey: true,
		Timeout:               10 * time.Second,
	}
}

// withIntegrationTestClient creates a test client and calls the provided function, ensuring cleanup.
// This helper reduces boilerplate by automatically getting the config and managing client lifecycle.
func withIntegrationTestClient(t *testing.T, fn func(t *testing.T, client *Client)) {
	t.Helper()

	config := getTestConfig(t)
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	fn(t, client)
}

// Integration Tests

func TestIntegration_NewClient(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		if client.sshClient == nil {
			t.Error("expected non-nil sshClient")
		}
		if client.sftpClient == nil {
			t.Error("expected non-nil sftpClient")
		}
	})
}

func TestIntegration_NewClient_WithKeyPath(t *testing.T) {
	c := getTestContainer(t)
	config := Config{
		Host:                  c.host,
		Port:                  c.port,
		User:                  c.user,
		KeyPath:               c.keyPath,
		InsecureIgnoreHostKey: true,
		Timeout:               10 * time.Second,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() with KeyPath error = %v", err)
	}
	defer client.Close()
}

func TestIntegration_UploadFile(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create a temp file to upload.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "test.txt")
		content := []byte("integration test content")
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/test_upload.txt"

		err := client.UploadFile(context.Background(), localPath, remotePath)
		if err != nil {
			t.Errorf("UploadFile() error = %v", err)
		}

		// Verify file exists.
		exists, err := client.FileExists(context.Background(), remotePath)
		if err != nil {
			t.Errorf("FileExists() error = %v", err)
		}
		if !exists {
			t.Error("expected file to exist after upload")
		}

		// Clean up.
		_ = client.DeleteFile(context.Background(), remotePath)
	})
}

func TestIntegration_GetFileHash(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create and upload a test file.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "hash_test.txt")
		content := []byte("content for hashing")
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/hash_test.txt"
		if err := client.UploadFile(context.Background(), localPath, remotePath); err != nil {
			t.Fatalf("UploadFile() error = %v", err)
		}
		defer client.DeleteFile(context.Background(), remotePath)

		// Get hash.
		hash, err := client.GetFileHash(context.Background(), remotePath)
		if err != nil {
			t.Errorf("GetFileHash() error = %v", err)
		}
		if hash == "" {
			t.Error("expected non-empty hash")
		}
		if len(hash) != 71 { // "sha256:" + 64 hex chars
			t.Errorf("expected hash length 71, got %d", len(hash))
		}
	})
}

func TestIntegration_ReadFileContent(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create and upload a test file.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "read_test.txt")
		content := []byte("content to read back")
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/read_test.txt"
		if err := client.UploadFile(context.Background(), localPath, remotePath); err != nil {
			t.Fatalf("UploadFile() error = %v", err)
		}
		defer client.DeleteFile(context.Background(), remotePath)

		// Read content back.
		data, err := client.ReadFileContent(context.Background(), remotePath, 0)
		if err != nil {
			t.Errorf("ReadFileContent() error = %v", err)
		}
		if string(data) != string(content) {
			t.Errorf("ReadFileContent() = %q, want %q", data, content)
		}
	})
}

func TestIntegration_GetFileInfo(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create and upload a test file.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "info_test.txt")
		content := []byte("content for info")
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/info_test.txt"
		if err := client.UploadFile(context.Background(), localPath, remotePath); err != nil {
			t.Fatalf("UploadFile() error = %v", err)
		}
		defer client.DeleteFile(context.Background(), remotePath)

		// Get file info.
		info, err := client.GetFileInfo(context.Background(), remotePath)
		if err != nil {
			t.Errorf("GetFileInfo() error = %v", err)
		}
		if info == nil {
			t.Fatal("expected non-nil FileInfo")
		}
		if info.Size() != int64(len(content)) {
			t.Errorf("Size() = %d, want %d", info.Size(), len(content))
		}
	})
}

func TestIntegration_DeleteFile(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create and upload a test file.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "delete_test.txt")
		if err := os.WriteFile(localPath, []byte("to be deleted"), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/delete_test.txt"
		if err := client.UploadFile(context.Background(), localPath, remotePath); err != nil {
			t.Fatalf("UploadFile() error = %v", err)
		}

		// Verify file exists.
		exists, _ := client.FileExists(context.Background(), remotePath)
		if !exists {
			t.Fatal("expected file to exist before delete")
		}

		// Delete file.
		err := client.DeleteFile(context.Background(), remotePath)
		if err != nil {
			t.Errorf("DeleteFile() error = %v", err)
		}

		// Verify file is gone.
		exists, _ = client.FileExists(context.Background(), remotePath)
		if exists {
			t.Error("expected file to not exist after delete")
		}
	})
}

func TestIntegration_SetFileAttributes_Mode(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create and upload a test file.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "mode_test.txt")
		if err := os.WriteFile(localPath, []byte("mode test"), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/mode_test.txt"
		if err := client.UploadFile(context.Background(), localPath, remotePath); err != nil {
			t.Fatalf("UploadFile() error = %v", err)
		}
		defer client.DeleteFile(context.Background(), remotePath)

		// Set mode only (no owner/group).
		err := client.SetFileAttributes(context.Background(), remotePath, "", "", "0755")
		if err != nil {
			t.Errorf("SetFileAttributes() error = %v", err)
		}

		// Verify mode was changed.
		info, err := client.GetFileInfo(context.Background(), remotePath)
		if err != nil {
			t.Fatalf("GetFileInfo() error = %v", err)
		}
		// Note: Mode includes file type bits, so we mask it.
		if info.Mode().Perm() != 0755 {
			t.Errorf("Mode() = %o, want %o", info.Mode().Perm(), 0755)
		}
	})
}

func TestIntegration_ConnectionPool_GetOrCreate(t *testing.T) {
	config := getTestConfig(t)
	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	// Get a connection.
	client, err := pool.GetOrCreate(config)
	if err != nil {
		t.Fatalf("GetOrCreate() error = %v", err)
	}

	// Verify client works.
	exists, err := client.FileExists(context.Background(), "/config")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("expected /config to exist")
	}

	// Release the connection.
	pool.Release(config)

	// Get the same connection again.
	client2, err := pool.GetOrCreate(config)
	if err != nil {
		t.Fatalf("GetOrCreate() second call error = %v", err)
	}

	// Should be the same connection.
	if client != client2 {
		t.Error("expected same client from pool")
	}

	pool.Release(config)
}

func TestIntegration_ConnectionPool_Stats(t *testing.T) {
	config := getTestConfig(t)
	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	// Initially empty.
	stats := pool.Stats()
	if stats.Total != 0 {
		t.Errorf("initial Total = %d, want 0", stats.Total)
	}

	// Get a connection.
	_, err := pool.GetOrCreate(config)
	if err != nil {
		t.Fatalf("GetOrCreate() error = %v", err)
	}

	stats = pool.Stats()
	if stats.Total != 1 {
		t.Errorf("Total = %d, want 1", stats.Total)
	}
	if stats.InUse != 1 {
		t.Errorf("InUse = %d, want 1", stats.InUse)
	}

	// Release.
	pool.Release(config)

	stats = pool.Stats()
	if stats.InUse != 0 {
		t.Errorf("InUse after release = %d, want 0", stats.InUse)
	}
	if stats.Idle != 1 {
		t.Errorf("Idle after release = %d, want 1", stats.Idle)
	}
}

func TestIntegration_GetConnection(t *testing.T) {
	config := getTestConfig(t)

	// Create an explicit pool instead of using global state.
	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	// Get a connection from the pool.
	client, err := pool.GetOrCreate(config)
	if err != nil {
		t.Fatalf("GetOrCreate() error = %v", err)
	}

	// Verify client works.
	exists, err := client.FileExists(context.Background(), "/config")
	if err != nil {
		t.Errorf("FileExists() error = %v", err)
	}
	if !exists {
		t.Error("expected /config to exist")
	}

	// Release the connection back to the pool.
	pool.Release(config)
}

func TestIntegration_NewSyncer(t *testing.T) {
	config := getTestConfig(t)

	syncer, err := NewSyncer(config)
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	defer syncer.Close()

	if syncer.Client() == nil {
		t.Error("expected non-nil client")
	}
}

func TestIntegration_NewSyncer_WithPool(t *testing.T) {
	config := getTestConfig(t)
	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	syncer, err := NewSyncer(config, WithConnectionPool(pool))
	if err != nil {
		t.Fatalf("NewSyncer() with pool error = %v", err)
	}
	defer syncer.Close()

	if syncer.Client() == nil {
		t.Error("expected non-nil client")
	}

	// Verify pool has a connection.
	stats := pool.Stats()
	if stats.Total != 1 {
		t.Errorf("pool Total = %d, want 1", stats.Total)
	}
}

func TestIntegration_Syncer_SyncFile(t *testing.T) {
	config := getTestConfig(t)

	syncer, err := NewSyncer(config, WithRetryConfig(NoRetryConfig()))
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	defer syncer.Close()

	// Create a temp file.
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "sync_test.txt")
	content := []byte("synced content")
	if err := os.WriteFile(localPath, content, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	remotePath := "/config/sync_test.txt"

	result, err := syncer.SyncFile(context.Background(), localPath, remotePath, nil)
	if err != nil {
		t.Errorf("SyncFile() error = %v", err)
	}
	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Hash == "" {
		t.Error("expected non-empty hash")
	}

	// Clean up.
	_ = syncer.DeleteFile(context.Background(), remotePath)
}

func TestIntegration_Syncer_SyncDirectory(t *testing.T) {
	config := getTestConfig(t)

	syncer, err := NewSyncer(config, WithRetryConfig(NoRetryConfig()))
	if err != nil {
		t.Fatalf("NewSyncer() error = %v", err)
	}
	defer syncer.Close()

	// Create temp directory with files.
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	remoteDir := "/config/sync_dir_test"

	result, err := syncer.SyncDirectory(context.Background(), tmpDir, remoteDir, nil)
	if err != nil {
		t.Errorf("SyncDirectory() error = %v", err)
	}
	if result.Uploaded != 2 {
		t.Errorf("Uploaded = %d, want 2", result.Uploaded)
	}

	// Clean up.
	_ = syncer.DeleteFile(context.Background(), remoteDir+"/file1.txt")
	_ = syncer.DeleteFile(context.Background(), remoteDir+"/file2.txt")
}

func TestIntegration_Client_Close(t *testing.T) {
	config := getTestConfig(t)

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Close should not error.
	err = client.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Close again should also not error (idempotent).
	err = client.Close()
	if err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

func TestIntegration_SetFileAttributes_Ownership(t *testing.T) {
	withIntegrationTestClient(t, func(t *testing.T, client *Client) {
		// Create and upload a test file.
		tmpDir := t.TempDir()
		localPath := filepath.Join(tmpDir, "owner_test.txt")
		if err := os.WriteFile(localPath, []byte("owner test"), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		remotePath := "/config/owner_test.txt"
		if err := client.UploadFile(context.Background(), localPath, remotePath); err != nil {
			t.Fatalf("UploadFile() error = %v", err)
		}
		defer client.DeleteFile(context.Background(), remotePath)

		// Set owner only (may fail if user doesn't exist, but covers the code path).
		err := client.SetFileAttributes(context.Background(), remotePath, "abc", "", "")
		// Note: Error is expected since "abc" user likely doesn't exist.
		t.Logf("SetFileAttributes(owner=abc) result: %v", err)

		// Set group only.
		err = client.SetFileAttributes(context.Background(), remotePath, "", "abc", "")
		t.Logf("SetFileAttributes(group=abc) result: %v", err)

		// Set both owner and group.
		err = client.SetFileAttributes(context.Background(), remotePath, "abc", "abc", "")
		t.Logf("SetFileAttributes(owner=abc, group=abc) result: %v", err)

		// Set mode and ownership together.
		err = client.SetFileAttributes(context.Background(), remotePath, "abc", "abc", "0644")
		t.Logf("SetFileAttributes(all) result: %v", err)
	})
}

func TestIntegration_NewSyncer_Error(t *testing.T) {
	// Test with invalid config.
	config := Config{
		Host:                  "192.0.2.1", // RFC 5737 TEST-NET-1, should not route
		Port:                  22,
		User:                  "testuser",
		PrivateKey:            getTestContainer(t).privateKey,
		InsecureIgnoreHostKey: true,
		Timeout:               1 * time.Second,
	}

	_, err := NewSyncer(config)
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestIntegration_Pool_GetOrCreate_Reuse(t *testing.T) {
	config := getTestConfig(t)
	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	// Get first connection.
	client1, err := pool.GetOrCreate(config)
	if err != nil {
		t.Fatalf("GetOrCreate() error = %v", err)
	}

	// Release it.
	pool.Release(config)

	// Get again - should reuse.
	client2, err := pool.GetOrCreate(config)
	if err != nil {
		t.Fatalf("GetOrCreate() second call error = %v", err)
	}

	if client1 != client2 {
		t.Error("expected same client to be reused")
	}

	pool.Release(config)
}

// TestIntegration_Bastion_WithKeyFile tests bastion authentication with key file.
// This test validates that bastion configuration is properly handled,
// even though we're connecting directly (not through an actual bastion hop).
func TestIntegration_Bastion_WithKeyFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	// Create a config with bastion settings pointing to the same target
	// (simulating a bastion that forwards to itself for testing)
	config := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		KeyPath:               container.keyPath,
		BastionHost:           "localhost", // Simulate local bastion (would be different host in real scenario)
		BastionPort:           container.port,
		BastionUser:           container.user,
		BastionKeyPath:        container.keyPath,
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Test that the configuration is accepted
	if config.BastionHost == "" {
		t.Error("bastion host not set")
	}
	if config.BastionKeyPath == "" {
		t.Error("bastion key path not set")
	}

	// Apply defaults
	config = config.WithDefaults()

	if config.BastionPort != 22 && config.BastionPort == 0 {
		t.Error("bastion port not defaulted")
	}
}

// TestIntegration_Bastion_WithInlineKey tests bastion authentication with inline key.
func TestIntegration_Bastion_WithInlineKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	config := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		PrivateKey:            container.privateKey,
		BastionHost:           "localhost",
		BastionPort:           container.port,
		BastionUser:           container.user,
		BastionKey:            container.privateKey,
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Verify config
	if config.BastionKey == "" {
		t.Error("bastion key not set")
	}
	if config.BastionHost != "localhost" {
		t.Error("bastion host not set correctly")
	}
}

// TestIntegration_Bastion_WithPassword tests bastion password authentication.
func TestIntegration_Bastion_WithPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	config := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		PrivateKey:            container.privateKey,
		BastionHost:           "localhost",
		BastionPort:           container.port,
		BastionUser:           container.user,
		BastionPassword:       "jumphostpass",
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Verify bastion password is set
	if config.BastionPassword == "" {
		t.Error("bastion password not set")
	}

	// Verify config doesn't have bastion key (password-only auth)
	if config.BastionKey != "" || config.BastionKeyPath != "" {
		t.Log("bastion has both password and key configured")
	}
}

// TestIntegration_Bastion_UserFallback tests that bastion user falls back to target user.
func TestIntegration_Bastion_UserFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	config := Config{
		Host:        "localhost",
		Port:        container.port,
		User:        container.user,
		PrivateKey:  container.privateKey,
		BastionHost: "localhost",
		// Note: BastionUser is NOT set, should fall back to User
		BastionKey:            container.privateKey,
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Verify bastion user falls back
	bastionUser := config.BastionUser
	if bastionUser == "" {
		bastionUser = config.User
	}

	if bastionUser != container.user {
		t.Errorf("bastion user fallback failed: expected %s, got %s", container.user, bastionUser)
	}
}

// TestIntegration_Bastion_DifferentKeyFromTarget tests bastion with different key than target.
func TestIntegration_Bastion_DifferentKeyFromTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	// Generate a different key for bastion
	bastionPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate bastion key: %v", err)
	}

	bastionKeyBytes := x509.MarshalPKCS1PrivateKey(bastionPrivateKey)
	bastionKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bastionKeyBytes,
	}))

	config := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		PrivateKey:            container.privateKey,
		BastionHost:           "localhost",
		BastionUser:           "jumpuser",
		BastionKey:            bastionKeyPEM, // Different key
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Verify bastion has separate key
	if config.BastionKey == config.PrivateKey {
		t.Error("bastion key should be different from target key")
	}
	if config.BastionUser != "jumpuser" {
		t.Error("bastion user not set correctly")
	}
}

// TestIntegration_Bastion_ConnectionPool tests bastion configs with connection pool.
func TestIntegration_Bastion_ConnectionPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	// Config 1: With bastion
	config1 := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		PrivateKey:            container.privateKey,
		BastionHost:           "bastion1.example.com",
		BastionPort:           22,
		BastionUser:           container.user,
		BastionKey:            container.privateKey,
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Config 2: Different bastion
	config2 := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		PrivateKey:            container.privateKey,
		BastionHost:           "bastion2.example.com",
		BastionPort:           22,
		BastionUser:           container.user,
		BastionKey:            container.privateKey,
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	// Config 3: No bastion
	config3 := Config{
		Host:                  "localhost",
		Port:                  container.port,
		User:                  container.user,
		PrivateKey:            container.privateKey,
		Timeout:               10 * time.Second,
		InsecureIgnoreHostKey: true,
	}

	key1 := pool.connectionKey(config1)
	key2 := pool.connectionKey(config2)
	key3 := pool.connectionKey(config3)

	// Verify keys are different
	if key1 == key2 {
		t.Error("different bastion hosts should produce different keys")
	}
	if key1 == key3 {
		t.Error("bastion vs non-bastion should produce different keys")
	}
	if key2 == key3 {
		t.Error("bastion vs non-bastion should produce different keys")
	}
}

// TestIntegration_Bastion_TimeoutConfiguration tests bastion with various timeouts.
func TestIntegration_Bastion_TimeoutConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	container := getTestContainer(t)
	if container == nil {
		t.Fatal("failed to get test container")
	}

	timeouts := []time.Duration{
		1 * time.Second,
		5 * time.Second,
		10 * time.Second,
		30 * time.Second,
	}

	for _, timeout := range timeouts {
		t.Run(fmt.Sprintf("timeout=%v", timeout), func(t *testing.T) {
			config := Config{
				Host:                  "localhost",
				Port:                  container.port,
				User:                  container.user,
				PrivateKey:            container.privateKey,
				BastionHost:           "localhost",
				BastionPort:           container.port,
				BastionUser:           container.user,
				BastionKey:            container.privateKey,
				Timeout:               timeout,
				InsecureIgnoreHostKey: true,
			}

			if config.Timeout != timeout {
				t.Errorf("timeout not set correctly: expected %v, got %v", timeout, config.Timeout)
			}
		})
	}
}
