package gosftp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"
)

// benchContainer holds a reusable SSH container for benchmarks.
type benchContainer struct {
	container  testcontainers.Container
	host       string
	port       int
	user       string
	privateKey string
	keyPath    string
}

var (
	benchContainerOnce sync.Once
	benchContainerInst *benchContainer
)

// getBenchContainer returns a shared SSH container for all benchmarks.
// The container is created once and reused across all benchmark runs.
func getBenchContainer(b *testing.B) *benchContainer {
	b.Helper()

	benchContainerOnce.Do(func() {
		ctx := context.Background()

		// Generate SSH key pair.
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatalf("failed to generate RSA key: %v", err)
		}

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}))

		publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
		if err != nil {
			b.Fatalf("failed to create SSH public key: %v", err)
		}
		publicKeySSH := string(ssh.MarshalAuthorizedKey(publicKey))

		// Write private key to temp file.
		tmpDir, err := os.MkdirTemp("", "gosftp-bench-*")
		if err != nil {
			b.Fatalf("failed to create temp dir: %v", err)
		}
		keyPath := filepath.Join(tmpDir, "bench_key")
		if err := os.WriteFile(keyPath, []byte(privateKeyPEM), 0600); err != nil {
			b.Fatalf("failed to write private key: %v", err)
		}

		// Start container.
		req := testcontainers.ContainerRequest{
			Image:        "linuxserver/openssh-server:latest",
			ExposedPorts: []string{"2222/tcp"},
			Env: map[string]string{
				"PUID":            "1000",
				"PGID":            "1000",
				"TZ":              "UTC",
				"USER_NAME":       "benchuser",
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
			b.Fatalf("failed to start container: %v", err)
		}

		host, err := container.Host(ctx)
		if err != nil {
			_ = container.Terminate(ctx)
			b.Fatalf("failed to get container host: %v", err)
		}

		mappedPort, err := container.MappedPort(ctx, "2222/tcp")
		if err != nil {
			_ = container.Terminate(ctx)
			b.Fatalf("failed to get mapped port: %v", err)
		}

		benchContainerInst = &benchContainer{
			container:  container,
			host:       host,
			port:       mappedPort.Int(),
			user:       "benchuser",
			privateKey: privateKeyPEM,
			keyPath:    keyPath,
		}

		// Wait for SSH to be ready.
		if err := waitForBenchSSH(benchContainerInst, 30*time.Second); err != nil {
			_ = container.Terminate(ctx)
			b.Fatalf("SSH not ready: %v", err)
		}
	})

	return benchContainerInst
}

func waitForBenchSSH(c *benchContainer, timeout time.Duration) error {
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
		client, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			client.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for SSH at %s", addr)
}

func (c *benchContainer) config() Config {
	return Config{
		Host:                  c.host,
		Port:                  c.port,
		User:                  c.user,
		PrivateKey:            c.privateKey,
		InsecureIgnoreHostKey: true,
		Timeout:               30 * time.Second,
	}
}

// createTestFile creates a temporary file with random content of the specified size.
func createTestFile(b *testing.B, size int) string {
	b.Helper()

	f, err := os.CreateTemp("", "gosftp-bench-*.dat")
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}
	defer f.Close()

	// Write random data in chunks.
	buf := make([]byte, 32*1024) // 32KB chunks
	remaining := size
	for remaining > 0 {
		toWrite := len(buf)
		if toWrite > remaining {
			toWrite = remaining
		}
		if _, err := rand.Read(buf[:toWrite]); err != nil {
			b.Fatalf("failed to generate random data: %v", err)
		}
		if _, err := f.Write(buf[:toWrite]); err != nil {
			b.Fatalf("failed to write data: %v", err)
		}
		remaining -= toWrite
	}

	return f.Name()
}

// BenchmarkUpload benchmarks file upload throughput for various file sizes.
func BenchmarkUpload(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	bc := getBenchContainer(b)
	ctx := context.Background()

	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			// Create test file.
			localPath := createTestFile(b, sz.size)
			defer os.Remove(localPath)

			// Create client.
			client, err := NewClient(bc.config())
			if err != nil {
				b.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			b.ResetTimer()
			b.SetBytes(int64(sz.size))

			for i := 0; i < b.N; i++ {
				remotePath := fmt.Sprintf("/tmp/bench-%d-%d.dat", sz.size, i)
				if err := client.UploadFile(ctx, localPath, remotePath); err != nil {
					b.Fatalf("upload failed: %v", err)
				}
				// Clean up remote file.
				_ = client.DeleteFile(ctx, remotePath)
			}
		})
	}
}

// BenchmarkConnectionSetup benchmarks the time to establish a new SSH connection.
func BenchmarkConnectionSetup(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	bc := getBenchContainer(b)
	config := bc.config()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client, err := NewClient(config)
		if err != nil {
			b.Fatalf("failed to create client: %v", err)
		}
		client.Close()
	}
}

// BenchmarkConnectionPool benchmarks connection pool performance vs direct connections.
func BenchmarkConnectionPool(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	bc := getBenchContainer(b)
	config := bc.config()
	ctx := context.Background()

	// Create a small test file.
	localPath := createTestFile(b, 1024)
	defer os.Remove(localPath)

	b.Run("DirectConnection", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			client, err := NewClient(config)
			if err != nil {
				b.Fatalf("failed to create client: %v", err)
			}

			remotePath := fmt.Sprintf("/tmp/bench-direct-%d.dat", i)
			if err := client.UploadFile(ctx, localPath, remotePath); err != nil {
				b.Fatalf("upload failed: %v", err)
			}
			_ = client.DeleteFile(ctx, remotePath)

			client.Close()
		}
	})

	b.Run("PooledConnection", func(b *testing.B) {
		pool := NewConnectionPool(5 * time.Minute)
		defer pool.Close()

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			client, err := pool.GetOrCreate(config)
			if err != nil {
				b.Fatalf("failed to get pooled client: %v", err)
			}

			remotePath := fmt.Sprintf("/tmp/bench-pool-%d.dat", i)
			if err := client.UploadFile(ctx, localPath, remotePath); err != nil {
				b.Fatalf("upload failed: %v", err)
			}
			_ = client.DeleteFile(ctx, remotePath)

			pool.Release(config)
		}
	})
}

// BenchmarkHash benchmarks the GetFileHash operation.
func BenchmarkHash(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	bc := getBenchContainer(b)
	ctx := context.Background()

	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			// Create and upload test file.
			localPath := createTestFile(b, sz.size)
			defer os.Remove(localPath)

			client, err := NewClient(bc.config())
			if err != nil {
				b.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			remotePath := fmt.Sprintf("/tmp/bench-hash-%d.dat", sz.size)
			if err := client.UploadFile(ctx, localPath, remotePath); err != nil {
				b.Fatalf("upload failed: %v", err)
			}
			defer client.DeleteFile(ctx, remotePath)

			b.ResetTimer()
			b.SetBytes(int64(sz.size))

			for i := 0; i < b.N; i++ {
				_, err := client.GetFileHash(ctx, remotePath)
				if err != nil {
					b.Fatalf("hash failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkParallelUpload benchmarks parallel upload with different worker counts.
func BenchmarkParallelUpload(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	bc := getBenchContainer(b)
	ctx := context.Background()

	// Create test files.
	const numFiles = 20
	const fileSize = 10 * 1024 // 10KB each

	localFiles := make([]string, numFiles)
	for i := 0; i < numFiles; i++ {
		localFiles[i] = createTestFile(b, fileSize)
	}
	defer func() {
		for _, f := range localFiles {
			os.Remove(f)
		}
	}()

	parallelisms := []int{1, 2, 4, 8}

	for _, p := range parallelisms {
		b.Run(fmt.Sprintf("Workers-%d", p), func(b *testing.B) {
			client, err := NewClient(bc.config())
			if err != nil {
				b.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			b.ResetTimer()
			b.SetBytes(int64(numFiles * fileSize))

			for i := 0; i < b.N; i++ {
				// Upload files in parallel using a worker pool.
				type job struct {
					local  string
					remote string
				}

				jobs := make(chan job, numFiles)
				var wg sync.WaitGroup

				// Start workers.
				for w := 0; w < p; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := range jobs {
							if err := client.UploadFile(ctx, j.local, j.remote); err != nil {
								b.Errorf("upload failed: %v", err)
							}
						}
					}()
				}

				// Send jobs.
				for j, localPath := range localFiles {
					remotePath := fmt.Sprintf("/tmp/bench-parallel-%d-%d-%d.dat", p, i, j)
					jobs <- job{local: localPath, remote: remotePath}
				}
				close(jobs)

				wg.Wait()

				// Clean up.
				for j := range localFiles {
					remotePath := fmt.Sprintf("/tmp/bench-parallel-%d-%d-%d.dat", p, i, j)
					_ = client.DeleteFile(ctx, remotePath)
				}
			}
		})
	}
}

// BenchmarkLocalHash benchmarks local SHA256 computation (to understand network vs CPU time).
func BenchmarkLocalHash(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			// Create test file.
			localPath := createTestFile(b, sz.size)
			defer os.Remove(localPath)

			b.ResetTimer()
			b.SetBytes(int64(sz.size))

			for i := 0; i < b.N; i++ {
				_, err := computeLocalHash(localPath)
				if err != nil {
					b.Fatalf("hash failed: %v", err)
				}
			}
		})
	}
}

// computeLocalHash computes SHA256 of a local file.
func computeLocalHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
