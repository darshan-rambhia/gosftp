package gosftp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWithRetryConfig(t *testing.T) {
	config := RetryConfig{
		MaxRetries:   5,
		JitterFactor: 0.5,
	}

	opt := WithRetryConfig(config)
	syncer := &Syncer{}
	opt(syncer)

	if syncer.retryConfig.MaxRetries != 5 {
		t.Errorf("expected MaxRetries=5, got %d", syncer.retryConfig.MaxRetries)
	}
	if syncer.retryConfig.JitterFactor != 0.5 {
		t.Errorf("expected JitterFactor=0.5, got %v", syncer.retryConfig.JitterFactor)
	}
}

func TestWithConnectionPool(t *testing.T) {
	pool := &ConnectionPool{}

	opt := WithConnectionPool(pool)
	syncer := &Syncer{}
	opt(syncer)

	if syncer.pool != pool {
		t.Error("expected pool to be set")
	}
	if !syncer.usePool {
		t.Error("expected usePool to be true")
	}
}

func TestHashFile(t *testing.T) {
	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	hash, size, err := HashFile(tmpFile)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	if size != int64(len(content)) {
		t.Errorf("expected size=%d, got %d", len(content), size)
	}

	// SHA256 of "hello world"
	expectedHash := "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expectedHash {
		t.Errorf("expected hash=%s, got %s", expectedHash, hash)
	}
}

func TestHashFile_NotExists(t *testing.T) {
	_, _, err := HashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestComputeCombinedHash(t *testing.T) {
	files := []FileInfo{
		{RelPath: "a.txt", Hash: "sha256:abc123"},
		{RelPath: "b.txt", Hash: "sha256:def456"},
	}

	hash := ComputeCombinedHash(files)
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if len(hash) < 10 {
		t.Error("expected reasonable hash length")
	}

	// Same files should produce same hash
	hash2 := ComputeCombinedHash(files)
	if hash != hash2 {
		t.Error("expected same hash for same input")
	}

	// Different order should produce different hash
	files2 := []FileInfo{
		{RelPath: "b.txt", Hash: "sha256:def456"},
		{RelPath: "a.txt", Hash: "sha256:abc123"},
	}
	hash3 := ComputeCombinedHash(files2)
	if hash == hash3 {
		t.Error("expected different hash for different order")
	}
}

func TestComputeCombinedHash_Empty(t *testing.T) {
	hash := ComputeCombinedHash([]FileInfo{})
	if hash == "" {
		t.Error("expected non-empty hash even for empty input")
	}
}

func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "no patterns",
			path:     "file.txt",
			patterns: nil,
			expected: false,
		},
		{
			name:     "match by basename",
			path:     "dir/file.tmp",
			patterns: []string{"*.tmp"},
			expected: true,
		},
		{
			name:     "match by full path",
			path:     "node_modules/package.json",
			patterns: []string{"node_modules/*"},
			expected: true,
		},
		{
			name:     "no match",
			path:     "src/main.go",
			patterns: []string{"*.tmp", "*.log"},
			expected: false,
		},
		{
			name:     "match exact filename",
			path:     ".git",
			patterns: []string{".git"},
			expected: true,
		},
		{
			name:     "match in subdirectory",
			path:     "deep/path/.git",
			patterns: []string{".git"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldExclude(tt.path, tt.patterns)
			if result != tt.expected {
				t.Errorf("shouldExclude(%q, %v) = %v, expected %v", tt.path, tt.patterns, result, tt.expected)
			}
		})
	}
}

func TestScanDirectory(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()

	// Create files
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.go"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create subdirectory with file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file3.txt"), []byte("content3"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Scan without excludes
	files, err := ScanDirectory(tmpDir, nil, "follow")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d", len(files))
	}

	// Verify files are sorted
	for i := 1; i < len(files); i++ {
		if files[i-1].RelPath >= files[i].RelPath {
			t.Error("files are not sorted")
		}
	}

	// Verify hashes are computed
	for _, f := range files {
		if f.Hash == "" {
			t.Errorf("expected hash for %s", f.RelPath)
		}
		if f.Size == 0 {
			t.Errorf("expected non-zero size for %s", f.RelPath)
		}
	}
}

func TestScanDirectory_WithExcludes(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "keep.txt"), []byte("keep"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "skip.tmp"), []byte("skip"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	files, err := ScanDirectory(tmpDir, []string{"*.tmp"}, "follow")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
	if files[0].RelPath != "keep.txt" {
		t.Errorf("expected keep.txt, got %s", files[0].RelPath)
	}
}

func TestScanDirectory_SymlinkSkip(t *testing.T) {
	tmpDir := t.TempDir()

	realFile := filepath.Join(tmpDir, "real.txt")
	if err := os.WriteFile(realFile, []byte("real"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create symlink
	linkFile := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	files, err := ScanDirectory(tmpDir, nil, "skip")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Should only have the real file, not the symlink
	if len(files) != 1 {
		t.Errorf("expected 1 file (symlink skipped), got %d", len(files))
	}
}

func TestScanDirectory_SymlinkFollow(t *testing.T) {
	tmpDir := t.TempDir()

	realFile := filepath.Join(tmpDir, "real.txt")
	content := []byte("real content")
	if err := os.WriteFile(realFile, content, 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create symlink
	linkFile := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	files, err := ScanDirectory(tmpDir, nil, "follow")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Should have both files, symlink is followed and hashed
	if len(files) != 2 {
		t.Errorf("expected 2 files (symlink followed), got %d", len(files))
	}
}

func TestScanDirectory_NotExists(t *testing.T) {
	_, err := ScanDirectory("/nonexistent/directory", nil, "follow")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestScanDirectory_DefaultSymlinkPolicy(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Empty symlink policy should default to "follow"
	files, err := ScanDirectory(tmpDir, nil, "")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

// mockSyncerClient provides a testable client for Syncer tests.
type mockSyncerClient struct {
	MockClientInterface
}

func TestSyncer_Close_WithPool(t *testing.T) {
	pool := &ConnectionPool{
		connections: make(map[string]*pooledConnection),
	}

	syncer := &Syncer{
		pool:    pool,
		usePool: true,
		config:  Config{Host: "test"},
	}

	err := syncer.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSyncer_Close_NoPool(t *testing.T) {
	syncer := &Syncer{
		usePool: false,
		client:  nil,
	}

	err := syncer.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSyncer_Client(t *testing.T) {
	client := &Client{}
	syncer := &Syncer{
		client: client,
	}

	if syncer.Client() != client {
		t.Error("expected same client")
	}
}

func TestSyncOptionsWithDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    SyncOptions
		expected SyncOptions
	}{
		{
			name:  "empty options",
			input: SyncOptions{},
			expected: SyncOptions{
				SymlinkPolicy: "follow",
				Parallelism:   4,
			},
		},
		{
			name: "custom symlink policy preserved",
			input: SyncOptions{
				SymlinkPolicy: "skip",
			},
			expected: SyncOptions{
				SymlinkPolicy: "skip",
				Parallelism:   4,
			},
		},
		{
			name: "custom parallelism preserved",
			input: SyncOptions{
				Parallelism: 8,
			},
			expected: SyncOptions{
				SymlinkPolicy: "follow",
				Parallelism:   8,
			},
		},
		{
			name: "all custom options preserved",
			input: SyncOptions{
				SymlinkPolicy:   "preserve",
				Parallelism:     16,
				DryRun:          true,
				ExcludePatterns: []string{"*.tmp"},
				Attributes: &FileAttributes{
					Owner: "root",
					Mode:  "0644",
				},
			},
			expected: SyncOptions{
				SymlinkPolicy:   "preserve",
				Parallelism:     16,
				DryRun:          true,
				ExcludePatterns: []string{"*.tmp"},
				Attributes: &FileAttributes{
					Owner: "root",
					Mode:  "0644",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.WithDefaults()
			if result.SymlinkPolicy != tt.expected.SymlinkPolicy {
				t.Errorf("SymlinkPolicy: expected %q, got %q", tt.expected.SymlinkPolicy, result.SymlinkPolicy)
			}
			if result.Parallelism != tt.expected.Parallelism {
				t.Errorf("Parallelism: expected %d, got %d", tt.expected.Parallelism, result.Parallelism)
			}
			if result.DryRun != tt.expected.DryRun {
				t.Errorf("DryRun: expected %v, got %v", tt.expected.DryRun, result.DryRun)
			}
		})
	}
}

// TestSyncFile_DryRun tests the dry run functionality.
func TestSyncFile_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	mock := NewMockClient()
	client := &Client{
		sftpClient: &mockSFTPClient{mock: mock},
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	opts := &SyncOptions{DryRun: true}
	result, err := syncer.SyncFile(context.Background(), localFile, "/remote/test.txt", opts)
	if err != nil {
		t.Fatalf("SyncFile failed: %v", err)
	}

	if !result.Changed {
		t.Error("expected Changed=true for dry run")
	}
	if result.Hash == "" {
		t.Error("expected hash to be computed")
	}

	// Verify file was NOT uploaded (dry run)
	exists, _ := mock.FileExists(context.Background(), "/remote/test.txt")
	if exists {
		t.Error("file should not exist in dry run")
	}
}

// mockSFTPClient wraps MockClientInterface to implement SFTPClientInterface.
type mockSFTPClient struct {
	mock      *MockClientInterface
	createErr error
	mkdirErr  error
}

func (m *mockSFTPClient) Open(path string) (SFTPFile, error) {
	content, exists := m.mock.files[path]
	if !exists {
		return nil, os.ErrNotExist
	}
	return &mockSFTPFile{content: content}, nil
}

func (m *mockSFTPClient) Create(path string) (SFTPFile, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	return &mockSFTPFile{path: path, mock: m.mock}, nil
}

func (m *mockSFTPClient) Remove(path string) error {
	delete(m.mock.files, path)
	return nil
}

func (m *mockSFTPClient) Stat(path string) (os.FileInfo, error) {
	content, exists := m.mock.files[path]
	if !exists {
		return nil, os.ErrNotExist
	}
	return &mockFileInfo{name: path, size: int64(len(content))}, nil
}

func (m *mockSFTPClient) Chmod(path string, mode os.FileMode) error {
	m.mock.modes[path] = mode
	return nil
}

func (m *mockSFTPClient) MkdirAll(_ string) error {
	if m.mkdirErr != nil {
		return m.mkdirErr
	}
	return nil
}

func (m *mockSFTPClient) Close() error {
	return nil
}

type mockSFTPFile struct {
	content []byte
	path    string
	mock    *MockClientInterface
	written []byte
}

func (f *mockSFTPFile) Read(p []byte) (int, error) {
	if len(f.content) == 0 {
		return 0, os.ErrNotExist
	}
	n := copy(p, f.content)
	f.content = f.content[n:]
	return n, nil
}

func (f *mockSFTPFile) Write(p []byte) (int, error) {
	f.written = append(f.written, p...)
	if f.mock != nil && f.path != "" {
		f.mock.files[f.path] = f.written
	}
	return len(p), nil
}

func (f *mockSFTPFile) Close() error {
	return nil
}

func TestSyncFile_Upload(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content for upload")
	if err := os.WriteFile(localFile, content, 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	result, err := syncer.SyncFile(context.Background(), localFile, "/remote/test.txt", nil)
	if err != nil {
		t.Fatalf("SyncFile failed: %v", err)
	}

	if !result.Changed {
		t.Error("expected Changed=true")
	}
	if result.Hash == "" {
		t.Error("expected hash to be computed")
	}
	if result.Size != int64(len(content)) {
		t.Errorf("expected size=%d, got %d", len(content), result.Size)
	}
}

func TestSyncFile_HashError(t *testing.T) {
	syncer := &Syncer{
		retryConfig: NoRetryConfig(),
	}

	// Try to sync a nonexistent file
	result, err := syncer.SyncFile(context.Background(), "/nonexistent/file.txt", "/remote/test.txt", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if result.Error == nil {
		t.Error("expected result.Error to be set")
	}
}

func TestSyncDirectory_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	mock := NewMockClient()
	client := &Client{
		sftpClient: &mockSFTPClient{mock: mock},
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	opts := &SyncOptions{DryRun: true}
	result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", opts)
	if err != nil {
		t.Fatalf("SyncDirectory failed: %v", err)
	}

	if len(result.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(result.Files))
	}
	if result.Uploaded != 2 {
		t.Errorf("expected Uploaded=2, got %d", result.Uploaded)
	}
	if result.CombinedHash == "" {
		t.Error("expected CombinedHash to be computed")
	}

	// Verify no files were actually uploaded
	if len(mock.files) != 0 {
		t.Error("files should not be uploaded in dry run")
	}
}

func TestSyncDirectory_Upload(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	opts := &SyncOptions{Parallelism: 1}
	result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", opts)
	if err != nil {
		t.Fatalf("SyncDirectory failed: %v", err)
	}

	if result.Uploaded != 1 {
		t.Errorf("expected Uploaded=1, got %d", result.Uploaded)
	}
	if result.Errors != 0 {
		t.Errorf("expected Errors=0, got %d", result.Errors)
	}
}

func TestSyncDirectory_ScanError(t *testing.T) {
	syncer := &Syncer{
		retryConfig: NoRetryConfig(),
	}

	_, err := syncer.SyncDirectory(context.Background(), "/nonexistent/dir", "/remote", nil)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestSyncDirectory_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	opts := &SyncOptions{Parallelism: 1}
	result, err := syncer.SyncDirectory(ctx, tmpDir, "/remote", opts)
	// Should not return error, but files should have errors
	if err != nil {
		t.Fatalf("SyncDirectory returned error: %v", err)
	}

	if result.Errors == 0 {
		t.Error("expected errors due to cancelled context")
	}
}

func TestSyncer_DeleteFile(t *testing.T) {
	mock := NewMockClient()
	mock.SetFile("/remote/test.txt", []byte("content"), 0644)

	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	err := syncer.DeleteFile(context.Background(), "/remote/test.txt")
	if err != nil {
		t.Errorf("DeleteFile failed: %v", err)
	}

	// Verify file was deleted
	if _, exists := mock.files["/remote/test.txt"]; exists {
		t.Error("file should have been deleted")
	}
}

func TestSyncDirectory_ParallelismCapped(t *testing.T) {
	tmpDir := t.TempDir()
	// Create just 2 files
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	// Request parallelism of 10, but only 2 files exist
	opts := &SyncOptions{Parallelism: 10}
	result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", opts)
	if err != nil {
		t.Fatalf("SyncDirectory failed: %v", err)
	}

	if result.Uploaded != 2 {
		t.Errorf("expected Uploaded=2, got %d", result.Uploaded)
	}
}

func TestSyncFile_WithAttributes(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	opts := &SyncOptions{
		Attributes: &FileAttributes{
			Mode: "0755",
		},
	}
	result, err := syncer.SyncFile(context.Background(), localFile, "/remote/test.txt", opts)
	if err != nil {
		t.Fatalf("SyncFile failed: %v", err)
	}

	if !result.Changed {
		t.Error("expected Changed=true")
	}

	// Verify mode was set
	if mock.modes["/remote/test.txt"] != 0755 {
		t.Errorf("expected mode 0755, got %o", mock.modes["/remote/test.txt"])
	}
}

func TestSyncDirectory_WithAttributes(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	opts := &SyncOptions{
		Parallelism: 1,
		Attributes: &FileAttributes{
			Mode: "0600",
		},
	}
	result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", opts)
	if err != nil {
		t.Fatalf("SyncDirectory failed: %v", err)
	}

	if result.Uploaded != 1 {
		t.Errorf("expected Uploaded=1, got %d", result.Uploaded)
	}
}

func TestScanDirectory_PreserveSymlink(t *testing.T) {
	tmpDir := t.TempDir()

	realFile := filepath.Join(tmpDir, "real.txt")
	if err := os.WriteFile(realFile, []byte("real"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create symlink
	linkFile := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	files, err := ScanDirectory(tmpDir, nil, "preserve")
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Should have both files
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}

	// Find the symlink entry
	var symlinkFile *FileInfo
	for i := range files {
		if files[i].IsSymlink {
			symlinkFile = &files[i]
			break
		}
	}

	if symlinkFile == nil {
		t.Fatal("expected to find symlink file")
	}

	if !symlinkFile.IsSymlink {
		t.Error("expected IsSymlink=true")
	}
	if symlinkFile.SymlinkTarget == "" {
		t.Error("expected SymlinkTarget to be set")
	}
	if symlinkFile.Size != 0 {
		t.Errorf("expected symlink size=0, got %d", symlinkFile.Size)
	}
}

func TestScanDirectory_WalkError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory with restrictive permissions
	restrictedDir := filepath.Join(tmpDir, "restricted")
	if err := os.MkdirAll(restrictedDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(restrictedDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Make the directory unreadable
	if err := os.Chmod(restrictedDir, 0000); err != nil {
		t.Skipf("cannot change permissions: %v", err)
	}
	defer func() { _ = os.Chmod(restrictedDir, 0755) }() // Restore permissions for cleanup

	_, err := ScanDirectory(tmpDir, nil, "follow")
	if err == nil {
		t.Error("expected error for unreadable directory")
	}
}

func TestHashFile_ReadError(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("content"), 0000); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// On some systems, root can still read the file, so skip if we can read it
	if _, err := os.ReadFile(tmpFile); err == nil {
		t.Skip("file is readable despite permissions")
	}

	_, _, err := HashFile(tmpFile)
	if err == nil {
		t.Error("expected error for unreadable file")
	}

	// Cleanup
	_ = os.Chmod(tmpFile, 0644)
}

func TestSyncer_CloseWithClient(t *testing.T) {
	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:  client,
		usePool: false,
	}

	err := syncer.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSyncFile_UploadError(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{
		mock:      mock,
		createErr: os.ErrPermission, // Simulate upload error
	}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	result, err := syncer.SyncFile(context.Background(), localFile, "/remote/test.txt", nil)
	if err == nil {
		t.Error("expected error for upload failure")
	}
	if result.Error == nil {
		t.Error("expected result.Error to be set")
	}
}

func TestSyncFile_NilOptions(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	// Pass nil options - should use defaults
	result, err := syncer.SyncFile(context.Background(), localFile, "/remote/test.txt", nil)
	if err != nil {
		t.Fatalf("SyncFile failed: %v", err)
	}

	if !result.Changed {
		t.Error("expected Changed=true")
	}
}

func TestSyncDirectory_NilOptions(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	// Pass nil options - should use defaults
	result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", nil)
	if err != nil {
		t.Fatalf("SyncDirectory failed: %v", err)
	}

	if result.Uploaded != 1 {
		t.Errorf("expected Uploaded=1, got %d", result.Uploaded)
	}
}

func TestSyncDirectory_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	// Don't create any files - empty directory

	mock := NewMockClient()
	sftpMock := &mockSFTPClient{mock: mock}
	client := &Client{
		sftpClient: sftpMock,
	}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", nil)
	if err != nil {
		t.Fatalf("SyncDirectory failed: %v", err)
	}

	if result.Uploaded != 0 {
		t.Errorf("expected Uploaded=0, got %d", result.Uploaded)
	}
	if len(result.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(result.Files))
	}
}
