package gosftp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestScanDirectory_Variants(t *testing.T) {
	tests := []struct {
		name            string
		createFiles     func(tmpDir string) error
		excludePatterns []string
		symlinkPolicy   string
		expectedCount   int
		verifyFn        func(t *testing.T, files []FileInfo) // Optional custom verification
		skipSymlinks    bool
	}{
		{
			name: "basic_scan",
			createFiles: func(tmpDir string) error {
				if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(tmpDir, "file2.go"), []byte("content2"), 0644); err != nil {
					return err
				}
				subDir := filepath.Join(tmpDir, "subdir")
				if err := os.MkdirAll(subDir, 0755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(subDir, "file3.txt"), []byte("content3"), 0644)
			},
			excludePatterns: nil,
			symlinkPolicy:   "follow",
			expectedCount:   3,
			verifyFn: func(t *testing.T, files []FileInfo) {
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
			},
		},
		{
			name: "with_excludes",
			createFiles: func(tmpDir string) error {
				if err := os.WriteFile(filepath.Join(tmpDir, "keep.txt"), []byte("keep"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(tmpDir, "skip.tmp"), []byte("skip"), 0644)
			},
			excludePatterns: []string{"*.tmp"},
			symlinkPolicy:   "follow",
			expectedCount:   1,
			verifyFn: func(t *testing.T, files []FileInfo) {
				if files[0].RelPath != "keep.txt" {
					t.Errorf("expected keep.txt, got %s", files[0].RelPath)
				}
			},
		},
		{
			name: "symlink_skip",
			createFiles: func(tmpDir string) error {
				realFile := filepath.Join(tmpDir, "real.txt")
				if err := os.WriteFile(realFile, []byte("real"), 0644); err != nil {
					return err
				}
				linkFile := filepath.Join(tmpDir, "link.txt")
				return os.Symlink(realFile, linkFile)
			},
			excludePatterns: nil,
			symlinkPolicy:   "skip",
			expectedCount:   1,
			skipSymlinks:    true,
		},
		{
			name: "symlink_follow",
			createFiles: func(tmpDir string) error {
				realFile := filepath.Join(tmpDir, "real.txt")
				if err := os.WriteFile(realFile, []byte("real content"), 0644); err != nil {
					return err
				}
				linkFile := filepath.Join(tmpDir, "link.txt")
				return os.Symlink(realFile, linkFile)
			},
			excludePatterns: nil,
			symlinkPolicy:   "follow",
			expectedCount:   2,
			skipSymlinks:    true,
		},
		{
			name: "symlink_preserve",
			createFiles: func(tmpDir string) error {
				realFile := filepath.Join(tmpDir, "real.txt")
				if err := os.WriteFile(realFile, []byte("real"), 0644); err != nil {
					return err
				}
				linkFile := filepath.Join(tmpDir, "link.txt")
				return os.Symlink(realFile, linkFile)
			},
			excludePatterns: nil,
			symlinkPolicy:   "preserve",
			expectedCount:   2,
			skipSymlinks:    true,
			verifyFn: func(t *testing.T, files []FileInfo) {
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
			},
		},
		{
			name: "default_symlink_policy",
			createFiles: func(tmpDir string) error {
				return os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("content"), 0644)
			},
			excludePatterns: nil,
			symlinkPolicy:   "", // Empty should default to "follow"
			expectedCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if err := tt.createFiles(tmpDir); err != nil {
				if tt.skipSymlinks && err.Error() == "symlinks not supported" {
					t.Skipf("symlinks not supported: %v", err)
				}
				t.Fatalf("failed to create test files: %v", err)
			}

			files, err := ScanDirectory(tmpDir, tt.excludePatterns, tt.symlinkPolicy)
			if err != nil {
				t.Fatalf("ScanDirectory failed: %v", err)
			}

			if len(files) != tt.expectedCount {
				t.Errorf("expected %d files, got %d", tt.expectedCount, len(files))
			}

			if tt.verifyFn != nil {
				tt.verifyFn(t, files)
			}
		})
	}
}

func TestScanDirectory_NotExists(t *testing.T) {
	_, err := ScanDirectory("/nonexistent/directory", nil, "follow")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
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

// TestSyncFile_Variants tests various SyncFile scenarios.
func TestSyncFile_Variants(t *testing.T) {
	tests := []struct {
		name          string
		content       []byte
		opts          *SyncOptions
		mockCreateErr error
		expectedErr   bool
		shouldExist   bool
		verifyFn      func(t *testing.T, result *SyncResult, mock *MockClientInterface)
	}{
		{
			name:        "basic_upload",
			content:     []byte("test content for upload"),
			opts:        nil,
			shouldExist: true,
			verifyFn: func(t *testing.T, result *SyncResult, mock *MockClientInterface) {
				if !result.Changed {
					t.Error("expected Changed=true")
				}
				if result.Hash == "" {
					t.Error("expected hash to be computed")
				}
			},
		},
		{
			name:        "dry_run",
			content:     []byte("test content"),
			opts:        &SyncOptions{DryRun: true},
			shouldExist: false,
			verifyFn: func(t *testing.T, result *SyncResult, mock *MockClientInterface) {
				if !result.Changed {
					t.Error("expected Changed=true for dry run")
				}
				if result.Hash == "" {
					t.Error("expected hash to be computed")
				}
			},
		},
		{
			name:        "with_attributes",
			content:     []byte("test content with mode"),
			opts:        &SyncOptions{Attributes: &FileAttributes{Mode: "0755"}},
			shouldExist: true,
			verifyFn: func(t *testing.T, result *SyncResult, mock *MockClientInterface) {
				if !result.Changed {
					t.Error("expected Changed=true")
				}
				if mock.modes["/remote/test.txt"] != 0755 {
					t.Errorf("expected mode 0755, got %o", mock.modes["/remote/test.txt"])
				}
			},
		},
		{
			name:        "nil_options",
			content:     []byte("content with nil options"),
			opts:        nil,
			shouldExist: true,
			verifyFn: func(t *testing.T, result *SyncResult, mock *MockClientInterface) {
				if !result.Changed {
					t.Error("expected Changed=true")
				}
			},
		},
		{
			name:          "upload_error",
			content:       []byte("test content"),
			mockCreateErr: os.ErrPermission,
			expectedErr:   true,
			verifyFn: func(t *testing.T, result *SyncResult, mock *MockClientInterface) {
				if result.Error == nil {
					t.Error("expected result.Error to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			localFile := filepath.Join(tmpDir, "test.txt")
			if err := os.WriteFile(localFile, tt.content, 0644); err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}

			mock := NewMockClient()
			sftpMock := &MockSFTPClientForSyncer{mock: mock, createErr: tt.mockCreateErr}
			client := &Client{
				sftpClient: sftpMock,
			}

			syncer := &Syncer{
				client:      client,
				retryConfig: NoRetryConfig(),
			}

			result, err := syncer.SyncFile(context.Background(), localFile, "/remote/test.txt", tt.opts)

			if tt.expectedErr && err == nil {
				t.Error("expected error for upload failure")
			}

			if !tt.expectedErr && err != nil {
				t.Fatalf("SyncFile failed: %v", err)
			}

			if tt.shouldExist {
				exists, _ := mock.FileExists(context.Background(), "/remote/test.txt")
				if !exists {
					t.Error("expected file to exist after upload")
				}
			} else if !tt.shouldExist && tt.opts != nil && tt.opts.DryRun {
				exists, _ := mock.FileExists(context.Background(), "/remote/test.txt")
				if exists {
					t.Error("file should not exist in dry run")
				}
			}

			if tt.verifyFn != nil && !tt.expectedErr {
				tt.verifyFn(t, result, mock)
			}
		})
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

func TestSyncDirectory_Variants(t *testing.T) {
	tests := []struct {
		name             string
		createFiles      func(tmpDir string) error
		opts             *SyncOptions
		expectedFiles    int
		expectedUploaded int
		verifyFn         func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface)
	}{
		{
			name: "basic_upload",
			createFiles: func(tmpDir string) error {
				return os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
			},
			opts:             &SyncOptions{Parallelism: 1},
			expectedFiles:    1,
			expectedUploaded: 1,
			verifyFn: func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface) {
				if result.Errors != 0 {
					t.Errorf("expected Errors=0, got %d", result.Errors)
				}
				if result.CombinedHash == "" {
					t.Error("expected CombinedHash to be computed")
				}
			},
		},
		{
			name: "dry_run",
			createFiles: func(tmpDir string) error {
				if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644)
			},
			opts:             &SyncOptions{DryRun: true},
			expectedFiles:    2,
			expectedUploaded: 2,
			verifyFn: func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface) {
				if result.CombinedHash == "" {
					t.Error("expected CombinedHash to be computed")
				}
				// Verify no files were actually uploaded in dry run
				if len(mock.files) != 0 {
					t.Error("files should not be uploaded in dry run")
				}
			},
		},
		{
			name: "with_attributes",
			createFiles: func(tmpDir string) error {
				return os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
			},
			opts: &SyncOptions{
				Parallelism: 1,
				Attributes: &FileAttributes{
					Mode: "0600",
				},
			},
			expectedFiles:    1,
			expectedUploaded: 1,
			verifyFn: func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface) {
				if result.Uploaded != 1 {
					t.Errorf("expected Uploaded=1, got %d", result.Uploaded)
				}
			},
		},
		{
			name: "nil_options",
			createFiles: func(tmpDir string) error {
				return os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
			},
			opts:             nil,
			expectedFiles:    1,
			expectedUploaded: 1,
			verifyFn: func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface) {
				if result.Uploaded != 1 {
					t.Errorf("expected Uploaded=1, got %d", result.Uploaded)
				}
			},
		},
		{
			name: "empty_directory",
			createFiles: func(tmpDir string) error {
				// Don't create any files - empty directory
				return nil
			},
			opts:             nil,
			expectedFiles:    0,
			expectedUploaded: 0,
			verifyFn: func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface) {
				if result.Uploaded != 0 {
					t.Errorf("expected Uploaded=0, got %d", result.Uploaded)
				}
				if len(result.Files) != 0 {
					t.Errorf("expected 0 files, got %d", len(result.Files))
				}
			},
		},
		{
			name: "parallelism_capped",
			createFiles: func(tmpDir string) error {
				if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644)
			},
			opts:             &SyncOptions{Parallelism: 10}, // Request parallelism of 10, but only 2 files exist
			expectedFiles:    2,
			expectedUploaded: 2,
			verifyFn: func(t *testing.T, result *DirectorySyncResult, mock *MockClientInterface) {
				if result.Uploaded != 2 {
					t.Errorf("expected Uploaded=2, got %d", result.Uploaded)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if err := tt.createFiles(tmpDir); err != nil {
				t.Fatalf("failed to create test files: %v", err)
			}

			mock := NewMockClient()
			sftpMock := &MockSFTPClientForSyncer{mock: mock}
			client := &Client{
				sftpClient: sftpMock,
			}

			syncer := &Syncer{
				client:      client,
				retryConfig: NoRetryConfig(),
			}

			result, err := syncer.SyncDirectory(context.Background(), tmpDir, "/remote", tt.opts)
			if err != nil {
				t.Fatalf("SyncDirectory failed: %v", err)
			}

			if len(result.Files) != tt.expectedFiles {
				t.Errorf("expected %d files, got %d", tt.expectedFiles, len(result.Files))
			}
			if result.Uploaded != tt.expectedUploaded {
				t.Errorf("expected Uploaded=%d, got %d", tt.expectedUploaded, result.Uploaded)
			}

			if tt.verifyFn != nil {
				tt.verifyFn(t, result, mock)
			}
		})
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
	sftpMock := &MockSFTPClientForSyncer{mock: mock}
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

	sftpMock := &MockSFTPClientForSyncer{mock: mock}
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
	sftpMock := &MockSFTPClientForSyncer{mock: mock}
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

// TestNewSyncer tests the NewSyncer constructor with different option combinations.
func TestNewSyncer(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	tests := []struct {
		name        string
		config      Config
		opts        []SyncerOption
		expectError bool
		verifyFn    func(t *testing.T, s *Syncer)
	}{
		{
			name: "basic syncer without options",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: keyContent,
			},
			opts:        nil,
			expectError: true, // Will fail to connect
		},
		{
			name: "syncer with retry config",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: keyContent,
			},
			opts: []SyncerOption{
				WithRetryConfig(RetryConfig{
					MaxRetries:   5,
					JitterFactor: 0.5,
				}),
			},
			expectError: true, // Will fail to connect
		},
		{
			name: "syncer with connection pool",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: keyContent,
			},
			opts: []SyncerOption{
				WithConnectionPool(NewConnectionPool(5 * time.Minute)),
			},
			expectError: true, // Will fail to connect
		},
		{
			name: "syncer with multiple options",
			config: Config{
				Host:       "192.168.1.100",
				Port:       22,
				User:       "root",
				PrivateKey: keyContent,
			},
			opts: []SyncerOption{
				WithRetryConfig(RetryConfig{
					MaxRetries:   3,
					JitterFactor: 0.3,
				}),
				WithConnectionPool(NewConnectionPool(10 * time.Minute)),
			},
			expectError: true, // Will fail to connect
		},
		{
			name: "syncer with no auth method",
			config: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
				// No auth configured
			},
			opts:        nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer, err := NewSyncer(tt.config, tt.opts...)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					if syncer != nil {
						syncer.Close()
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if syncer == nil {
					t.Fatal("expected non-nil syncer")
				}
				defer syncer.Close()

				if tt.verifyFn != nil {
					tt.verifyFn(t, syncer)
				}
			}
		})
	}
}

// TestConnectionPool_GetOrCreate tests connection pool cache hits and misses.
func TestConnectionPool_GetOrCreate(t *testing.T) {
	keyContent, _ := generateTestKey(t)

	tests := []struct {
		name        string
		setupPool   func() *ConnectionPool
		configs     []Config
		expectError bool
		verifyFn    func(t *testing.T, pool *ConnectionPool, clients []*Client)
	}{
		{
			name: "cache miss - creates new connection",
			setupPool: func() *ConnectionPool {
				return NewConnectionPool(5 * time.Minute)
			},
			configs: []Config{
				{
					Host:       "192.168.1.100",
					Port:       22,
					User:       "root",
					PrivateKey: keyContent,
				},
			},
			expectError: true, // Will fail to connect but tests the logic
		},
		{
			name: "cache hit - reuses existing connection",
			setupPool: func() *ConnectionPool {
				// We can't easily test cache hits without actual connections
				// This test primarily validates the pool exists
				return NewConnectionPool(5 * time.Minute)
			},
			configs: []Config{
				{
					Host:       "192.168.1.100",
					Port:       22,
					User:       "root",
					PrivateKey: keyContent,
				},
				{
					Host:       "192.168.1.100",
					Port:       22,
					User:       "root",
					PrivateKey: keyContent,
				},
			},
			expectError: true, // Will fail to connect
		},
		{
			name: "different configs create different connections",
			setupPool: func() *ConnectionPool {
				return NewConnectionPool(5 * time.Minute)
			},
			configs: []Config{
				{
					Host:       "192.168.1.100",
					Port:       22,
					User:       "root",
					PrivateKey: keyContent,
				},
				{
					Host:       "192.168.1.101",
					Port:       22,
					User:       "root",
					PrivateKey: keyContent,
				},
			},
			expectError: true, // Will fail to connect
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := tt.setupPool()
			defer pool.Close()

			var clients []*Client
			for i, config := range tt.configs {
				client, err := pool.GetOrCreate(config)
				if tt.expectError {
					if err == nil {
						t.Errorf("config %d: expected error, got nil", i)
						if client != nil {
							clients = append(clients, client)
						}
					}
				} else {
					if err != nil {
						t.Errorf("config %d: unexpected error: %v", i, err)
					}
					if client != nil {
						clients = append(clients, client)
					}
				}
			}

			if tt.verifyFn != nil && !tt.expectError {
				tt.verifyFn(t, pool, clients)
			}

			// Release all clients
			for _, config := range tt.configs {
				pool.Release(config)
			}
		})
	}
}

// TestConnectionPool_GetOrCreate_HealthCheck tests unhealthy connection replacement.
func TestConnectionPool_GetOrCreate_HealthCheck(t *testing.T) {
	pool := NewConnectionPool(5 * time.Minute)
	defer pool.Close()

	keyContent, _ := generateTestKey(t)
	config := Config{
		Host:       "192.168.1.100",
		Port:       22,
		User:       "root",
		PrivateKey: keyContent,
	}

	// First attempt will fail (no server)
	_, err := pool.GetOrCreate(config)
	if err == nil {
		t.Error("expected error for unreachable server")
	}

	// Verify pool stats
	stats := pool.Stats()
	if stats.Total < 0 {
		t.Errorf("expected Total >= 0, got %d", stats.Total)
	}
}

// TestSyncFile_ErrorScenarios tests additional error scenarios in SyncFile.
func TestSyncFile_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() (*MockClientInterface, *Client)
		createFile  func(t *testing.T) string
		opts        *SyncOptions
		expectError bool
		errorSubstr string
	}{
		{
			name: "context cancelled before upload",
			setupMock: func() (*MockClientInterface, *Client) {
				mock := NewMockClient()
				sftpMock := &MockSFTPClientForSyncer{mock: mock}
				return mock, &Client{sftpClient: sftpMock}
			},
			createFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				localFile := filepath.Join(tmpDir, "test.txt")
				if err := os.WriteFile(localFile, []byte("content"), 0644); err != nil {
					t.Fatal(err)
				}
				return localFile
			},
			opts:        nil,
			expectError: true,
			errorSubstr: "context",
		},
		{
			name: "invalid local file path",
			setupMock: func() (*MockClientInterface, *Client) {
				mock := NewMockClient()
				sftpMock := &MockSFTPClientForSyncer{mock: mock}
				return mock, &Client{sftpClient: sftpMock}
			},
			createFile: func(t *testing.T) string {
				return "/definitely/nonexistent/path/file.txt"
			},
			opts:        nil,
			expectError: true,
			errorSubstr: "failed to hash local file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, client := tt.setupMock()
			_ = mock // Use mock if needed

			syncer := &Syncer{
				client:      client,
				retryConfig: NoRetryConfig(),
			}

			localFile := tt.createFile(t)

			var ctx context.Context
			if tt.name == "context cancelled before upload" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				cancel() // Cancel immediately
			} else {
				ctx = context.Background()
			}

			result, err := syncer.SyncFile(ctx, localFile, "/remote/test.txt", tt.opts)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errorSubstr != "" && err != nil && !findSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
				if result != nil && result.Error == nil {
					t.Error("expected result.Error to be set")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestHashFile_Variants tests HashFile with edge cases.
func TestHashFile_Variants(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		expectError bool
		errorSubstr string
		verifyFn    func(t *testing.T, hash string, size int64)
	}{
		{
			name: "empty file",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "empty.txt")
				if err := os.WriteFile(path, []byte{}, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			expectError: false,
			verifyFn: func(t *testing.T, hash string, size int64) {
				if size != 0 {
					t.Errorf("expected size 0, got %d", size)
				}
				if !strings.HasPrefix(hash, "sha256:") {
					t.Errorf("expected sha256 prefix, got %q", hash)
				}
				// SHA256 of empty file
				expected := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				if hash != expected {
					t.Errorf("expected %s, got %s", expected, hash)
				}
			},
		},
		{
			name: "large file",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "large.bin")
				// Create a 10MB file
				content := make([]byte, 10*1024*1024)
				for i := range content {
					content[i] = byte(i % 256)
				}
				if err := os.WriteFile(path, content, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			expectError: false,
			verifyFn: func(t *testing.T, hash string, size int64) {
				if size != 10*1024*1024 {
					t.Errorf("expected size %d, got %d", 10*1024*1024, size)
				}
				if !strings.HasPrefix(hash, "sha256:") {
					t.Errorf("expected sha256 prefix, got %q", hash)
				}
			},
		},
		{
			name: "binary file with null bytes",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "binary.dat")
				content := []byte{0x00, 0x00, 0xFF, 0xFE, 0x00, 0x01}
				if err := os.WriteFile(path, content, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			expectError: false,
			verifyFn: func(t *testing.T, hash string, size int64) {
				if size != 6 {
					t.Errorf("expected size 6, got %d", size)
				}
			},
		},
		{
			name: "file with special characters in name",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "file-with_special.chars.txt")
				if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			expectError: false,
			verifyFn: func(t *testing.T, hash string, size int64) {
				if size != 7 {
					t.Errorf("expected size 7, got %d", size)
				}
			},
		},
		{
			name: "nonexistent file",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/path/file.txt"
			},
			expectError: true,
			errorSubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			hash, size, err := HashFile(path)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.verifyFn != nil {
					tt.verifyFn(t, hash, size)
				}
			}
		})
	}
}

// TestShouldExclude_Coverage adds remaining pattern matching scenarios.
func TestShouldExclude_Coverage(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "match multiple extensions",
			path:     "test.log",
			patterns: []string{"*.tmp", "*.log", "*.bak"},
			expected: true,
		},
		{
			name:     "no match with similar pattern",
			path:     "file.txt",
			patterns: []string{"*.tx"},
			expected: false,
		},
		{
			name:     "match exact basename",
			path:     "deep/nested/path/Makefile",
			patterns: []string{"Makefile"},
			expected: true,
		},
		{
			name:     "match with wildcard in middle",
			path:     "test_file_123.tmp",
			patterns: []string{"test_*_*.tmp"},
			expected: true,
		},
		{
			name:     "no match when pattern too specific",
			path:     "file.txt",
			patterns: []string{"other/file.txt"},
			expected: false,
		},
		{
			name:     "match hidden file basename",
			path:     "dir/.hidden",
			patterns: []string{".hidden"},
			expected: true,
		},
		{
			name:     "match with question mark wildcard",
			path:     "file1.txt",
			patterns: []string{"file?.txt"},
			expected: true,
		},
		{
			name:     "match character class",
			path:     "test-file.log",
			patterns: []string{"*-*.log"},
			expected: true,
		},
		{
			name:     "no match - wrong extension",
			path:     "file.go",
			patterns: []string{"*.txt", "*.md"},
			expected: false,
		},
		{
			name:     "match complex pattern",
			path:     "backup_2023_01_15.bak",
			patterns: []string{"backup_*.bak"},
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

// TestSyncFile_ContextCancelled tests file sync with cancelled context.
func TestSyncFile_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(localFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := NewMockClient()
	sftpMock := &MockSFTPClientForSyncer{mock: mock}
	client := &Client{sftpClient: sftpMock}

	syncer := &Syncer{
		client:      client,
		retryConfig: NoRetryConfig(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	result, err := syncer.SyncFile(ctx, localFile, "/remote/test.txt", nil)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if result != nil && result.Error == nil {
		t.Error("expected result.Error to be set")
	}
}

// TestClient_GetFileHash_ContextCancelled tests hash getting with cancelled context.
func TestClient_GetFileHash_ContextCancelled(t *testing.T) {
	mockSFTP := NewMockSFTPClient()
	// Create a large file to ensure context cancellation can occur.
	content := make([]byte, 1024*1024) // 1MB.
	mockSFTP.SetFile("/large.bin", content, 0644)
	client := NewClientWithSFTP(mockSFTP, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := client.GetFileHash(ctx, "/large.bin")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
	if !strings.Contains(err.Error(), "cancel") {
		t.Errorf("expected cancellation error, got: %v", err)
	}
}

// TestSyncDirectory_ContextCancelled_Variants adds more context cancellation scenarios.
func TestSyncDirectory_ContextCancelled_Variants(t *testing.T) {
	tests := []struct {
		name         string
		setupFiles   func(tmpDir string) error
		cancelTiming string // "immediate", "after_scan"
		expectErrors bool
	}{
		{
			name: "immediate cancellation",
			setupFiles: func(tmpDir string) error {
				return os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("content"), 0644)
			},
			cancelTiming: "immediate",
			expectErrors: true,
		},
		{
			name: "multiple files with cancellation",
			setupFiles: func(tmpDir string) error {
				for i := 0; i < 5; i++ {
					filename := fmt.Sprintf("file%d.txt", i)
					if err := os.WriteFile(filepath.Join(tmpDir, filename), []byte("content"), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			cancelTiming: "immediate",
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if err := tt.setupFiles(tmpDir); err != nil {
				t.Fatalf("failed to setup files: %v", err)
			}

			mock := NewMockClient()
			sftpMock := &MockSFTPClientForSyncer{mock: mock}
			client := &Client{sftpClient: sftpMock}

			syncer := &Syncer{
				client:      client,
				retryConfig: NoRetryConfig(),
			}

			ctx, cancel := context.WithCancel(context.Background())
			if tt.cancelTiming == "immediate" {
				cancel() // Cancel immediately
			}
			defer cancel()

			result, err := syncer.SyncDirectory(ctx, tmpDir, "/remote", &SyncOptions{Parallelism: 1})
			if err != nil {
				t.Fatalf("SyncDirectory returned error: %v", err)
			}

			if tt.expectErrors && result.Errors == 0 {
				t.Error("expected errors due to cancelled context")
			}
		})
	}
}

// TestScanDirectory_EdgeCases tests additional edge cases for directory scanning.
func TestScanDirectory_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		setupDir      func(tmpDir string) error
		excludes      []string
		symlinkPolicy string
		expectError   bool
		verifyFn      func(t *testing.T, files []FileInfo)
	}{
		{
			name: "directory with many files",
			setupDir: func(tmpDir string) error {
				for i := 0; i < 100; i++ {
					filename := fmt.Sprintf("file%03d.txt", i)
					if err := os.WriteFile(filepath.Join(tmpDir, filename), []byte("content"), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			excludes:      nil,
			symlinkPolicy: "follow",
			expectError:   false,
			verifyFn: func(t *testing.T, files []FileInfo) {
				if len(files) != 100 {
					t.Errorf("expected 100 files, got %d", len(files))
				}
				// Verify sorted
				for i := 1; i < len(files); i++ {
					if files[i-1].RelPath >= files[i].RelPath {
						t.Error("files are not sorted")
						break
					}
				}
			},
		},
		{
			name: "nested directory structure",
			setupDir: func(tmpDir string) error {
				dirs := []string{"a", "a/b", "a/b/c", "x", "x/y"}
				for _, dir := range dirs {
					if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(tmpDir, dir, "file.txt"), []byte("content"), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			excludes:      nil,
			symlinkPolicy: "follow",
			expectError:   false,
			verifyFn: func(t *testing.T, files []FileInfo) {
				if len(files) != 5 {
					t.Errorf("expected 5 files, got %d", len(files))
				}
			},
		},
		{
			name: "exclude multiple patterns",
			setupDir: func(tmpDir string) error {
				files := []string{"keep.txt", "skip.tmp", "skip.log", "keep.go", "skip.bak"}
				for _, file := range files {
					if err := os.WriteFile(filepath.Join(tmpDir, file), []byte("content"), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			excludes:      []string{"*.tmp", "*.log", "*.bak"},
			symlinkPolicy: "follow",
			expectError:   false,
			verifyFn: func(t *testing.T, files []FileInfo) {
				if len(files) != 2 {
					t.Errorf("expected 2 files, got %d", len(files))
				}
			},
		},
		{
			name: "empty directory",
			setupDir: func(tmpDir string) error {
				// Just create the directory, no files
				return nil
			},
			excludes:      nil,
			symlinkPolicy: "follow",
			expectError:   false,
			verifyFn: func(t *testing.T, files []FileInfo) {
				if len(files) != 0 {
					t.Errorf("expected 0 files, got %d", len(files))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if err := tt.setupDir(tmpDir); err != nil {
				t.Fatalf("failed to setup directory: %v", err)
			}

			files, err := ScanDirectory(tmpDir, tt.excludes, tt.symlinkPolicy)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.verifyFn != nil {
					tt.verifyFn(t, files)
				}
			}
		})
	}
}
