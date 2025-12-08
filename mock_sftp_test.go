package gosftp

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// mockFileInfo implements os.FileInfo for testing.
type mockFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return m.modTime }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() any           { return nil }

// MockClientInterface provides a testable client implementation.
type MockClientInterface struct {
	mu          sync.RWMutex
	files       map[string][]byte
	modes       map[string]os.FileMode
	owners      map[string]string
	groups      map[string]string
	shouldError map[string]error
}

// NewMockClient creates a new mock client for testing.
func NewMockClient() *MockClientInterface {
	return &MockClientInterface{
		files:       make(map[string][]byte),
		modes:       make(map[string]os.FileMode),
		owners:      make(map[string]string),
		groups:      make(map[string]string),
		shouldError: make(map[string]error),
	}
}

func (m *MockClientInterface) SetFile(path string, content []byte, mode os.FileMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = content
	m.modes[path] = mode
}

func (m *MockClientInterface) SetError(op string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldError[op] = err
}

func (m *MockClientInterface) Close() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.shouldError["Close"]; ok {
		return err
	}
	return nil
}

func (m *MockClientInterface) UploadFile(_ context.Context, localPath, remotePath string) error {
	m.mu.RLock()
	err, ok := m.shouldError["UploadFile"]
	m.mu.RUnlock()
	if ok {
		return err
	}

	content, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = content
	m.modes[remotePath] = 0644
	return nil
}

func (m *MockClientInterface) GetFileHash(_ context.Context, remotePath string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.shouldError["GetFileHash"]; ok {
		return "", err
	}

	content, exists := m.files[remotePath]
	if !exists {
		return "", os.ErrNotExist
	}

	return hashContent(content), nil
}

func (m *MockClientInterface) SetFileAttributes(_ context.Context, remotePath, owner, group, mode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.shouldError["SetFileAttributes"]; ok {
		return err
	}

	if _, exists := m.files[remotePath]; !exists {
		return os.ErrNotExist
	}

	if owner != "" {
		m.owners[remotePath] = owner
	}
	if group != "" {
		m.groups[remotePath] = group
	}
	if mode != "" {
		modeInt, err := parseOctal(mode)
		if err != nil {
			return err
		}
		m.modes[remotePath] = os.FileMode(modeInt)
	}

	return nil
}

func (m *MockClientInterface) DeleteFile(_ context.Context, remotePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.shouldError["DeleteFile"]; ok {
		return err
	}

	if _, exists := m.files[remotePath]; !exists {
		return nil // Already deleted
	}

	delete(m.files, remotePath)
	delete(m.modes, remotePath)
	delete(m.owners, remotePath)
	delete(m.groups, remotePath)
	return nil
}

func (m *MockClientInterface) FileExists(_ context.Context, remotePath string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.shouldError["FileExists"]; ok {
		return false, err
	}

	_, exists := m.files[remotePath]
	return exists, nil
}

func (m *MockClientInterface) GetFileInfo(_ context.Context, remotePath string) (os.FileInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.shouldError["GetFileInfo"]; ok {
		return nil, err
	}

	content, exists := m.files[remotePath]
	if !exists {
		return nil, os.ErrNotExist
	}

	mode := m.modes[remotePath]
	if mode == 0 {
		mode = 0644
	}

	return &mockFileInfo{
		name:    remotePath,
		size:    int64(len(content)),
		mode:    mode,
		modTime: time.Now(),
		isDir:   false,
	}, nil
}

func (m *MockClientInterface) ReadFileContent(_ context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err, ok := m.shouldError["ReadFileContent"]; ok {
		return nil, err
	}

	content, exists := m.files[remotePath]
	if !exists {
		return nil, os.ErrNotExist
	}

	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return content[:maxBytes], nil
	}

	return content, nil
}

// Helper functions.
func hashContent(content []byte) string {
	// Simplified hash for testing.
	return "sha256:mock_hash_" + string(content[:min(10, len(content))])
}

func parseOctal(s string) (uint64, error) {
	var val uint64
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, fs.ErrInvalid
		}
		val = val*8 + uint64(c-'0')
	}
	return val, nil
}

// Verify MockClientInterface implements ClientInterface.
var _ ClientInterface = (*MockClientInterface)(nil)

// MockSFTPFile implements SFTPFile for testing.
type MockSFTPFile struct {
	content    []byte
	readOffset int
	closed     bool
}

// NewMockSFTPFile creates a new mock SFTP file with the given content.
func NewMockSFTPFile(content []byte) *MockSFTPFile {
	return &MockSFTPFile{content: content}
}

func (f *MockSFTPFile) Read(p []byte) (n int, err error) {
	if f.readOffset >= len(f.content) {
		return 0, io.EOF
	}
	n = copy(p, f.content[f.readOffset:])
	f.readOffset += n
	return n, nil
}

func (f *MockSFTPFile) Write(p []byte) (n int, err error) {
	f.content = append(f.content, p...)
	return len(p), nil
}

func (f *MockSFTPFile) Close() error {
	f.closed = true
	return nil
}

// MockSFTPFileData holds file metadata for the mock SFTP client.
type MockSFTPFileData struct {
	content []byte
	mode    os.FileMode
}

// MockSFTPClient implements SFTPClientInterface for testing.
type MockSFTPClient struct {
	files  map[string]*MockSFTPFileData
	errors map[string]error
	closed bool
}

// NewMockSFTPClient creates a new mock SFTP client.
func NewMockSFTPClient() *MockSFTPClient {
	return &MockSFTPClient{
		files:  make(map[string]*MockSFTPFileData),
		errors: make(map[string]error),
	}
}

// Ensure MockSFTPClient implements SFTPClientInterface.
var _ SFTPClientInterface = (*MockSFTPClient)(nil)

// SetError sets an error to be returned for a specific method.
func (m *MockSFTPClient) SetError(method string, err error) {
	m.errors[method] = err
}

// SetFile sets a file in the mock SFTP client.
func (m *MockSFTPClient) SetFile(path string, content []byte, mode os.FileMode) {
	m.files[path] = &MockSFTPFileData{content: content, mode: mode}
}

func (m *MockSFTPClient) Open(path string) (SFTPFile, error) {
	if err := m.errors["Open"]; err != nil {
		return nil, err
	}
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return NewMockSFTPFile(data.content), nil
}

func (m *MockSFTPClient) Create(path string) (SFTPFile, error) {
	if err := m.errors["Create"]; err != nil {
		return nil, err
	}
	m.files[path] = &MockSFTPFileData{content: []byte{}, mode: 0644}
	return NewMockSFTPFile(nil), nil
}

func (m *MockSFTPClient) Remove(path string) error {
	if err := m.errors["Remove"]; err != nil {
		return err
	}
	if _, ok := m.files[path]; !ok {
		return os.ErrNotExist
	}
	delete(m.files, path)
	return nil
}

func (m *MockSFTPClient) Stat(path string) (os.FileInfo, error) {
	if err := m.errors["Stat"]; err != nil {
		return nil, err
	}
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return &mockFileInfo{
		name:    filepath.Base(path),
		size:    int64(len(data.content)),
		mode:    data.mode,
		modTime: time.Now(),
		isDir:   false,
	}, nil
}

func (m *MockSFTPClient) Chmod(path string, mode os.FileMode) error {
	if err := m.errors["Chmod"]; err != nil {
		return err
	}
	data, ok := m.files[path]
	if !ok {
		return os.ErrNotExist
	}
	data.mode = mode
	return nil
}

func (m *MockSFTPClient) MkdirAll(path string) error {
	if err := m.errors["MkdirAll"]; err != nil {
		return err
	}
	return nil
}

func (m *MockSFTPClient) Close() error {
	if err := m.errors["Close"]; err != nil {
		return err
	}
	m.closed = true
	return nil
}

// MockSFTPFileForSyncer wraps MockClientInterface for use in syncer tests.
type MockSFTPFileForSyncer struct {
	content []byte
	path    string
	mock    *MockClientInterface
	written []byte
}

func (f *MockSFTPFileForSyncer) Read(p []byte) (int, error) {
	if len(f.content) == 0 {
		return 0, os.ErrNotExist
	}
	n := copy(p, f.content)
	f.content = f.content[n:]
	return n, nil
}

func (f *MockSFTPFileForSyncer) Write(p []byte) (int, error) {
	f.written = append(f.written, p...)
	if f.mock != nil && f.path != "" {
		f.mock.mu.Lock()
		f.mock.files[f.path] = f.written
		f.mock.mu.Unlock()
	}
	return len(p), nil
}

func (f *MockSFTPFileForSyncer) Close() error {
	return nil
}

// MockSFTPClientForSyncer implements SFTPClientInterface for syncer tests.
type MockSFTPClientForSyncer struct {
	mock      *MockClientInterface
	createErr error
	mkdirErr  error
}

func (m *MockSFTPClientForSyncer) Open(path string) (SFTPFile, error) {
	content, exists := m.mock.files[path]
	if !exists {
		return nil, os.ErrNotExist
	}
	return &MockSFTPFileForSyncer{content: content}, nil
}

func (m *MockSFTPClientForSyncer) Create(path string) (SFTPFile, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	return &MockSFTPFileForSyncer{path: path, mock: m.mock}, nil
}

func (m *MockSFTPClientForSyncer) Remove(path string) error {
	delete(m.mock.files, path)
	return nil
}

func (m *MockSFTPClientForSyncer) Stat(path string) (os.FileInfo, error) {
	content, exists := m.mock.files[path]
	if !exists {
		return nil, os.ErrNotExist
	}
	return &mockFileInfo{name: path, size: int64(len(content))}, nil
}

func (m *MockSFTPClientForSyncer) Chmod(path string, mode os.FileMode) error {
	m.mock.modes[path] = mode
	return nil
}

func (m *MockSFTPClientForSyncer) MkdirAll(_ string) error {
	if m.mkdirErr != nil {
		return m.mkdirErr
	}
	return nil
}

func (m *MockSFTPClientForSyncer) Close() error {
	return nil
}
