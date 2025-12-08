package gosftp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ClientInterface defines the interface for SSH/SFTP operations.
// This allows for mocking in tests.
type ClientInterface interface {
	// Close closes the SSH connection.
	Close() error
	// UploadFile uploads a local file to the remote host.
	UploadFile(ctx context.Context, localPath, remotePath string) error
	// GetFileHash returns the SHA256 hash of a remote file.
	GetFileHash(ctx context.Context, remotePath string) (string, error)
	// SetFileAttributes sets ownership and permissions on a remote file.
	SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error
	// DeleteFile removes a file from the remote host.
	DeleteFile(ctx context.Context, remotePath string) error
	// FileExists checks if a file exists on the remote host.
	FileExists(ctx context.Context, remotePath string) (bool, error)
	// GetFileInfo returns information about a remote file.
	GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error)
	// ReadFileContent reads the content of a remote file.
	ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error)
}

// Client wraps SSH and SFTP connections for file operations.
type Client struct {
	sshClient     *ssh.Client
	sftpClient    SFTPClientInterface
	bastionClient *ssh.Client // nil if no bastion host
}

// Ensure Client implements ClientInterface.
var _ ClientInterface = (*Client)(nil)

// SFTPClientInterface abstracts SFTP operations for testing.
type SFTPClientInterface interface {
	Open(path string) (SFTPFile, error)
	Create(path string) (SFTPFile, error)
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
	MkdirAll(path string) error
	Close() error
}

// SFTPFile abstracts file operations for testing.
type SFTPFile interface {
	io.Reader
	io.Writer
	io.Closer
}

// SFTPClientWrapper wraps the real sftp.Client to implement SFTPClientInterface.
type SFTPClientWrapper struct {
	client *sftp.Client
}

var _ SFTPClientInterface = (*SFTPClientWrapper)(nil)

func (w *SFTPClientWrapper) Open(path string) (SFTPFile, error)         { return w.client.Open(path) }
func (w *SFTPClientWrapper) Create(path string) (SFTPFile, error)       { return w.client.Create(path) }
func (w *SFTPClientWrapper) Remove(path string) error                   { return w.client.Remove(path) }
func (w *SFTPClientWrapper) Stat(path string) (os.FileInfo, error)      { return w.client.Stat(path) }
func (w *SFTPClientWrapper) Chmod(path string, mode os.FileMode) error  { return w.client.Chmod(path, mode) }
func (w *SFTPClientWrapper) MkdirAll(path string) error                 { return w.client.MkdirAll(path) }
func (w *SFTPClientWrapper) Close() error                               { return w.client.Close() }

// NewClient creates a new SSH/SFTP client.
func NewClient(config Config) (*Client, error) {
	config = config.WithDefaults()

	authMethods, err := buildAuthMethods(config)
	if err != nil {
		return nil, err
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method configured")
	}

	hostKeyCallback, err := buildHostKeyCallback(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure host key verification: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         config.Timeout,
	}

	var sshClient *ssh.Client
	var bastionClient *ssh.Client

	targetAddr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	if config.BastionHost != "" {
		bastionClient, err = connectToBastion(config)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to bastion host: %w", err)
		}

		conn, err := bastionClient.Dial("tcp", targetAddr)
		if err != nil {
			bastionClient.Close()
			return nil, fmt.Errorf("failed to dial target through bastion: %w", err)
		}

		ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
		if err != nil {
			conn.Close()
			bastionClient.Close()
			return nil, fmt.Errorf("failed to create SSH connection through bastion: %w", err)
		}

		sshClient = ssh.NewClient(ncc, chans, reqs)
	} else {
		sshClient, err = ssh.Dial("tcp", targetAddr, sshConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
		}
	}

	rawSftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		if bastionClient != nil {
			bastionClient.Close()
		}
		return nil, fmt.Errorf("failed to create SFTP client: %w", err)
	}

	return &Client{
		sshClient:     sshClient,
		sftpClient:    &SFTPClientWrapper{client: rawSftpClient},
		bastionClient: bastionClient,
	}, nil
}

// NewClientWithSFTP creates a Client with a custom SFTP client implementation.
// This is primarily used for testing with mock SFTP clients.
func NewClientWithSFTP(sftpClient SFTPClientInterface, sshClient *ssh.Client) *Client {
	return &Client{
		sshClient:  sshClient,
		sftpClient: sftpClient,
	}
}

// Close closes SFTP, SSH, and bastion connections.
func (c *Client) Close() error {
	if c.sftpClient != nil {
		c.sftpClient.Close()
	}
	if c.sshClient != nil {
		c.sshClient.Close()
	}
	if c.bastionClient != nil {
		c.bastionClient.Close()
	}
	return nil
}

// UploadFile uploads a local file to the remote host.
func (c *Client) UploadFile(ctx context.Context, localPath, remotePath string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("operation cancelled: %w", err)
	}

	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	remoteDir := filepath.Dir(remotePath)
	if remoteDir != "" && remoteDir != "/" && remoteDir != "." {
		if err := c.sftpClient.MkdirAll(remoteDir); err != nil {
			return fmt.Errorf("failed to create remote directory %s: %w", remoteDir, err)
		}
	}

	remoteFile, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(remoteFile, localFile)
		if err != nil {
			done <- fmt.Errorf("failed to copy file content: %w", err)
			return
		}
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("upload cancelled: %w", ctx.Err())
	case err := <-done:
		return err
	}
}

// GetFileHash returns the SHA256 hash of a remote file.
func (c *Client) GetFileHash(ctx context.Context, remotePath string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("operation cancelled: %w", err)
	}

	file, err := c.sftpClient.Open(remotePath)
	if err != nil {
		return "", fmt.Errorf("failed to open remote file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(h, file)
		done <- err
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("hash computation cancelled: %w", ctx.Err())
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("failed to read remote file: %w", err)
		}
		return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
	}
}

// validOwnerGroupPattern matches valid Unix user/group names.
var validOwnerGroupPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$|^[0-9]+$`)

// validModePattern matches valid Unix file permission modes.
var validModePattern = regexp.MustCompile(`^[0-7]{3,4}$`)

// SetFileAttributes sets ownership and permissions on a remote file.
func (c *Client) SetFileAttributes(ctx context.Context, remotePath, owner, group, mode string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("operation cancelled: %w", err)
	}

	// Validate inputs.
	if err := validateOwnerGroup(owner, "owner"); err != nil {
		return err
	}
	if err := validateOwnerGroup(group, "group"); err != nil {
		return err
	}
	if err := ValidateMode(mode); err != nil {
		return err
	}

	// Set permissions via SFTP.
	if mode != "" {
		modeInt, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid mode %s: %w", mode, err)
		}
		if err := c.sftpClient.Chmod(remotePath, os.FileMode(modeInt)); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	// Set ownership via SSH command.
	if owner != "" || group != "" {
		var ownership string
		if owner != "" && group != "" {
			ownership = owner + ":" + group
		} else if owner != "" {
			ownership = owner
		} else {
			ownership = ":" + group
		}

		session, err := c.sshClient.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create SSH session: %w", err)
		}
		defer session.Close()

		cmd := fmt.Sprintf("chown %s %s", ownership, shellQuote(remotePath))

		done := make(chan error, 1)
		go func() {
			done <- session.Run(cmd)
		}()

		select {
		case <-ctx.Done():
			return fmt.Errorf("set attributes cancelled: %w", ctx.Err())
		case err := <-done:
			if err != nil {
				return fmt.Errorf("failed to set ownership: %w", err)
			}
		}
	}

	return nil
}

// DeleteFile removes a file from the remote host.
func (c *Client) DeleteFile(ctx context.Context, remotePath string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("operation cancelled: %w", err)
	}

	err := c.sftpClient.Remove(remotePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to delete remote file: %w", err)
	}
	return nil
}

// FileExists checks if a file exists on the remote host.
func (c *Client) FileExists(ctx context.Context, remotePath string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("operation cancelled: %w", err)
	}

	_, err := c.sftpClient.Stat(remotePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetFileInfo returns information about a remote file.
func (c *Client) GetFileInfo(ctx context.Context, remotePath string) (os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	return c.sftpClient.Stat(remotePath)
}

// ReadFileContent reads the content of a remote file.
func (c *Client) ReadFileContent(ctx context.Context, remotePath string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation cancelled: %w", err)
	}

	file, err := c.sftpClient.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open remote file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	if maxBytes > 0 {
		reader = io.LimitReader(file, maxBytes)
	}

	done := make(chan struct {
		content []byte
		err     error
	}, 1)
	go func() {
		content, err := io.ReadAll(reader)
		done <- struct {
			content []byte
			err     error
		}{content, err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("read cancelled: %w", ctx.Err())
	case result := <-done:
		if result.err != nil {
			return nil, fmt.Errorf("failed to read remote file: %w", result.err)
		}
		return result.content, nil
	}
}

// Helper functions

func connectToBastion(config Config) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if config.BastionPassword != "" {
		authMethods = append(authMethods, ssh.Password(config.BastionPassword))
	} else {
		var keyData []byte
		var err error

		if config.BastionKey != "" {
			keyData = []byte(config.BastionKey)
		} else if config.BastionKeyPath != "" {
			keyData, err = os.ReadFile(config.BastionKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read bastion key file: %w", err)
			}
		} else if config.PrivateKey != "" {
			keyData = []byte(config.PrivateKey)
		} else if config.KeyPath != "" {
			keyData, err = os.ReadFile(config.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read key file for bastion: %w", err)
			}
		} else {
			return nil, fmt.Errorf("no SSH key configured for bastion host")
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bastion SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	bastionUser := config.BastionUser
	if bastionUser == "" {
		bastionUser = config.User
	}

	hostKeyCallback, err := buildHostKeyCallback(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure host key verification for bastion: %w", err)
	}

	bastionConfig := &ssh.ClientConfig{
		User:            bastionUser,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         config.Timeout,
	}

	bastionAddr := fmt.Sprintf("%s:%d", config.BastionHost, config.BastionPort)
	return ssh.Dial("tcp", bastionAddr, bastionConfig)
}

func buildHostKeyCallback(config Config) (ssh.HostKeyCallback, error) {
	if config.InsecureIgnoreHostKey {
		log.Printf("[WARN] SSH host key verification disabled for %s:%d - this is insecure!", config.Host, config.Port)
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if config.KnownHostsFile != "" {
		expandedPath := ExpandPath(config.KnownHostsFile)
		callback, err := knownhosts.New(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts file %s: %w", expandedPath, err)
		}
		return callback, nil
	}

	homeDir, err := os.UserHomeDir()
	if err == nil {
		defaultKnownHosts := filepath.Join(homeDir, ".ssh", "known_hosts")
		if _, err := os.Stat(defaultKnownHosts); err == nil {
			callback, err := knownhosts.New(defaultKnownHosts)
			if err == nil {
				return callback, nil
			}
			log.Printf("[WARN] Could not parse known_hosts file %s: %v", defaultKnownHosts, err)
		}
	}

	log.Printf("[WARN] No known_hosts file found for %s:%d - host key verification disabled.", config.Host, config.Port)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}, nil
}

func buildAuthMethods(config Config) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	authMethod := config.AuthMethod
	if authMethod == "" {
		authMethod = inferAuthMethod(config)
	}

	switch authMethod {
	case AuthMethodPassword:
		if config.Password == "" {
			return nil, fmt.Errorf("password authentication requires password to be set")
		}
		authMethods = append(authMethods, ssh.Password(config.Password))

	case AuthMethodCertificate:
		certAuth, err := buildCertificateAuth(config)
		if err != nil {
			return nil, fmt.Errorf("certificate authentication failed: %w", err)
		}
		authMethods = append(authMethods, certAuth)

	case AuthMethodPrivateKey, "":
		keyAuth, err := buildPrivateKeyAuth(config)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, keyAuth)
	}

	return authMethods, nil
}

func inferAuthMethod(config Config) AuthMethod {
	if config.Password != "" {
		return AuthMethodPassword
	}
	if config.Certificate != "" || config.CertificatePath != "" {
		return AuthMethodCertificate
	}
	return AuthMethodPrivateKey
}

func buildPrivateKeyAuth(config Config) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = os.ReadFile(config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no SSH private key provided (set private_key or key_path)")
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

func buildCertificateAuth(config Config) (ssh.AuthMethod, error) {
	var keyData []byte
	var err error

	if config.PrivateKey != "" {
		keyData = []byte(config.PrivateKey)
	} else if config.KeyPath != "" {
		keyData, err = os.ReadFile(config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("certificate auth requires private key")
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	var certData []byte
	if config.Certificate != "" {
		certData = []byte(config.Certificate)
	} else if config.CertificatePath != "" {
		certData, err = os.ReadFile(config.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("certificate auth requires certificate")
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("provided file is not an SSH certificate")
	}

	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %w", err)
	}

	return ssh.PublicKeys(certSigner), nil
}

func validateOwnerGroup(name, fieldName string) error {
	if name == "" {
		return nil
	}
	if len(name) > 32 {
		return fmt.Errorf("%s name too long (max 32 characters): %s", fieldName, name)
	}
	if !validOwnerGroupPattern.MatchString(name) {
		return fmt.Errorf("invalid %s name: %s", fieldName, name)
	}
	return nil
}

// ValidateMode checks if a file mode string is valid.
func ValidateMode(mode string) error {
	if mode == "" {
		return nil
	}
	if !validModePattern.MatchString(mode) {
		return fmt.Errorf("invalid mode %q: must be 3-4 octal digits", mode)
	}
	return nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	escaped := strings.ReplaceAll(s, "'", "'\"'\"'")
	return "'" + escaped + "'"
}

// ExpandPath expands ~ to home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, path[2:])
		}
	}
	return path
}

// IsBinaryContent checks if content appears to be binary.
func IsBinaryContent(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}
