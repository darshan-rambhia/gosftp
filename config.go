package gosftp

import "time"

// AuthMethod represents the SSH authentication method to use.
type AuthMethod string

const (
	// AuthMethodPrivateKey uses SSH private key authentication (default).
	AuthMethodPrivateKey AuthMethod = "private_key"
	// AuthMethodPassword uses password authentication.
	AuthMethodPassword AuthMethod = "password"
	// AuthMethodCertificate uses SSH certificate authentication.
	AuthMethodCertificate AuthMethod = "certificate"
)

// Config holds SSH connection configuration.
type Config struct {
	// Host is the target SSH server hostname or IP address.
	Host string

	// Port is the SSH port (default 22).
	Port int

	// User is the SSH username.
	User string

	// AuthMethod specifies which authentication method to use.
	// If not set, it will be inferred from the provided credentials.
	AuthMethod AuthMethod

	// PrivateKey is the SSH private key content (PEM encoded).
	// Mutually exclusive with KeyPath.
	PrivateKey string

	// KeyPath is the path to the SSH private key file.
	// Mutually exclusive with PrivateKey.
	KeyPath string

	// Password is the SSH password for password authentication.
	Password string

	// Certificate is the SSH certificate content.
	// Used with PrivateKey or KeyPath for certificate authentication.
	Certificate string

	// CertificatePath is the path to the SSH certificate file.
	// Used with PrivateKey or KeyPath for certificate authentication.
	CertificatePath string

	// Timeout is the connection timeout (default 30s).
	Timeout time.Duration

	// KnownHostsFile is the path to a known_hosts file for host key verification.
	// If not set, defaults to ~/.ssh/known_hosts if it exists.
	KnownHostsFile string

	// InsecureIgnoreHostKey skips host key verification.
	// WARNING: This is insecure and should only be used for testing.
	InsecureIgnoreHostKey bool

	// BastionHost is the hostname or IP of a bastion/jump host.
	BastionHost string

	// BastionPort is the SSH port of the bastion host (default 22).
	BastionPort int

	// BastionUser is the SSH username for the bastion host.
	// Falls back to User if not set.
	BastionUser string

	// BastionKey is the private key content for the bastion host.
	// Falls back to PrivateKey if not set.
	BastionKey string

	// BastionKeyPath is the path to the private key for the bastion host.
	// Falls back to KeyPath if not set.
	BastionKeyPath string

	// BastionPassword is the password for the bastion host.
	BastionPassword string

	// AgentForwarding enables SSH agent forwarding.
	AgentForwarding bool
}

// WithDefaults returns a copy of the config with default values applied.
func (c Config) WithDefaults() Config {
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.BastionPort == 0 && c.BastionHost != "" {
		c.BastionPort = 22
	}
	return c
}

// FileAttributes represents file ownership and permissions.
type FileAttributes struct {
	// Owner is the file owner (username or UID).
	Owner string

	// Group is the file group (group name or GID).
	Group string

	// Mode is the file permissions in octal (e.g., "0644").
	Mode string
}

// SyncOptions configures sync behavior.
type SyncOptions struct {
	// Attributes specifies file ownership and permissions to set.
	Attributes *FileAttributes

	// ExcludePatterns is a list of glob patterns to exclude from sync.
	// Example: []string{"*.tmp", ".git", "node_modules"}
	ExcludePatterns []string

	// SymlinkPolicy specifies how to handle symlinks: "follow", "skip", or "preserve".
	// Default is "follow".
	SymlinkPolicy string

	// Parallelism is the number of concurrent uploads for directory sync.
	// Default is 4.
	Parallelism int

	// DryRun only reports what would be synced without making changes.
	DryRun bool
}

// WithDefaults returns a copy of the options with default values applied.
func (o SyncOptions) WithDefaults() SyncOptions {
	if o.SymlinkPolicy == "" {
		o.SymlinkPolicy = "follow"
	}
	if o.Parallelism == 0 {
		o.Parallelism = 4
	}
	return o
}

// SyncResult represents the result of a sync operation.
type SyncResult struct {
	// LocalPath is the source file path.
	LocalPath string

	// RemotePath is the destination file path.
	RemotePath string

	// Hash is the SHA256 hash of the file content.
	Hash string

	// Size is the file size in bytes.
	Size int64

	// Changed indicates if the file was uploaded (true) or unchanged (false).
	Changed bool

	// Deleted indicates if the file was deleted from the remote.
	Deleted bool

	// Error contains any error that occurred during sync.
	Error error
}

// DirectorySyncResult represents the result of a directory sync operation.
type DirectorySyncResult struct {
	// Files contains the result for each file.
	Files []SyncResult

	// TotalSize is the total size of all synced files.
	TotalSize int64

	// CombinedHash is a combined hash of all file hashes.
	CombinedHash string

	// Uploaded is the number of files uploaded.
	Uploaded int

	// Skipped is the number of files skipped (unchanged).
	Skipped int

	// Deleted is the number of files deleted.
	Deleted int

	// Errors is the number of files that failed.
	Errors int
}
