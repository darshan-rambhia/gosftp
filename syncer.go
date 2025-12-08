package gosftp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Syncer provides a high-level API for file synchronization operations.
type Syncer struct {
	client      *Client
	config      Config
	retryConfig RetryConfig
	pool        *ConnectionPool
	usePool     bool
}

// SyncerOption configures a Syncer.
type SyncerOption func(*Syncer)

// WithRetryConfig sets the retry configuration.
func WithRetryConfig(config RetryConfig) SyncerOption {
	return func(s *Syncer) {
		s.retryConfig = config
	}
}

// WithConnectionPool enables connection pooling.
func WithConnectionPool(pool *ConnectionPool) SyncerOption {
	return func(s *Syncer) {
		s.pool = pool
		s.usePool = true
	}
}

// NewSyncer creates a new Syncer with the given configuration.
func NewSyncer(config Config, opts ...SyncerOption) (*Syncer, error) {
	retryConfig := DefaultRetryConfig()
	retryConfig.Logger = config.Logger
	s := &Syncer{
		config:      config,
		retryConfig: retryConfig,
	}

	for _, opt := range opts {
		opt(s)
	}

	var err error
	if s.usePool && s.pool != nil {
		s.client, err = s.pool.GetOrCreate(config)
	} else {
		s.client, err = NewClient(config)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %w", err)
	}

	return s, nil
}

// Close closes the syncer and releases resources.
func (s *Syncer) Close() error {
	if s.usePool && s.pool != nil {
		s.pool.Release(s.config)
		return nil
	}
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// Client returns the underlying SSH client.
func (s *Syncer) Client() *Client {
	return s.client
}

// SyncFile synchronizes a single file to the remote host.
func (s *Syncer) SyncFile(ctx context.Context, localPath, remotePath string, opts *SyncOptions) (*SyncResult, error) {
	if opts == nil {
		opts = &SyncOptions{}
	}
	*opts = opts.WithDefaults()

	result := &SyncResult{
		LocalPath:  localPath,
		RemotePath: remotePath,
	}

	// Compute local file hash.
	hash, size, err := HashFile(localPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to hash local file: %w", err)
		return result, result.Error
	}
	result.Hash = hash
	result.Size = size

	if opts.DryRun {
		result.Changed = true
		return result, nil
	}

	// Upload with retry.
	err = Retry(ctx, s.retryConfig, "upload file", func() error {
		return s.client.UploadFile(ctx, localPath, remotePath)
	})
	if err != nil {
		result.Error = err
		return result, err
	}

	// Set attributes if specified.
	if opts.Attributes != nil {
		err = Retry(ctx, s.retryConfig, "set file attributes", func() error {
			return s.client.SetFileAttributes(
				ctx,
				remotePath,
				opts.Attributes.Owner,
				opts.Attributes.Group,
				opts.Attributes.Mode,
			)
		})
		if err != nil {
			result.Error = err
			return result, err
		}
	}

	result.Changed = true
	return result, nil
}

// SyncDirectory synchronizes a directory to the remote host.
func (s *Syncer) SyncDirectory(ctx context.Context, localDir, remoteDir string, opts *SyncOptions) (*DirectorySyncResult, error) {
	if opts == nil {
		opts = &SyncOptions{}
	}
	*opts = opts.WithDefaults()

	result := &DirectorySyncResult{}

	// Scan local directory.
	files, err := ScanDirectory(localDir, opts.ExcludePatterns, opts.SymlinkPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to scan directory: %w", err)
	}

	if opts.DryRun {
		for _, f := range files {
			result.Files = append(result.Files, SyncResult{
				LocalPath:  filepath.Join(localDir, f.RelPath),
				RemotePath: filepath.Join(remoteDir, f.RelPath),
				Hash:       f.Hash,
				Size:       f.Size,
				Changed:    true,
			})
			result.TotalSize += f.Size
		}
		result.Uploaded = len(files)
		result.CombinedHash = ComputeCombinedHash(files)
		return result, nil
	}

	// Prepare jobs.
	type uploadJob struct {
		file       FileInfo
		localPath  string
		remotePath string
	}

	jobs := make([]uploadJob, 0, len(files))
	for _, file := range files {
		jobs = append(jobs, uploadJob{
			file:       file,
			localPath:  filepath.Join(localDir, file.RelPath),
			remotePath: filepath.Join(remoteDir, file.RelPath),
		})
	}

	// Upload in parallel.
	parallelism := opts.Parallelism
	if parallelism > len(jobs) {
		parallelism = len(jobs)
	}
	if parallelism < 1 {
		parallelism = 1
	}

	jobChan := make(chan uploadJob, len(jobs))
	resultChan := make(chan SyncResult, len(jobs))

	var wg sync.WaitGroup
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				syncResult := SyncResult{
					LocalPath:  job.localPath,
					RemotePath: job.remotePath,
					Hash:       job.file.Hash,
					Size:       job.file.Size,
				}

				if ctx.Err() != nil {
					syncResult.Error = ctx.Err()
					resultChan <- syncResult
					continue
				}

				err := Retry(ctx, s.retryConfig, "upload file", func() error {
					return s.client.UploadFile(ctx, job.localPath, job.remotePath)
				})
				if err != nil {
					syncResult.Error = err
					resultChan <- syncResult
					continue
				}

				if opts.Attributes != nil {
					err = Retry(ctx, s.retryConfig, "set attributes", func() error {
						return s.client.SetFileAttributes(
							ctx,
							job.remotePath,
							opts.Attributes.Owner,
							opts.Attributes.Group,
							opts.Attributes.Mode,
						)
					})
					if err != nil {
						syncResult.Error = err
						resultChan <- syncResult
						continue
					}
				}

				syncResult.Changed = true
				resultChan <- syncResult
			}
		}()
	}

	// Send jobs.
	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	// Wait and close results.
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results.
	for r := range resultChan {
		result.Files = append(result.Files, r)
		if r.Error != nil {
			result.Errors++
		} else if r.Changed {
			result.Uploaded++
			result.TotalSize += r.Size
		} else {
			result.Skipped++
		}
	}

	result.CombinedHash = ComputeCombinedHash(files)
	return result, nil
}

// DeleteFile deletes a file from the remote host.
func (s *Syncer) DeleteFile(ctx context.Context, remotePath string) error {
	return Retry(ctx, s.retryConfig, "delete file", func() error {
		return s.client.DeleteFile(ctx, remotePath)
	})
}

// FileInfo holds information about a file.
type FileInfo struct {
	RelPath       string
	Hash          string
	Size          int64
	IsSymlink     bool
	SymlinkTarget string
}

// ScanDirectory walks a directory and returns information about all files.
func ScanDirectory(root string, excludePatterns []string, symlinkPolicy string) ([]FileInfo, error) {
	if symlinkPolicy == "" {
		symlinkPolicy = "follow"
	}

	var files []FileInfo

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		if shouldExclude(relPath, excludePatterns) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed to get info for %s: %w", relPath, err)
		}

		isSymlink := info.Mode()&os.ModeSymlink != 0

		if isSymlink {
			switch symlinkPolicy {
			case "skip":
				return nil
			case "preserve":
				target, err := os.Readlink(path)
				if err != nil {
					return fmt.Errorf("failed to read symlink %s: %w", relPath, err)
				}
				files = append(files, FileInfo{
					RelPath:       relPath,
					Hash:          fmt.Sprintf("symlink:%s", target),
					Size:          0,
					IsSymlink:     true,
					SymlinkTarget: target,
				})
				return nil
			}
		}

		hash, size, err := HashFile(path)
		if err != nil {
			return fmt.Errorf("failed to hash %s: %w", relPath, err)
		}

		files = append(files, FileInfo{
			RelPath: relPath,
			Hash:    hash,
			Size:    size,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].RelPath < files[j].RelPath
	})

	return files, nil
}

func shouldExclude(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		parts := filepath.SplitList(path)
		for _, part := range parts {
			if matched, _ := filepath.Match(pattern, part); matched {
				return true
			}
		}
	}
	return false
}

// HashFile computes the SHA256 hash of a file.
func HashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), size, nil
}

// ComputeCombinedHash computes a combined hash from multiple file hashes.
func ComputeCombinedHash(files []FileInfo) string {
	h := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(h, file.RelPath)
		_, _ = io.WriteString(h, ":")
		_, _ = io.WriteString(h, file.Hash)
		_, _ = io.WriteString(h, "\n")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
