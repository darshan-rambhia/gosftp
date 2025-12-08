// Package gosftp provides a library for synchronizing files over SSH/SFTP.
//
// This package provides:
//   - SSH client with SFTP support for file operations
//   - Connection pooling for efficient connection reuse
//   - Retry logic with exponential backoff for transient failures
//   - Support for various authentication methods (private key, password, certificate)
//   - Bastion/jump host support for multi-hop SSH connections
//
// # Basic Usage
//
// Create a client and upload a file:
//
//	config := gosftp.Config{
//		Host:    "example.com",
//		Port:    22,
//		User:    "deploy",
//		KeyPath: "~/.ssh/id_ed25519",
//	}
//
//	client, err := gosftp.NewClient(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	err = client.UploadFile(ctx, "/local/path/file.txt", "/remote/path/file.txt")
//
// # Connection Pooling
//
// For multiple operations to the same host, use connection pooling:
//
//	pool := gosftp.NewConnectionPool(5 * time.Minute)
//	defer pool.Close()
//
//	client, err := pool.GetOrCreate(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer pool.Release(config)
//
//	// Use client...
//
// # High-Level API
//
// For common sync operations, use the Syncer API:
//
//	syncer, err := gosftp.NewSyncer(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer syncer.Close()
//
//	// Sync a single file
//	result, err := syncer.SyncFile(ctx, "/local/file.txt", "/remote/file.txt", nil)
//
//	// Sync a directory
//	results, err := syncer.SyncDirectory(ctx, "/local/dir", "/remote/dir", nil)
package gosftp
