# gosftp

A Go library for synchronizing files over SSH/SFTP with connection pooling, retry logic, and bastion host support.

[![CI](https://github.com/darshan-rambhia/gosftp/actions/workflows/ci.yml/badge.svg)](https://github.com/darshan-rambhia/gosftp/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8?logo=go)](https://go.dev/)
[![codecov](https://codecov.io/gh/darshan-rambhia/gosftp/graph/badge.svg)](https://codecov.io/gh/darshan-rambhia/gosftp)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Features

- SSH client with SFTP support for file operations
- Connection pooling for efficient connection reuse
- Retry logic with exponential backoff for transient failures
- Support for various authentication methods (private key, password, certificate)
- Bastion/jump host support for multi-hop SSH connections
- High-level sync API for file and directory synchronization

## Installation

```bash
go get github.com/darshan-rambhia/gosftp
```

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/darshan-rambhia/gosftp"
)

func main() {
    config := gosftp.Config{
        Host:    "example.com",
        Port:    22,
        User:    "deploy",
        KeyPath: "~/.ssh/id_ed25519",
    }

    client, err := gosftp.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()
    err = client.UploadFile(ctx, "/local/path/file.txt", "/remote/path/file.txt")
    if err != nil {
        log.Fatal(err)
    }
}
```

### Connection Pooling

For multiple operations to the same host, use connection pooling:

```go
pool := gosftp.NewConnectionPool(5 * time.Minute)
defer pool.Close()

client, err := pool.GetOrCreate(config)
if err != nil {
    log.Fatal(err)
}
defer pool.Release(config)

// Use client...
```

### High-Level Sync API

For common sync operations, use the Syncer API:

```go
syncer, err := gosftp.NewSyncer(config)
if err != nil {
    log.Fatal(err)
}
defer syncer.Close()

// Sync a single file
result, err := syncer.SyncFile(ctx, "/local/file.txt", "/remote/file.txt", nil)

// Sync a directory
results, err := syncer.SyncDirectory(ctx, "/local/dir", "/remote/dir", nil)
```

### Authentication Methods

#### Private Key (from file)
```go
config := gosftp.Config{
    Host:    "example.com",
    Port:    22,
    User:    "deploy",
    KeyPath: "~/.ssh/id_ed25519",
}
```

#### Private Key (inline)
```go
config := gosftp.Config{
    Host:       "example.com",
    Port:       22,
    User:       "deploy",
    PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
}
```

#### Password
```go
config := gosftp.Config{
    Host:       "example.com",
    Port:       22,
    User:       "deploy",
    Password:   "secret",
    AuthMethod: gosftp.AuthMethodPassword,
}
```

#### Bastion/Jump Host
```go
config := gosftp.Config{
    Host:           "internal-server",
    Port:           22,
    User:           "deploy",
    KeyPath:        "~/.ssh/id_ed25519",
    BastionHost:    "bastion.example.com",
    BastionPort:    22,
    BastionUser:    "jump",
    BastionKeyPath: "~/.ssh/bastion_key",
}
```

## Testing

```bash
# Run unit tests
go test -short ./...

# Run benchmarks (requires Docker)
go test -bench=. -benchmem ./...

# Run fuzz tests
go test -fuzz=FuzzExpandPath -fuzztime=30s ./...
```

## License

MIT License - see [LICENSE](LICENSE) for details.
