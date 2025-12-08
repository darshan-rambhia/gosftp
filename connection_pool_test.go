package gosftp

import (
	"testing"
	"time"
)

func TestConnectionPool_ConnectionKey(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	tests := []struct {
		name    string
		config1 Config
		config2 Config
		same    bool
	}{
		{
			name: "same config same key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			same: true,
		},
		{
			name: "different host different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.101",
				Port: 22,
				User: "root",
			},
			same: false,
		},
		{
			name: "different port different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.100",
				Port: 2222,
				User: "root",
			},
			same: false,
		},
		{
			name: "different user different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "deploy",
			},
			same: false,
		},
		{
			name: "different auth different key",
			config1: Config{
				Host:     "192.168.1.100",
				Port:     22,
				User:     "root",
				Password: "secret1",
			},
			config2: Config{
				Host:     "192.168.1.100",
				Port:     22,
				User:     "root",
				Password: "secret2",
			},
			same: false,
		},
		{
			name: "with bastion different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host:        "192.168.1.100",
				Port:        22,
				User:        "root",
				BastionHost: "bastion.example.com",
			},
			same: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := pool.connectionKey(tt.config1)
			key2 := pool.connectionKey(tt.config2)

			if tt.same && key1 != key2 {
				t.Errorf("expected same key, got %s and %s", key1, key2)
			}
			if !tt.same && key1 == key2 {
				t.Errorf("expected different keys, got same: %s", key1)
			}
		})
	}
}

func TestConnectionPool_Stats(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	stats := pool.Stats()
	if stats.Total != 0 {
		t.Errorf("expected 0 total connections, got %d", stats.Total)
	}
	if stats.InUse != 0 {
		t.Errorf("expected 0 in-use connections, got %d", stats.InUse)
	}
	if stats.Idle != 0 {
		t.Errorf("expected 0 idle connections, got %d", stats.Idle)
	}
}

func TestConnectionPool_Release(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	config := Config{
		Host: "192.168.1.100",
		Port: 22,
		User: "root",
	}

	// Release without getting should not panic.
	pool.Release(config)

	// Release multiple times should not panic.
	pool.Release(config)
	pool.Release(config)
}

func TestConnectionPool_Close(t *testing.T) {
	pool := NewConnectionPool(time.Minute)

	// Close should work on empty pool.
	pool.Close()

	// Verify pool is empty.
	stats := pool.Stats()
	if stats.Total != 0 {
		t.Errorf("expected 0 connections after close, got %d", stats.Total)
	}
}

func TestConnectionPool_CloseIdle(t *testing.T) {
	pool := NewConnectionPool(time.Millisecond * 10)
	defer pool.Close()

	// CloseIdle on empty pool should not panic.
	pool.CloseIdle()
}

func TestNewConnectionPool(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	pool.Close()
}

func TestPoolStats(t *testing.T) {
	stats := PoolStats{
		Total: 10,
		InUse: 5,
		Idle:  5,
	}

	if stats.Total != 10 {
		t.Errorf("Total = %d, want 10", stats.Total)
	}
	if stats.InUse != 5 {
		t.Errorf("InUse = %d, want 5", stats.InUse)
	}
	if stats.Idle != 5 {
		t.Errorf("Idle = %d, want 5", stats.Idle)
	}
}

func TestConnectionPool_StatsWithConnections(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	// Manually add connections to test stats
	config1 := Config{Host: "host1", Port: 22, User: "user"}
	config2 := Config{Host: "host2", Port: 22, User: "user"}

	key1 := pool.connectionKey(config1)
	key2 := pool.connectionKey(config2)

	pool.mu.Lock()
	pool.connections[key1] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now(),
		inUse:    1, // in use
	}
	pool.connections[key2] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now(),
		inUse:    0, // idle
	}
	pool.mu.Unlock()

	stats := pool.Stats()
	if stats.Total != 2 {
		t.Errorf("expected 2 total connections, got %d", stats.Total)
	}
	if stats.InUse != 1 {
		t.Errorf("expected 1 in-use connection, got %d", stats.InUse)
	}
	if stats.Idle != 1 {
		t.Errorf("expected 1 idle connection, got %d", stats.Idle)
	}
}

func TestConnectionPool_ReleaseDecrementsInUse(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	config := Config{Host: "host1", Port: 22, User: "user"}
	key := pool.connectionKey(config)

	pool.mu.Lock()
	pool.connections[key] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now(),
		inUse:    2,
	}
	pool.mu.Unlock()

	pool.Release(config)

	pool.mu.RLock()
	pc := pool.connections[key]
	pool.mu.RUnlock()

	if pc.inUse != 1 {
		t.Errorf("expected inUse=1 after release, got %d", pc.inUse)
	}

	// Release again
	pool.Release(config)

	pool.mu.RLock()
	pc = pool.connections[key]
	pool.mu.RUnlock()

	if pc.inUse != 0 {
		t.Errorf("expected inUse=0 after second release, got %d", pc.inUse)
	}

	// Release when already 0 should stay at 0
	pool.Release(config)

	pool.mu.RLock()
	pc = pool.connections[key]
	pool.mu.RUnlock()

	if pc.inUse != 0 {
		t.Errorf("expected inUse=0 after third release, got %d", pc.inUse)
	}
}

func TestConnectionPool_CloseIdleRemovesOldConnections(t *testing.T) {
	pool := NewConnectionPool(time.Millisecond * 10)
	defer pool.Close()

	config := Config{Host: "host1", Port: 22, User: "user"}
	key := pool.connectionKey(config)

	// Add an old idle connection
	pool.mu.Lock()
	pool.connections[key] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now().Add(-time.Hour), // 1 hour ago
		inUse:    0,
	}
	pool.mu.Unlock()

	pool.CloseIdle()

	pool.mu.RLock()
	_, exists := pool.connections[key]
	pool.mu.RUnlock()

	if exists {
		t.Error("expected idle connection to be removed")
	}
}

func TestConnectionPool_CloseIdleKeepsInUseConnections(t *testing.T) {
	pool := NewConnectionPool(time.Millisecond * 10)
	defer pool.Close()

	config := Config{Host: "host1", Port: 22, User: "user"}
	key := pool.connectionKey(config)

	// Add an old connection that is in use
	pool.mu.Lock()
	pool.connections[key] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now().Add(-time.Hour), // 1 hour ago
		inUse:    1,                          // still in use
	}
	pool.mu.Unlock()

	pool.CloseIdle()

	pool.mu.RLock()
	_, exists := pool.connections[key]
	pool.mu.RUnlock()

	if !exists {
		t.Error("expected in-use connection to be kept")
	}
}

func TestConnectionPool_CloseRemovesAllConnections(t *testing.T) {
	pool := NewConnectionPool(time.Minute)

	config1 := Config{Host: "host1", Port: 22, User: "user"}
	config2 := Config{Host: "host2", Port: 22, User: "user"}

	key1 := pool.connectionKey(config1)
	key2 := pool.connectionKey(config2)

	pool.mu.Lock()
	pool.connections[key1] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now(),
		inUse:    1,
	}
	pool.connections[key2] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now(),
		inUse:    0,
	}
	pool.mu.Unlock()

	pool.Close()

	stats := pool.Stats()
	if stats.Total != 0 {
		t.Errorf("expected 0 connections after close, got %d", stats.Total)
	}
}

func TestConnectionKey_WithPrivateKey(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	config1 := Config{
		Host:       "host1",
		Port:       22,
		User:       "user",
		PrivateKey: "key-content-1",
	}
	config2 := Config{
		Host:       "host1",
		Port:       22,
		User:       "user",
		PrivateKey: "key-content-2",
	}

	key1 := pool.connectionKey(config1)
	key2 := pool.connectionKey(config2)

	if key1 == key2 {
		t.Error("expected different keys for different private keys")
	}
}

func TestConnectionKey_WithKeyPath(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	config1 := Config{
		Host:    "host1",
		Port:    22,
		User:    "user",
		KeyPath: "/path/to/key1",
	}
	config2 := Config{
		Host:    "host1",
		Port:    22,
		User:    "user",
		KeyPath: "/path/to/key2",
	}

	key1 := pool.connectionKey(config1)
	key2 := pool.connectionKey(config2)

	if key1 == key2 {
		t.Error("expected different keys for different key paths")
	}
}

func TestConnectionKey_WithBastionPort(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	config1 := Config{
		Host:        "host1",
		Port:        22,
		User:        "user",
		BastionHost: "bastion",
		BastionPort: 22,
	}
	config2 := Config{
		Host:        "host1",
		Port:        22,
		User:        "user",
		BastionHost: "bastion",
		BastionPort: 2222,
	}

	key1 := pool.connectionKey(config1)
	key2 := pool.connectionKey(config2)

	if key1 == key2 {
		t.Error("expected different keys for different bastion ports")
	}
}

func TestConnectionPool_CleanupLoop(t *testing.T) {
	// Create a pool with very short idle timeout
	pool := NewConnectionPool(time.Millisecond * 20)

	config := Config{Host: "host1", Port: 22, User: "user"}
	key := pool.connectionKey(config)

	// Add an old idle connection
	pool.mu.Lock()
	pool.connections[key] = &pooledConnection{
		client:   &Client{},
		lastUsed: time.Now().Add(-time.Hour),
		inUse:    0,
	}
	pool.mu.Unlock()

	// Wait for cleanup loop to run
	time.Sleep(time.Millisecond * 50)

	pool.mu.RLock()
	_, exists := pool.connections[key]
	pool.mu.RUnlock()

	pool.Close()

	if exists {
		t.Error("expected cleanup loop to remove idle connection")
	}
}
