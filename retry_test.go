package gosftp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxRetries != 3 {
		t.Errorf("expected MaxRetries=3, got %d", config.MaxRetries)
	}
	if config.InitialDelay != 1*time.Second {
		t.Errorf("expected InitialDelay=1s, got %v", config.InitialDelay)
	}
	if config.MaxDelay != 30*time.Second {
		t.Errorf("expected MaxDelay=30s, got %v", config.MaxDelay)
	}
	if config.Multiplier != 2.0 {
		t.Errorf("expected Multiplier=2.0, got %v", config.Multiplier)
	}
	if config.JitterFactor != 0.25 {
		t.Errorf("expected JitterFactor=0.25, got %v", config.JitterFactor)
	}
}

func TestNoRetryConfig(t *testing.T) {
	config := NoRetryConfig()

	if config.MaxRetries != 0 {
		t.Errorf("expected MaxRetries=0, got %d", config.MaxRetries)
	}
}

func TestRetry_Success(t *testing.T) {
	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	callCount := 0
	err := Retry(ctx, config, "test operation", func() error {
		callCount++
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestRetry_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	callCount := 0
	err := Retry(ctx, config, "test operation", func() error {
		callCount++
		if callCount < 3 {
			return errors.New("connection refused")
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 calls, got %d", callCount)
	}
}

func TestRetry_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   2,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	callCount := 0
	err := Retry(ctx, config, "test operation", func() error {
		callCount++
		return errors.New("connection refused")
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount != 3 { // initial + 2 retries
		t.Errorf("expected 3 calls, got %d", callCount)
	}
	if !errors.Is(err, errors.New("")) {
		// Check error message contains expected text
		if err.Error() != "test operation failed after 3 attempts: connection refused" {
			t.Errorf("unexpected error message: %v", err)
		}
	}
}

func TestRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	config := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	callCount := 0
	permanentErr := errors.New("permission denied")
	err := Retry(ctx, config, "test operation", func() error {
		callCount++
		return permanentErr
	})

	if err != permanentErr {
		t.Errorf("expected permanentErr, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	config := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Millisecond,
	}

	err := Retry(ctx, config, "test operation", func() error {
		return nil
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestRetry_ContextCancelledDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	config := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Second, // Long delay
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0,
	}

	callCount := 0
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, config, "test operation", func() error {
		callCount++
		return errors.New("connection refused") // Retryable error
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestRetry_NoRetries(t *testing.T) {
	ctx := context.Background()
	config := NoRetryConfig()

	callCount := 0
	err := Retry(ctx, config, "test operation", func() error {
		callCount++
		return errors.New("connection refused")
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestCalculateDelay(t *testing.T) {
	tests := []struct {
		name      string
		config    RetryConfig
		attempt   int
		minDelay  time.Duration
		maxDelay  time.Duration
		exactTest bool
	}{
		{
			name: "first attempt no jitter",
			config: RetryConfig{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     10 * time.Second,
				Multiplier:   2.0,
				JitterFactor: 0,
			},
			attempt:   0,
			minDelay:  100 * time.Millisecond,
			maxDelay:  100 * time.Millisecond,
			exactTest: true,
		},
		{
			name: "second attempt with multiplier no jitter",
			config: RetryConfig{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     10 * time.Second,
				Multiplier:   2.0,
				JitterFactor: 0,
			},
			attempt:   1,
			minDelay:  200 * time.Millisecond,
			maxDelay:  200 * time.Millisecond,
			exactTest: true,
		},
		{
			name: "third attempt with multiplier no jitter",
			config: RetryConfig{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     10 * time.Second,
				Multiplier:   2.0,
				JitterFactor: 0,
			},
			attempt:   2,
			minDelay:  400 * time.Millisecond,
			maxDelay:  400 * time.Millisecond,
			exactTest: true,
		},
		{
			name: "capped at max delay",
			config: RetryConfig{
				InitialDelay: 1 * time.Second,
				MaxDelay:     5 * time.Second,
				Multiplier:   10.0,
				JitterFactor: 0,
			},
			attempt:   2,
			minDelay:  5 * time.Second,
			maxDelay:  5 * time.Second,
			exactTest: true,
		},
		{
			name: "with jitter",
			config: RetryConfig{
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     10 * time.Second,
				Multiplier:   2.0,
				JitterFactor: 0.5,
			},
			attempt:   0,
			minDelay:  50 * time.Millisecond,
			maxDelay:  150 * time.Millisecond,
			exactTest: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := calculateDelay(tt.config, tt.attempt)
			if tt.exactTest {
				if delay != tt.minDelay {
					t.Errorf("expected delay=%v, got %v", tt.minDelay, delay)
				}
			} else {
				if delay < tt.minDelay || delay > tt.maxDelay {
					t.Errorf("expected delay between %v and %v, got %v", tt.minDelay, tt.maxDelay, delay)
				}
			}
		})
	}
}

// mockNetError implements net.Error for testing.
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

var _ net.Error = (*mockNetError)(nil)

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			name:     "timeout network error",
			err:      &mockNetError{timeout: true, msg: "timeout"},
			expected: true,
		},
		{
			name:     "non-timeout network error",
			err:      &mockNetError{timeout: false, msg: "some error"},
			expected: false,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "connection reset",
			err:      errors.New("connection reset by peer"),
			expected: true,
		},
		{
			name:     "broken pipe",
			err:      errors.New("write: broken pipe"),
			expected: true,
		},
		{
			name:     "no route to host",
			err:      errors.New("no route to host"),
			expected: true,
		},
		{
			name:     "network unreachable",
			err:      errors.New("network is unreachable"),
			expected: true,
		},
		{
			name:     "i/o timeout",
			err:      errors.New("i/o timeout"),
			expected: true,
		},
		{
			name:     "handshake failed",
			err:      errors.New("ssh: handshake failed"),
			expected: true,
		},
		{
			name:     "ssh disconnect",
			err:      errors.New("ssh: disconnect"),
			expected: true,
		},
		{
			name:     "ssh unable to authenticate",
			err:      errors.New("ssh: unable to authenticate"),
			expected: true,
		},
		{
			name:     "temporary failure",
			err:      errors.New("temporary failure in name resolution"),
			expected: true,
		},
		{
			name:     "too many open files",
			err:      errors.New("too many open files"),
			expected: true,
		},
		{
			name:     "permission denied - not retryable",
			err:      errors.New("permission denied"),
			expected: false,
		},
		{
			name:     "file not found - not retryable",
			err:      errors.New("file not found"),
			expected: false,
		},
		{
			name:     "case insensitive - Connection Refused",
			err:      errors.New("Connection Refused"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryableError(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestWithRetry(t *testing.T) {
	ctx := context.Background()

	callCount := 0
	err := WithRetry(ctx, 2, "test operation", func() error {
		callCount++
		if callCount < 2 {
			return errors.New("connection refused")
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestWithRetry_Failure(t *testing.T) {
	ctx := context.Background()

	callCount := 0
	err := WithRetry(ctx, 1, "test operation", func() error {
		callCount++
		return errors.New("connection refused")
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount != 2 { // initial + 1 retry
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}
