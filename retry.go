package gosftp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

// RetryConfig configures retry behavior for SSH operations.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (0 = no retries).
	MaxRetries int

	// InitialDelay is the initial delay between retries.
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries.
	MaxDelay time.Duration

	// Multiplier is the backoff multiplier (e.g., 2.0 = double delay each retry).
	Multiplier float64

	// JitterFactor adds randomness to delay (0.0 = no jitter, 0.5 = ±50% jitter).
	JitterFactor float64
}

// DefaultRetryConfig returns sensible default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:   3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		JitterFactor: 0.25,
	}
}

// NoRetryConfig returns a config with retries disabled.
func NoRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 0,
	}
}

// RetryableFunc is a function that can be retried.
type RetryableFunc func() error

// Retry executes the given function with exponential backoff retry logic.
func Retry(ctx context.Context, config RetryConfig, operation string, fn RetryableFunc) error {
	var lastErr error

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s cancelled: %w", operation, err)
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if !IsRetryableError(err) {
			return err
		}

		if attempt == config.MaxRetries {
			break
		}

		delay := calculateDelay(config, attempt)

		log.Printf("[WARN] %s failed (attempt %d/%d): %v. Retrying in %v...",
			operation, attempt+1, config.MaxRetries+1, err, delay)

		select {
		case <-ctx.Done():
			return fmt.Errorf("%s cancelled during retry wait: %w", operation, ctx.Err())
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("%s failed after %d attempts: %w", operation, config.MaxRetries+1, lastErr)
}

func calculateDelay(config RetryConfig, attempt int) time.Duration {
	delay := float64(config.InitialDelay)
	for i := 0; i < attempt; i++ {
		delay *= config.Multiplier
	}

	if config.JitterFactor > 0 {
		jitter := delay * config.JitterFactor
		delay = delay - jitter + (rand.Float64() * 2 * jitter)
	}

	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}

	return time.Duration(delay)
}

// IsRetryableError checks if an error is transient and worth retrying.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	errMsg := err.Error()
	retryableMessages := []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"no route to host",
		"network is unreachable",
		"i/o timeout",
		"handshake failed",
		"ssh: disconnect",
		"ssh: unable to authenticate",
		"temporary failure",
		"too many open files",
	}

	for _, msg := range retryableMessages {
		if strings.Contains(strings.ToLower(errMsg), msg) {
			return true
		}
	}

	return false
}

// WithRetry wraps an operation with retry logic.
func WithRetry(ctx context.Context, maxRetries int, operation string, fn RetryableFunc) error {
	config := DefaultRetryConfig()
	config.MaxRetries = maxRetries
	return Retry(ctx, config, operation, fn)
}
