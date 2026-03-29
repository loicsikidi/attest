package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/loicsikidi/attest/internal/utils"
)

var (
	ErrHTTPGetTooLarge = errors.New("downloaded content exceeds maximum allowed size")
	ErrHTTPGetError    = errors.New("error during HTTP GET request")
)

const (
	maxRetries           = 4               // Total attempts: 1 initial + 3 retries
	maxHTTPGetSize int64 = 5 * 1024 * 1024 // 5 MiB
)

// DefaultBackoffConfig holds the default exponential backoff configuration for HTTP retries.
// Can be modified for testing purposes.
var DefaultBackoffConfig = &backoff.ExponentialBackOff{
	InitialInterval:     100 * time.Millisecond,
	MaxInterval:         500 * time.Millisecond,
	Multiplier:          2.0, // Double the interval each retry
	RandomizationFactor: 0.5, // Default randomization factor (±50%)
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds the configuration for HttpGET requests.
type Config struct {
	// MaxSize is the maximum allowed size for the HTTP GET response body.
	MaxSize int64
	// Backoff is the exponential backoff configuration for retries.
	Backoff *backoff.ExponentialBackOff
}

// CheckAndSetDefault validates the configuration and sets default values.
func (c *Config) CheckAndSetDefault() error {
	if c.MaxSize == 0 {
		c.MaxSize = maxHTTPGetSize
	}
	if c.Backoff == nil {
		c.Backoff = &backoff.ExponentialBackOff{
			InitialInterval:     DefaultBackoffConfig.InitialInterval,
			MaxInterval:         DefaultBackoffConfig.MaxInterval,
			Multiplier:          DefaultBackoffConfig.Multiplier,
			RandomizationFactor: DefaultBackoffConfig.RandomizationFactor,
		}
	}
	return nil
}

func HttpGET(ctx context.Context, client HTTPClient, url string, optionalCfg ...Config) ([]byte, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	c := client
	if c == nil {
		c = http.DefaultClient
	}

	expBackoff := cfg.Backoff

	statusCode := -1
	type operationResult struct {
		body       []byte
		statusCode int
	}
	operation := func() (operationResult, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return operationResult{}, backoff.Permanent(err)
		}

		res, err := c.Do(req)
		if err != nil {
			return operationResult{}, backoff.Permanent(err)
		}
		defer res.Body.Close()

		statusCode = res.StatusCode

		if is5xx(res.StatusCode) {
			return operationResult{nil, statusCode}, fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
		}

		if res.StatusCode != http.StatusOK {
			err := fmt.Errorf("failed to download from %s: HTTP %d", url, res.StatusCode)
			return operationResult{nil, statusCode}, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetError, err))
		}

		// Process successful response
		var length int64
		if header := res.Header.Get("Content-Length"); header != "" {
			length, err = strconv.ParseInt(header, 10, 0)
			if err != nil {
				return operationResult{nil, statusCode}, backoff.Permanent(err)
			}
			if length > cfg.MaxSize {
				err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, length, cfg.MaxSize)
				return operationResult{nil, statusCode}, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err))
			}
		}

		// Although the size has been checked above, use a LimitReader in case
		// the reported size is inaccurate.
		data, err := io.ReadAll(io.LimitReader(res.Body, cfg.MaxSize+1))
		if err != nil {
			return operationResult{nil, statusCode}, backoff.Permanent(err)
		}

		length = int64(len(data))
		if int64(length) > cfg.MaxSize {
			err := fmt.Errorf("download failed for %s, length %d is larger than expected %d", url, length, cfg.MaxSize)
			return operationResult{nil, statusCode}, backoff.Permanent(fmt.Errorf("%w: %v", ErrHTTPGetTooLarge, err))
		}
		return operationResult{data, statusCode}, nil
	}

	result, err := backoff.Retry(ctx, operation, backoff.WithBackOff(expBackoff), backoff.WithMaxTries(maxRetries))
	if err != nil {
		// backoff.Retry automatically unwraps permanent errors
		// So errors here are either:
		// 1. Already unwrapped permanent errors (client errors, ErrHTTPGetError, ErrHTTPGetTooLarge)
		// 2. Context errors (canceled, deadline exceeded)
		// 3. Retryable errors that exhausted max retries (5xx server errors)

		// Return context errors directly
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		// Return errors already wrapped with sentinel errors
		if errors.Is(err, ErrHTTPGetError) || errors.Is(err, ErrHTTPGetTooLarge) {
			return nil, err
		}

		// Check if this is a retryable 5xx error that exhausted retries
		// These need to be wrapped with ErrHTTPGetError
		if is5xx(result.statusCode) {
			return nil, fmt.Errorf("%w: %v", ErrHTTPGetError, err)
		}

		// All other errors (client, network, etc.) return as-is
		return nil, err
	}

	return result.body, nil
}

func is5xx(statusCode int) bool {
	return statusCode >= 500 && statusCode < 600
}
