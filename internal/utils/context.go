package utils

import (
	"context"
	"time"
)

// HasDeadline reports whether ctx has a deadline or timeout set.
// It returns true if the context will eventually be canceled automatically
// by a deadline or timeout, false otherwise.
func HasDeadline(ctx context.Context) bool {
	_, ok := ctx.Deadline()
	return ok
}

// WithTimeout ensures that ctx has at most the specified timeout.
// If ctx already has a deadline that occurs sooner than the specified timeout,
// it returns the original context with a no-op cancel function.
// Otherwise, it creates a new context with the specified timeout.
//
//	ctx, cancel := WithTimeout(parentCtx, 5*time.Second)
//	defer cancel()
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if ok {
		if time.Until(deadline) <= timeout {
			// Existing deadline is sooner, return original context with no-op cancel
			return ctx, func() {}
		}
	}

	// No deadline or existing deadline is later, create new context with timeout
	return context.WithTimeout(ctx, timeout)
}
