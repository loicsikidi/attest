package utils

import (
	"context"
	"testing"
	"time"
)

func TestHasDeadline(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{
			name: "context with timeout",
			ctx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				return ctx
			}(),
			want: true,
		},
		{
			name: "context with deadline",
			ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
				defer cancel()
				return ctx
			}(),
			want: true,
		},
		{
			name: "context without deadline",
			ctx:  context.Background(),
			want: false,
		},
		{
			name: "context with cancel only",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				return ctx
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := HasDeadline(tt.ctx); got != tt.want {
				t.Errorf("HasDeadline() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithTimeout(t *testing.T) {
	tests := []struct {
		name                string
		setupCtx            func() context.Context
		timeout             time.Duration
		expectNewContext    bool
		expectDeadlineClose bool
	}{
		{
			name: "context without deadline creates new context with timeout",
			setupCtx: func() context.Context {
				return context.Background()
			},
			timeout:             100 * time.Millisecond,
			expectNewContext:    true,
			expectDeadlineClose: true,
		},
		{
			name: "context with longer deadline creates new context with shorter timeout",
			setupCtx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				t.Cleanup(cancel)
				return ctx
			},
			timeout:             100 * time.Millisecond,
			expectNewContext:    true,
			expectDeadlineClose: true,
		},
		{
			name: "context with shorter deadline returns original context",
			setupCtx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			timeout:             time.Hour,
			expectNewContext:    false,
			expectDeadlineClose: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			originalCtx := tt.setupCtx()
			originalDeadline, originalHasDeadline := originalCtx.Deadline()

			resultCtx, cancel := WithTimeout(originalCtx, tt.timeout)
			defer cancel()

			// Verify context always has a deadline after WithTimeout
			resultDeadline, hasDeadline := resultCtx.Deadline()
			if !hasDeadline && tt.expectDeadlineClose {
				t.Error("expected result context to have a deadline")
			}

			if tt.expectNewContext {
				// Should have created a new context
				if originalHasDeadline && !resultDeadline.Before(originalDeadline) {
					t.Errorf("expected new deadline to be before original deadline")
				}
			} else {
				// Should return original context
				if resultCtx != originalCtx {
					t.Error("expected to return original context")
				}
				if hasDeadline && originalHasDeadline {
					if !resultDeadline.Equal(originalDeadline) {
						t.Errorf("expected deadline to be unchanged, got %v, want %v", resultDeadline, originalDeadline)
					}
				}
			}
		})
	}
}

func TestWithTimeout_CancelNoOp(t *testing.T) {
	// Setup a context with a short deadline
	ctx, originalCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer originalCancel()

	// WithTimeout should return original context with no-op cancel
	resultCtx, cancel := WithTimeout(ctx, time.Hour)

	// Calling the no-op cancel should not cancel the original context
	cancel()

	// Original context should still be valid (not canceled by no-op)
	select {
	case <-resultCtx.Done():
		// This is expected after the original timeout
	case <-time.After(100 * time.Millisecond):
		t.Error("context should have been canceled by original timeout")
	}
}
