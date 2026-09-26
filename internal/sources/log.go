package sources

import (
	"context"
	"fmt"
	"io"
)

type logKey struct{}

// WithLog returns a context whose progress and warning messages go to w. The
// CLI attaches os.Stderr; a library caller that attaches nothing gets silence,
// because a package should not write to a terminal it does not own.
func WithLog(ctx context.Context, w io.Writer) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if w == nil {
		return ctx
	}
	return context.WithValue(ctx, logKey{}, w)
}

// LogWriter returns the writer attached by WithLog, or io.Discard.
func LogWriter(ctx context.Context) io.Writer {
	if ctx != nil {
		if w, ok := ctx.Value(logKey{}).(io.Writer); ok {
			return w
		}
	}
	return io.Discard
}

// logf writes one message to the context's log writer.
func logf(ctx context.Context, format string, args ...any) {
	fmt.Fprintf(LogWriter(ctx), format, args...)
}
