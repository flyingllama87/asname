package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// idleTimeout abandons a request that receives nothing for this long, whether
// waiting for the response or partway through the body. A connection that a
// network path stops forwarding stays open with nothing arriving, and without
// this a download would wait on it forever. A download abandoned this way
// keeps its partial file and resumes on the next update.
var idleTimeout = 60 * time.Second

// errStalled marks a request abandoned by idleTimeout.
var errStalled = errors.New("stalled")

// stallGuard cancels one request's context once it has been idle for idleTimeout.
type stallGuard struct {
	timer   *time.Timer
	cancel  context.CancelFunc
	stalled atomic.Bool
}

func newStallGuard(parent context.Context) (context.Context, *stallGuard) {
	ctx, cancel := context.WithCancel(parent)
	g := &stallGuard{cancel: cancel}
	g.timer = time.AfterFunc(idleTimeout, func() {
		g.stalled.Store(true)
		cancel()
	})
	return ctx, g
}

func (g *stallGuard) touch() { g.timer.Reset(idleTimeout) }

func (g *stallGuard) stop() {
	g.timer.Stop()
	g.cancel()
}

// wrap explains an error caused by the guard firing.
func (g *stallGuard) wrap(err error) error {
	if err != nil && g.stalled.Load() {
		return fmt.Errorf("%w: no data received for %s", errStalled, idleTimeout)
	}
	return err
}

// guardedBody resets the guard on every read and releases it on Close.
type guardedBody struct {
	io.ReadCloser
	g *stallGuard
}

func (b *guardedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.g.touch()
	}
	if err != nil && err != io.EOF {
		err = b.g.wrap(err)
	}
	return n, err
}

func (b *guardedBody) Close() error {
	err := b.ReadCloser.Close()
	b.g.stop()
	return err
}
