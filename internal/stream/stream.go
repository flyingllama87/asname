package stream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
)

type StreamOptions struct {
	Format     format.OutputFormat
	ReverseDNS bool
	UseColor   bool
	Workers    int
	// V4Only and V6Only keep only the addresses and prefixes of one family.
	V4Only, V6Only bool
}

// RunStream reads targets continuously from an io.Reader, resolves them
// concurrently across a worker pool, and immediately flushes the results to w.
func RunStream(ctx context.Context, r io.Reader, w io.Writer, eng *engine.Engine, opts StreamOptions) error {
	if opts.Workers <= 0 {
		opts.Workers = engine.MaxResolveWorkers
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	targetsCh := make(chan engine.Target, opts.Workers*4)
	var outMu sync.Mutex
	out := bufio.NewWriter(w)
	if opts.Format == format.FormatCSV {
		_, _ = out.WriteString(format.FormatCSVRow(format.LookupCSVHeader))
		_ = out.Flush()
	}

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-targetsCh:
					if !ok {
						return
					}
					processStreamTarget(ctx, t, eng, out, &outMu, opts)
				}
			}
		}()
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	scanErr := error(nil)
scan:
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break scan
		default:
		}

		line := scanner.Text()
		entry, ok := engine.EntryFromLine(line)
		if !ok || entry == "" {
			continue
		}

		t := engine.NewTarget(entry)
		select {
		case <-ctx.Done():
			break scan
		case targetsCh <- t:
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		scanErr = err
	}

	close(targetsCh)
	wg.Wait()

	outMu.Lock()
	_ = out.Flush()
	outMu.Unlock()

	return scanErr
}

func processStreamTarget(ctx context.Context, t engine.Target, eng *engine.Engine, out *bufio.Writer, outMu *sync.Mutex, opts StreamOptions) {
	if t.Err == nil && t.Host != "" && len(t.IPs) == 0 {
		var err error
		t.IPs, err = engine.LookupHostIPsWithRetry(ctx, t.Host)
		if err != nil {
			t.Err = err
		}
	}
	t = t.OnlyFamily(opts.V4Only, opts.V6Only)

	if t.Err != nil {
		if opts.Format == format.FormatJSON || opts.Format == format.FormatCSV {
			outMu.Lock()
			errLine, _ := format.FormatJSONError(t.Raw, t.Err.Error())
			if opts.Format == format.FormatCSV {
				errLine = format.FormatCSVError(t.Raw, t.Err.Error())
			}
			_, _ = out.WriteString(errLine)
			_ = out.Flush()
			outMu.Unlock()
		} else {
			fmt.Fprintf(os.Stderr, "asname: %s: %v\n", t.Raw, t.Err)
		}
		return
	}

	results, err := eng.LookupTarget(t)
	if err != nil {
		fmt.Fprintf(os.Stderr, "asname: %s: %v\n", t.Raw, err)
		return
	}
	engine.OnlyFamilyPrefixes(results, opts.V4Only, opts.V6Only)

	if opts.ReverseDNS {
		engine.ResolveReverseDNS(ctx, results)
	}

	outMu.Lock()
	defer outMu.Unlock()

	for i, res := range results {
		var formatted string
		switch opts.Format {
		case format.FormatJSON:
			formatted, _ = format.FormatJSONLookupOutput(res)
		case format.FormatCSV:
			formatted = format.FormatCSVLookupOutput(res)
		case format.FormatPretty:
			formatted = format.FormatPrettyLookupOutput(res, i, len(results), opts.UseColor)
		case format.FormatUniform:
			formatted = format.FormatLookupOutput(res, true, res.Host != "")
		default:
			formatted = format.FormatLookupOutput(res, false, res.Host != "")
		}

		if _, writeErr := out.WriteString(formatted); writeErr != nil {
			if isBrokenPipe(writeErr) {
				return
			}
		}
	}
	_ = out.Flush()
}

func isBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}
