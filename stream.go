package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type streamOptions struct {
	format     outputFormat
	reverseDNS bool
	useColor   bool
	workers    int
}

// runStream reads targets continuously from an io.Reader, resolves them
// concurrently across a worker pool, and immediately flushes the results to w.
func runStream(ctx context.Context, r io.Reader, w io.Writer, eng *engine, opts streamOptions) error {
	if opts.workers <= 0 {
		opts.workers = maxResolveWorkers
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	targetsCh := make(chan target, opts.workers*4)
	var outMu sync.Mutex
	out := bufio.NewWriter(w)

	var wg sync.WaitGroup
	for i := 0; i < opts.workers; i++ {
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
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break
		default:
		}

		line := scanner.Text()
		entry, ok := entryFromLine(line)
		if !ok || entry == "" {
			continue
		}

		t := newTarget(entry)
		select {
		case <-ctx.Done():
			break
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

// processStreamTarget resolves a single target, queries the engine, optionally
// resolves reverse DNS, and formats/flushes the output.
func processStreamTarget(ctx context.Context, t target, eng *engine, out *bufio.Writer, outMu *sync.Mutex, opts streamOptions) {
	// If the target is a hostname, resolve it with retry
	if t.err == nil && t.host != "" && len(t.ips) == 0 {
		var err error
		t.ips, err = lookupHostIPsWithRetry(ctx, t.host)
		if err != nil {
			t.err = err
		}
	}

	if t.err != nil {
		if opts.format == formatJSON {
			outMu.Lock()
			jr := jsonLookupResult{
				Target: t.raw,
				Error:  t.err.Error(),
			}
			data, _ := formatJSONLookupOutput(lookupResult{target: t.raw})
			// serialize error json
			_ = data
			_ = jr
			errLine, _ := formatJSONError(t.raw, t.err.Error())
			_, _ = out.WriteString(errLine)
			_ = out.Flush()
			outMu.Unlock()
		} else {
			fmt.Fprintf(os.Stderr, "asname: %s: %v\n", t.raw, t.err)
		}
		return
	}

	results, err := eng.lookupTarget(t)
	if err != nil {
		fmt.Fprintf(os.Stderr, "asname: %s: %v\n", t.raw, err)
		return
	}

	if opts.reverseDNS {
		resolveReverseDNS(ctx, results)
	}

	outMu.Lock()
	defer outMu.Unlock()

	for i, res := range results {
		var formatted string
		switch opts.format {
		case formatJSON:
			formatted, _ = formatJSONLookupOutput(res)
		case formatPretty:
			formatted = formatPrettyLookupOutput(res, i, len(results), opts.useColor)
		case formatUniform:
			formatted = formatLookupOutput(res, true, res.host != "")
		default:
			formatted = formatLookupOutput(res, false, res.host != "")
		}

		if _, writeErr := out.WriteString(formatted); writeErr != nil {
			if isBrokenPipe(writeErr) {
				return
			}
		}
	}
	_ = out.Flush()
}

// formatJSONError formats an unresolvable target error into a JSONL line.
func formatJSONError(target, errStr string) (string, error) {
	jr := jsonLookupResult{
		Target: target,
		Error:  errStr,
	}
	b, err := jsonMarshal(jr)
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// lookupHostIPsWithRetry resolves hostnames with a single retry on transient failures.
func lookupHostIPsWithRetry(ctx context.Context, host string) ([]net.IP, error) {
	var addrs []net.IPAddr
	var err error

	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}

		lookupCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
		addrs, err = net.DefaultResolver.LookupIPAddr(lookupCtx, host)
		cancel()

		if err == nil {
			break
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			break // NXDOMAIN: do not retry
		}
	}

	if err != nil {
		return nil, err
	}

	ips := dedupeIPs(addrs)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses found", host)
	}
	return ips, nil
}

func isBrokenPipe(err error) bool {
	if errors.Is(err, syscall.EPIPE) {
		return true
	}
	return false
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
