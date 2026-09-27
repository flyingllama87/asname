package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
)

func TestRunStreamJSON(t *testing.T) {
	eng := engine.NewTestEngine(t)
	input := "8.8.8.8\n# comment line\n\n8.8.8.8\n"
	r := strings.NewReader(input)
	var w bytes.Buffer

	opts := StreamOptions{
		Format:  format.FormatJSON,
		Workers: 2,
	}

	err := RunStream(context.Background(), r, &w, eng, opts)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(w.String()), "\n")
	require.Len(t, lines, 2)

	for _, line := range lines {
		var parsed format.JSONLookupResult
		err = json.Unmarshal([]byte(line), &parsed)
		require.NoError(t, err)
		require.Equal(t, "8.8.8.8", parsed.IP)
		require.Equal(t, "AS15169", parsed.ASN.ASNString)
	}
}

func TestRunStreamPretty(t *testing.T) {
	eng := engine.NewTestEngine(t)
	input := "8.8.8.8\n"
	r := strings.NewReader(input)
	var w bytes.Buffer

	opts := StreamOptions{
		Format:   format.FormatPretty,
		UseColor: false,
		Workers:  1,
	}

	err := RunStream(context.Background(), r, &w, eng, opts)
	require.NoError(t, err)

	out := w.String()
	require.Contains(t, out, "Target: 8.8.8.8")
	require.Contains(t, out, "AS15169")
	require.Contains(t, out, "GOOGLE - Google LLC, US")
}

func TestRunStreamDefaultFormat(t *testing.T) {
	eng := engine.NewTestEngine(t)
	input := "8.8.8.8\n"
	r := strings.NewReader(input)
	var w bytes.Buffer

	opts := StreamOptions{
		Format:  format.FormatDefault,
		Workers: 1,
	}

	err := RunStream(context.Background(), r, &w, eng, opts)
	require.NoError(t, err)

	out := w.String()
	require.Equal(t, "IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States\n", out)
}

// endlessLines yields "8.8.8.8" lines forever, like a producer that never
// closes its end of the pipe.
type endlessLines struct{}

func (endlessLines) Read(p []byte) (int, error) {
	const line = "8.8.8.8\n"
	n := 0
	for n+len(line) <= len(p) {
		n += copy(p[n:], line)
	}
	return n, nil
}

func TestRunStreamStopsOnCancel(t *testing.T) {
	eng := engine.NewTestEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunStream(ctx, endlessLines{}, io.Discard, eng, StreamOptions{Workers: 2})
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("RunStream kept reading input after its context was cancelled")
	}
}
