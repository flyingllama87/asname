package stream

import (
	"bytes"
	"context"
	"encoding/csv"
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

func TestRunStreamCSV(t *testing.T) {
	eng := engine.NewTestEngine(t)
	r := strings.NewReader("8.8.8.8\n2001:db8::1\n")
	var w bytes.Buffer

	err := RunStream(context.Background(), r, &w, eng, StreamOptions{Format: format.FormatCSV, Workers: 1, V4Only: true})
	require.NoError(t, err)

	rows, err := csv.NewReader(&w).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 3)
	require.Equal(t, format.LookupCSVHeader, rows[0], "the header comes first")
	byTarget := map[string][]string{}
	for _, row := range rows[1:] {
		byTarget[row[0]] = row
	}
	require.Equal(t, "AS15169", byTarget["8.8.8.8"][4])
	require.Equal(t, "lookup 2001:db8::1: no IPv4 address", byTarget["2001:db8::1"][len(format.LookupCSVHeader)-1])
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
