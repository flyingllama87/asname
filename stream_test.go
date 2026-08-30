package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunStreamJSON(t *testing.T) {
	eng := testEngine(t)
	input := "8.8.8.8\n# comment line\n\n8.8.8.8\n"
	r := strings.NewReader(input)
	var w bytes.Buffer

	opts := streamOptions{
		format:  formatJSON,
		workers: 2,
	}

	err := runStream(context.Background(), r, &w, eng, opts)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(w.String()), "\n")
	require.Len(t, lines, 2)

	for _, line := range lines {
		var parsed jsonLookupResult
		err = json.Unmarshal([]byte(line), &parsed)
		require.NoError(t, err)
		require.Equal(t, "8.8.8.8", parsed.IP)
		require.Equal(t, "AS15169", parsed.ASN.ASNString)
	}
}

func TestRunStreamPretty(t *testing.T) {
	eng := testEngine(t)
	input := "8.8.8.8\n"
	r := strings.NewReader(input)
	var w bytes.Buffer

	opts := streamOptions{
		format:   formatPretty,
		useColor: false,
		workers:  1,
	}

	err := runStream(context.Background(), r, &w, eng, opts)
	require.NoError(t, err)

	out := w.String()
	require.Contains(t, out, "Target: 8.8.8.8")
	require.Contains(t, out, "AS15169")
	require.Contains(t, out, "GOOGLE - Google LLC, US")
}

func TestRunStreamDefaultFormat(t *testing.T) {
	eng := testEngine(t)
	input := "8.8.8.8\n"
	r := strings.NewReader(input)
	var w bytes.Buffer

	opts := streamOptions{
		format:  formatDefault,
		workers: 1,
	}

	err := runStream(context.Background(), r, &w, eng, opts)
	require.NoError(t, err)

	out := w.String()
	require.Equal(t, "IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States\n", out)
}
