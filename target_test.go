package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8"},
		{" 8.8.8.8 ", "8.8.8.8"},
		{"dns.google", "dns.google"},
		{"dns.google.", "dns.google"},
		{"2001:4860:4860::8888", "2001:4860:4860::8888"},

		{"https://example.com", "example.com"},
		{"http://example.com/", "example.com"},
		{"https://example.com:8443/path/to?q=1#frag", "example.com"},
		{"ftp://user:pass@example.com:21/pub", "example.com"},
		{"//example.com/path", "example.com"},
		{"example.com/path/with@sign", "example.com"},
		{"example.com:8080", "example.com"},

		{"https://8.8.8.8:443/health", "8.8.8.8"},
		{"http://[2001:4860:4860::8888]:80/x", "2001:4860:4860::8888"},
		{"[2001:4860:4860::8888]:443", "2001:4860:4860::8888"},

		{"", ""},
		{"https://", ""},
	}

	for _, tc := range cases {
		require.Equal(t, tc.want, normalizeTarget(tc.in), "input %q", tc.in)
	}
}

func TestNewTargetIP(t *testing.T) {
	got := newTarget("https://8.8.8.8:443/status")

	require.Empty(t, got.host)
	require.NoError(t, got.err)
	require.Equal(t, []net.IP{net.ParseIP("8.8.8.8")}, got.ips)
}

func TestNewTargetHostname(t *testing.T) {
	got := newTarget("https://dns.google/query?name=a")

	require.Equal(t, "dns.google", got.host)
	require.NoError(t, got.err)
	require.Empty(t, got.ips)
}

func TestNewTargetInvalid(t *testing.T) {
	require.Error(t, newTarget("///").err)
}

func TestParseTargetsLiteralIP(t *testing.T) {
	targets, err := parseTargets("8.8.4.4")

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, []net.IP{net.ParseIP("8.8.4.4")}, targets[0].ips)
}

func TestParseTargetsHostname(t *testing.T) {
	targets, err := parseTargets("dns.google")

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "dns.google", targets[0].host)
}

func TestParseTargetsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	content := "" +
		"# a comment\n" +
		"\n" +
		"8.8.8.8\n" +
		"  1.1.1.1  # trailing comment\n" +
		"https://dns.google:443/path\n" +
		"2001:4860:4860::8888\tsome trailing column\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	targets, err := parseTargets(path)
	require.NoError(t, err)
	require.Len(t, targets, 4)

	require.Equal(t, []net.IP{net.ParseIP("8.8.8.8")}, targets[0].ips)
	require.Equal(t, []net.IP{net.ParseIP("1.1.1.1")}, targets[1].ips)
	require.Equal(t, "dns.google", targets[2].host)
	require.Equal(t, []net.IP{net.ParseIP("2001:4860:4860::8888")}, targets[3].ips)
}

func TestParseTargetsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	require.NoError(t, os.WriteFile(path, []byte("# nothing here\n\n"), 0o644))

	_, err := parseTargets(path)
	require.Error(t, err)
}

func TestParseTargetsRejectsDirectory(t *testing.T) {
	_, err := parseTargets(t.TempDir())

	require.Error(t, err)
	require.Contains(t, err.Error(), "is a directory")
}

// An argument that can only be a path is reported as a missing file rather
// than being handed to DNS as a hostname.
func TestParseTargetsMissingFile(t *testing.T) {
	_, err := parseTargets(filepath.Join(t.TempDir(), "missing.txt"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file")
}

// A scheme-less URL keeps working even though it contains a slash.
func TestParseTargetsSchemelessURL(t *testing.T) {
	targets, err := parseTargets("example.com/status")

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "example.com", targets[0].host)
}

func TestDedupeIPs(t *testing.T) {
	got := dedupeIPs([]net.IPAddr{
		{IP: net.ParseIP("8.8.8.8")},
		{IP: net.ParseIP("2001:4860:4860::8888")},
		{IP: net.ParseIP("8.8.8.8")},
	})

	require.Equal(t, []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("2001:4860:4860::8888"),
	}, got)
}

func TestEntryFromLine(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{"8.8.8.8", "8.8.8.8", true},
		{"  8.8.8.8  ", "8.8.8.8", true},
		{"8.8.8.8 # comment", "8.8.8.8", true},
		{"8.8.8.8\tGOOGLE", "8.8.8.8", true},
		{"# comment", "", false},
		{"", "", false},
		{"   ", "", false},
	}

	for _, tc := range cases {
		got, ok := entryFromLine(tc.in)
		require.Equal(t, tc.valid, ok, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}
