package engine

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
		require.Equal(t, tc.want, NormalizeTarget(tc.in), "input %q", tc.in)
	}
}

func TestNewTargetIP(t *testing.T) {
	got := NewTarget("https://8.8.8.8:443/status")

	require.Empty(t, got.Host)
	require.NoError(t, got.Err)
	require.Equal(t, []net.IP{net.ParseIP("8.8.8.8")}, got.IPs)
}

func TestNewTargetHostname(t *testing.T) {
	got := NewTarget("https://dns.google/query?name=a")

	require.Equal(t, "dns.google", got.Host)
	require.NoError(t, got.Err)
	require.Empty(t, got.IPs)
}

func TestNewTargetInvalid(t *testing.T) {
	require.Error(t, NewTarget("///").Err)
}

func TestParseTargetsLiteralIP(t *testing.T) {
	targets, err := ParseTargets("8.8.4.4")

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, []net.IP{net.ParseIP("8.8.4.4")}, targets[0].IPs)
}

func TestParseTargetsHostname(t *testing.T) {
	targets, err := ParseTargets("dns.google")

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "dns.google", targets[0].Host)
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

	targets, err := ParseTargets(path)
	require.NoError(t, err)
	require.Len(t, targets, 4)

	require.Equal(t, []net.IP{net.ParseIP("8.8.8.8")}, targets[0].IPs)
	require.Equal(t, []net.IP{net.ParseIP("1.1.1.1")}, targets[1].IPs)
	require.Equal(t, "dns.google", targets[2].Host)
	require.Equal(t, []net.IP{net.ParseIP("2001:4860:4860::8888")}, targets[3].IPs)
}

func TestParseTargetsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	require.NoError(t, os.WriteFile(path, []byte("# nothing here\n\n"), 0o644))

	_, err := ParseTargets(path)
	require.Error(t, err)
}

func TestParseTargetsRejectsDirectory(t *testing.T) {
	_, err := ParseTargets(t.TempDir())

	require.Error(t, err)
	require.Contains(t, err.Error(), "is a directory")
}

func TestParseTargetsMissingFile(t *testing.T) {
	_, err := ParseTargets(filepath.Join(t.TempDir(), "missing.txt"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file")
}

func TestParseTargetsSchemelessURL(t *testing.T) {
	targets, err := ParseTargets("example.com/status")

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "example.com", targets[0].Host)
}

func TestDedupeIPs(t *testing.T) {
	got := DedupeIPs([]net.IPAddr{
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
		got, ok := EntryFromLine(tc.in)
		require.Equal(t, tc.valid, ok, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

func TestParseASNTarget(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"AS15169", 15169, true},
		{"as15169", 15169, true},
		{"ASN15169", 15169, true},
		{"asn15169", 15169, true},
		{"AS-15169", 15169, true},
		{"ASN:15169", 15169, true},
		{"15169", 15169, true},
		{"AS0", 0, false},
		{"AS", 0, false},
		{"example.com", 0, false},
		{"8.8.8.8", 0, false},
	}

	for _, tc := range cases {
		got, ok := ParseASNTarget(tc.in)
		require.Equal(t, tc.ok, ok, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

func TestNewTargetASN(t *testing.T) {
	got := NewTarget("AS15169")
	require.Equal(t, uint32(15169), got.ASN)
	require.Empty(t, got.Host)
	require.Empty(t, got.IPs)
	require.NoError(t, got.Err)

	gotNum := NewTarget("13335")
	require.Equal(t, uint32(13335), gotNum.ASN)
	require.Empty(t, gotNum.Host)
	require.Empty(t, gotNum.IPs)
}
