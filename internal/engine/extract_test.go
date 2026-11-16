package engine

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntriesFromLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		// A line that starts with a target: its first field, as always.
		{"8.8.8.8", []string{"8.8.8.8"}},
		{"  8.8.8.8  ", []string{"8.8.8.8"}},
		{"8.8.8.8 # comment", []string{"8.8.8.8"}},
		{"8.8.8.8\tGOOGLE", []string{"8.8.8.8"}},
		{"13335 Cloudflare", []string{"13335"}},
		{"AS15169", []string{"AS15169"}},
		{"dns.google", []string{"dns.google"}},
		{"intranet-host", []string{"intranet-host"}},
		{"https://example.com/a#frag", []string{"https://example.com/a#frag"}},
		{"2001:db8::1 v6 host", []string{"2001:db8::1"}},
		{"185.220.101.1 - - [16/Nov/2026:12:30:45] \"GET / HTTP/1.1\" 200", []string{"185.220.101.1"}},
		// Bullets, numbering and quotes.
		{"- 27.32.75.65", []string{"27.32.75.65"}},
		{"* 46.16.34.229", []string{"46.16.34.229"}},
		{"3. AS134181", []string{"AS134181"}},
		{"\"1.1.1.1\",", []string{"1.1.1.1"}},
		// Free text: everything in it.
		{"Nov 16 12:30:45 sshd[123]: Failed password for root from 185.220.101.1 port 4242 ssh2",
			[]string{"185.220.101.1"}},
		{"beacon to hxxps://evil[.]example[.]com/x and bad-domain[.]ru, from AS 213790",
			[]string{"evil.example.com", "bad-domain.ru", "AS213790"}},
		{"see README.md, setup.py and Node.js, version 10.0.19041 (3.5 KB)", nil},
		{"mail abuse@btcloud.ro about 2a02:6b8::feed:0ff at 12:30:45", []string{"2a02:6b8::feed:0ff"}},
		{"[streaming](https://github.com/topics/streaming \"Topic: streaming\")", []string{"github.com"}},
		// Comments and blanks.
		{"# comment", nil},
		{"### [moviedb](https://github.com/acidvegas/moviedb) Public", nil},
		{"", nil},
		{"   ", nil},
		{"Self-hosted movie & TV browser built on the full IMDb datasets", nil},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, EntriesFromLine(tc.in), "input %q", tc.in)
	}
}

func TestEntryFromLine(t *testing.T) {
	got, ok := EntryFromLine("- 8.8.8.8")
	require.True(t, ok)
	require.Equal(t, "8.8.8.8", got)
	_, ok = EntryFromLine("# nothing")
	require.False(t, ok)
}

func TestExtractTargetsDedupes(t *testing.T) {
	text := "- 27.32.75.65\n- 46.16.34.229\n- 27.32.75.65\n" +
		"[a](https://github.com/x) [b](https://github.com/y)\n"
	require.Equal(t, []string{"27.32.75.65", "46.16.34.229", "github.com"}, ExtractTargets(text))
}
