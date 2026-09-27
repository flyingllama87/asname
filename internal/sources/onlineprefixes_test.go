package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func prefixAsker(t *testing.T, mode WhoisMode, answer string) (*PrefixAsker, *strings.Builder) {
	t.Helper()

	out := &strings.Builder{}
	a := NewPrefixAsker(filepath.Join(t.TempDir(), OnlinePrefixConsentFilename), mode)
	a.Out = out
	a.In = strings.NewReader(answer)
	a.Terminal = true
	return a, out
}

func TestPrefixAskerAsksOnceAndRemembers(t *testing.T) {
	a, out := prefixAsker(t, WhoisAsk, "y\n")

	require.True(t, a.Allowed(10793))
	require.Contains(t, out.String(), "AS10793")
	require.Contains(t, out.String(), "stat.ripe.net")

	before := out.String()
	require.True(t, a.Allowed(15169))
	require.Equal(t, before, out.String())

	consent, ok := LoadWhoisConsent(a.Path)
	require.True(t, ok)
	require.True(t, consent.Allow)
}

func TestPrefixAskerRemembersRefusal(t *testing.T) {
	a, _ := prefixAsker(t, WhoisAsk, "n\n")
	require.False(t, a.Allowed(10793))

	next, out := prefixAsker(t, WhoisAsk, "y\n")
	next.Path = a.Path
	require.False(t, next.Allowed(10793))
	require.Empty(t, out.String())
}

func TestPrefixAskerDefaultsToNoOnEmptyAnswer(t *testing.T) {
	a, _ := prefixAsker(t, WhoisAsk, "\n")
	require.False(t, a.Allowed(10793))
}

func TestPrefixAskerFlagsSkipTheQuestion(t *testing.T) {
	always, out := prefixAsker(t, WhoisAlways, "")
	require.True(t, always.Allowed(10793))
	require.Empty(t, out.String())
	_, ok := LoadWhoisConsent(always.Path)
	require.False(t, ok)

	never, out := prefixAsker(t, WhoisNever, "y\n")
	require.False(t, never.Allowed(10793))
	require.Empty(t, out.String())
}

func TestPrefixAskerWithoutATerminalDoesNotAsk(t *testing.T) {
	a, out := prefixAsker(t, WhoisAsk, "y\n")
	a.Terminal = false

	require.False(t, a.Allowed(10793))
	require.Contains(t, out.String(), "--online-prefixes")
	require.Equal(t, 1, strings.Count(out.String(), "\n"), "the hint is one line")
	_, ok := LoadWhoisConsent(a.Path)
	require.False(t, ok)
}

func TestPrefixAskerNilIsNeverAllowed(t *testing.T) {
	var a *PrefixAsker
	require.False(t, a.Allowed(10793))
}

func TestIsTerminalRejectsDevNull(t *testing.T) {
	// /dev/null is a character device, which is what cron gives stdin; it
	// must not be mistaken for a terminal to ask on.
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer f.Close()
	require.False(t, isTerminal(f))

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	require.False(t, isTerminal(r))
	require.False(t, isTerminal(nil))
}
