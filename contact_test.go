package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// contactFor builds an asker with the terminal replaced, so the question and
// the answer can both be driven from a test.
func contactFor(t *testing.T, override, answer string) (*contactAsker, *strings.Builder) {
	t.Helper()

	out := &strings.Builder{}
	a := newContactAsker(filepath.Join(t.TempDir(), contactFilename), override)
	a.out = out
	a.in = strings.NewReader(answer)
	a.terminal = true
	return a, out
}

func TestContactAsksOnceAndRemembers(t *testing.T) {
	a, out := contactFor(t, "", "me@example.com\n")

	email, ok := a.contact()
	require.True(t, ok)
	require.Equal(t, "me@example.com", email)
	// The question has to say what the address is for and where it goes.
	require.Contains(t, out.String(), "bgp.tools")
	require.Contains(t, out.String(), "User-Agent")

	// Asked once per build, and remembered for the next one.
	before := out.String()
	_, _ = a.contact()
	require.Equal(t, before, out.String())

	next, nextOut := contactFor(t, "", "")
	next.path = a.path
	email, ok = next.contact()
	require.True(t, ok)
	require.Equal(t, "me@example.com", email)
	require.Empty(t, nextOut.String())
}

// Declining is a decision, and is remembered too: the build carries on with
// every other source.
func TestContactDeclineIsRemembered(t *testing.T) {
	a, out := contactFor(t, "", "\n")

	email, ok := a.contact()
	require.False(t, ok)
	require.Empty(t, email)
	require.Contains(t, out.String(), contactEnvVar, "the way back must be spelled out")

	next, nextOut := contactFor(t, "", "me@example.com\n")
	next.path = a.path
	_, ok = next.contact()
	require.False(t, ok)
	require.Empty(t, nextOut.String())
}

func TestContactRetriesOnMalformedAnswer(t *testing.T) {
	a, out := contactFor(t, "", "not an email\nstill-not\nme@example.com\n")

	email, ok := a.contact()
	require.True(t, ok)
	require.Equal(t, "me@example.com", email)
	require.Contains(t, out.String(), "does not look like an email address")
}

func TestContactOverrideSkipsTheQuestion(t *testing.T) {
	a, out := contactFor(t, "flag@example.com", "typed@example.com\n")

	email, ok := a.contact()
	require.True(t, ok)
	require.Equal(t, "flag@example.com", email)
	require.Empty(t, out.String())
	// An address given per-run is not written to disk.
	_, found := loadContact(a.path)
	require.False(t, found)
}

func TestContactRejectsMalformedOverride(t *testing.T) {
	a, out := contactFor(t, "nonsense", "")

	_, ok := a.contact()
	require.False(t, ok)
	require.Contains(t, out.String(), "does not look like an email address")
}

func TestContactWithoutATerminalDoesNotAsk(t *testing.T) {
	a, out := contactFor(t, "", "me@example.com\n")
	a.terminal = false

	_, ok := a.contact()
	require.False(t, ok)
	require.Contains(t, out.String(), contactEnvVar)
	_, found := loadContact(a.path)
	require.False(t, found, "nothing was asked, so nothing should be remembered")
}

func TestValidContactEmail(t *testing.T) {
	for _, in := range []string{"me@example.com", "a.b+c@sub.example.co.uk", "x@y.io"} {
		require.True(t, validContactEmail(in), in)
	}
	for _, in := range []string{
		"", "nonsense", "@example.com", "me@", "me@example", "me@example.",
		"me example.com", "a@b@c.com",
	} {
		require.False(t, validContactEmail(in), in)
	}
}

// The address is interpolated into a request header, so anything that could
// end the header line and start another has to be rejected.
func TestValidContactEmailRejectsHeaderInjection(t *testing.T) {
	for _, in := range []string{
		"me@example.com\r\nX-Evil: yes",
		"me@example.com\nX-Evil: yes",
		"me@example.com\tx",
		"me@exa mple.com",
		"me@exam\x00ple.com",
	} {
		require.False(t, validContactEmail(in), "%q", in)
	}
}

func TestContactIgnoresUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), contactFilename)
	require.NoError(t, writeFileAtomic(path, []byte("not json")))
	_, ok := loadContact(path)
	require.False(t, ok)

	// An address that has gone bad on disk is worth asking about again rather
	// than sending as-is.
	require.NoError(t, writeFileAtomic(path, []byte(`{"email":"broken\nheader"}`)))
	_, ok = loadContact(path)
	require.False(t, ok)
}

func TestBGPToolsUserAgentCarriesTheAddress(t *testing.T) {
	agent := bgpToolsUserAgent("me@example.com")
	require.Contains(t, agent, "asname/")
	require.Contains(t, agent, "bgp.tools")
	require.Contains(t, agent, "me@example.com")
}
