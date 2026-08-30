package sources

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func contactFor(t *testing.T, override, answer string) (*ContactAsker, *strings.Builder) {
	t.Helper()

	out := &strings.Builder{}
	a := NewContactAsker(filepath.Join(t.TempDir(), ContactFilename), override)
	a.Out = out
	a.In = strings.NewReader(answer)
	a.Terminal = true
	return a, out
}

func TestContactAsksOnceAndRemembers(t *testing.T) {
	a, out := contactFor(t, "", "me@example.com\n")

	email, ok := a.Contact()
	require.True(t, ok)
	require.Equal(t, "me@example.com", email)
	require.Contains(t, out.String(), "bgp.tools")
	require.Contains(t, out.String(), "User-Agent")

	before := out.String()
	_, _ = a.Contact()
	require.Equal(t, before, out.String())

	next, nextOut := contactFor(t, "", "")
	next.Path = a.Path
	email, ok = next.Contact()
	require.True(t, ok)
	require.Equal(t, "me@example.com", email)
	require.Empty(t, nextOut.String())
}

func TestContactDeclineIsRemembered(t *testing.T) {
	a, out := contactFor(t, "", "\n")

	email, ok := a.Contact()
	require.False(t, ok)
	require.Empty(t, email)
	require.Contains(t, out.String(), ContactEnvVar, "the way back must be spelled out")

	next, nextOut := contactFor(t, "", "me@example.com\n")
	next.Path = a.Path
	_, ok = next.Contact()
	require.False(t, ok)
	require.Empty(t, nextOut.String())
}

func TestContactRetriesOnMalformedAnswer(t *testing.T) {
	a, out := contactFor(t, "", "not an email\nstill-not\nme@example.com\n")

	email, ok := a.Contact()
	require.True(t, ok)
	require.Equal(t, "me@example.com", email)
	require.Contains(t, out.String(), "does not look like an email address")
}

func TestContactOverrideSkipsTheQuestion(t *testing.T) {
	a, out := contactFor(t, "flag@example.com", "typed@example.com\n")

	email, ok := a.Contact()
	require.True(t, ok)
	require.Equal(t, "flag@example.com", email)
	require.Empty(t, out.String())

	_, found := LoadContact(a.Path)
	require.False(t, found)
}

func TestContactRejectsMalformedOverride(t *testing.T) {
	a, out := contactFor(t, "nonsense", "")

	_, ok := a.Contact()
	require.False(t, ok)
	require.Contains(t, out.String(), "does not look like an email address")
}

func TestContactWithoutATerminalDoesNotAsk(t *testing.T) {
	a, out := contactFor(t, "", "me@example.com\n")
	a.Terminal = false

	_, ok := a.Contact()
	require.False(t, ok)
	require.Contains(t, out.String(), ContactEnvVar)
	_, found := LoadContact(a.Path)
	require.False(t, found, "nothing was asked, so nothing should be remembered")
}

func TestValidContactEmail(t *testing.T) {
	for _, in := range []string{"me@example.com", "a.b+c@sub.example.co.uk", "x@y.io"} {
		require.True(t, ValidContactEmail(in), in)
	}
	for _, in := range []string{
		"", "nonsense", "@example.com", "me@", "me@example", "me@example.",
		"me example.com", "a@b@c.com",
	} {
		require.False(t, ValidContactEmail(in), in)
	}
}

func TestValidContactEmailRejectsHeaderInjection(t *testing.T) {
	for _, in := range []string{
		"me@example.com\r\nX-Evil: yes",
		"me@example.com\nX-Evil: yes",
		"me@example.com\tx",
		"me@exa mple.com",
		"me@exam\x00ple.com",
	} {
		require.False(t, ValidContactEmail(in), "%q", in)
	}
}

func TestContactIgnoresUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ContactFilename)
	require.NoError(t, WriteFileAtomic(path, []byte("not json")))
	_, ok := LoadContact(path)
	require.False(t, ok)

	require.NoError(t, WriteFileAtomic(path, []byte(`{"email":"broken\nheader"}`)))
	_, ok = LoadContact(path)
	require.False(t, ok)
}

func TestBGPToolsUserAgentCarriesTheAddress(t *testing.T) {
	agent := BGPToolsUserAgent("me@example.com")
	require.Contains(t, agent, "asname/")
	require.Contains(t, agent, "bgp.tools")
	require.Contains(t, agent, "me@example.com")
}
