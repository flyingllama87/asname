package main

import (
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseWhoisNetblockARIN(t *testing.T) {
	// ARIN answers with the network record followed by the organisation's.
	info := parseWhoisNetblock(`#
# ARIN WHOIS data and services are subject to the Terms of Use
#

NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
NetHandle:      NET-8-8-8-0-2
Parent:         NET8 (NET-8-0-0-0-0)
NetType:        Direct Allocation
OriginAS:
Organization:   Google LLC (GOGL)
RegDate:        2023-12-28

OrgName:        Google LLC
OrgId:          GOGL
Address:        1600 Amphitheatre Parkway
Country:        US
`)

	require.Equal(t, "GOGL", info.netname)
	require.Equal(t, "Google LLC", info.org)
	require.Equal(t, "GOGL (Google LLC)", info.String())
}

func TestParseWhoisNetblockLACNIC(t *testing.T) {
	// LACNIC has no netname at all: the owner is the whole answer.
	info := parseWhoisNetblock(`% Joint Whois - whois.lacnic.net

inetnum:     200.3.12.0/22
status:      assigned
aut-num:     AS28001
owner:       LACNIC - Latin American and Caribbean IP address
ownerid:     UY-LACN-LACNIC
responsible: Ernesto Majó
country:     UY
`)

	require.Equal(t, "", info.netname)
	require.Equal(t, "LACNIC - Latin American and Caribbean IP address", info.org)
}

// A stale offline database is not the only reason to reach an RPSL registry, so
// their spelling has to work too.
func TestParseWhoisNetblockRPSL(t *testing.T) {
	info := parseWhoisNetblock(`% [whois.apnic.net]

inetnum:        183.177.54.128 - 183.177.54.135
netname:        SISS-SY4
descr:          Secure Internet Storage Solutions
country:        AU
`)

	require.Equal(t, "SISS-SY4", info.netname)
	require.Equal(t, "Secure Internet Storage Solutions", info.org)
}

// The registries answer for ranges they do not hold; those placeholders are no
// more useful live than they are in the offline database.
func TestParseWhoisNetblockDropsPlaceholders(t *testing.T) {
	info := parseWhoisNetblock(`inetnum:        8.0.0.0 - 8.255.255.255
netname:        IANA-NETBLOCK-8
descr:          This network range is not allocated to APNIC.
`)

	require.True(t, info.empty())
}

func TestParseWhoisNetblockNoMatch(t *testing.T) {
	require.True(t, parseWhoisNetblock("No match found for 203.0.113.1\n").empty())
	require.True(t, parseWhoisNetblock("").empty())
}

func TestWhoisFieldPrefersTheOrderGiven(t *testing.T) {
	body := "owner: Second Choice\nOrgName: First Choice\n"
	require.Equal(t, "First Choice", whoisField(body, "orgname", "owner"))
	require.Equal(t, "Second Choice", whoisField(body, "owner", "orgname"))
	require.Equal(t, "", whoisField(body, "netname"))
	// Comment lines are not attributes, whichever registry's marker they use.
	require.Equal(t, "", whoisField("% netname: Commented\n# netname: Also\n", "netname"))
}

// fakeWhoisServer serves one canned response per connection and returns its
// host:port, so the client can be exercised without touching the network.
func fakeWhoisServer(t *testing.T, response string) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	queries := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			queries <- strings.TrimSpace(string(buf[:n]))
			io.WriteString(conn, response)
			conn.Close()
		}
	}()
	return ln.Addr().String(), queries
}

func TestWhoisQuery(t *testing.T) {
	addr, queries := fakeWhoisServer(t, "NetName: GOGL\nOrgName: Google LLC\n")
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	// whoisQuery appends the port itself, so point it at the fake one.
	body, err := whoisQueryOn(host, port, "8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", <-queries)
	require.Equal(t, "GOGL", parseWhoisNetblock(body).netname)
}

func TestIsWhoisRateLimited(t *testing.T) {
	// A throttled registry answers with a well-formed document holding no data,
	// which must not be mistaken for an address nobody holds.
	require.True(t, isWhoisRateLimited("#\n# Query rate limit exceeded. Please wait.\n#\n"))
	require.True(t, isWhoisRateLimited("%% Excessive querying, grace period of 30 seconds\n"))
	require.False(t, isWhoisRateLimited("No match found for 203.0.113.1\n"))
	require.False(t, isWhoisRateLimited("NetName: GOGL\n"))
}

func TestWhoisQueryUnreachable(t *testing.T) {
	// Port 0 is never listening, so this fails without waiting for a timeout.
	_, err := whoisQueryOn("127.0.0.1", "0", "8.8.8.8")
	require.Error(t, err)
}

func TestWhoisConsentRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), whoisConsentFilename)

	_, ok := loadWhoisConsent(path)
	require.False(t, ok, "no answer has been given yet")

	require.NoError(t, saveWhoisConsent(path, true))
	consent, ok := loadWhoisConsent(path)
	require.True(t, ok)
	require.True(t, consent.Allow)

	// A refusal is remembered just as firmly as an agreement, which is the
	// point: it stops the question coming back on every address.
	require.NoError(t, saveWhoisConsent(path, false))
	consent, ok = loadWhoisConsent(path)
	require.True(t, ok)
	require.False(t, consent.Allow)
}

func TestWhoisConsentExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), whoisConsentFilename)

	writeConsent := func(asked time.Time) {
		t.Helper()
		require.NoError(t, saveWhoisConsent(path, true))
		consent, ok := loadWhoisConsent(path)
		require.True(t, ok)
		consent.Asked = asked
		data, err := marshalConsent(consent)
		require.NoError(t, err)
		require.NoError(t, writeFileAtomic(path, data))
	}

	writeConsent(time.Now().Add(-whoisConsentTTL + time.Minute))
	_, ok := loadWhoisConsent(path)
	require.True(t, ok, "an answer given within the hour still holds")

	writeConsent(time.Now().Add(-whoisConsentTTL - time.Minute))
	_, ok = loadWhoisConsent(path)
	require.False(t, ok, "an answer older than the hour is asked again")

	// A clock that has moved backwards must not leave an answer holding
	// forever.
	writeConsent(time.Now().Add(24 * time.Hour))
	_, ok = loadWhoisConsent(path)
	require.False(t, ok)
}

func TestWhoisConsentIgnoresUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), whoisConsentFilename)
	require.NoError(t, writeFileAtomic(path, []byte("not json")))

	_, ok := loadWhoisConsent(path)
	require.False(t, ok)
}

// asker builds a whoisAsker with the terminal replaced, so the question and the
// answer can both be driven from a test.
func asker(t *testing.T, mode whoisMode, answer string) (*whoisAsker, *strings.Builder) {
	t.Helper()

	out := &strings.Builder{}
	a := newWhoisAsker(filepath.Join(t.TempDir(), whoisConsentFilename), mode)
	a.out = out
	a.in = strings.NewReader(answer)
	a.terminal = true
	return a, out
}

func TestWhoisAskerAsksOnceAndRemembers(t *testing.T) {
	a, out := asker(t, whoisAsk, "y\n")

	require.True(t, a.allowed(net.ParseIP("8.8.8.8")))
	require.Contains(t, out.String(), "8.8.8.8 has no offline netblock")

	// The second address must not ask again, in this run or the next.
	before := out.String()
	require.True(t, a.allowed(net.ParseIP("52.95.110.1")))
	require.Equal(t, before, out.String())

	consent, ok := loadWhoisConsent(a.path)
	require.True(t, ok)
	require.True(t, consent.Allow)
}

func TestWhoisAskerRemembersRefusal(t *testing.T) {
	a, _ := asker(t, whoisAsk, "n\n")
	require.False(t, a.allowed(net.ParseIP("8.8.8.8")))

	consent, ok := loadWhoisConsent(a.path)
	require.True(t, ok)
	require.False(t, consent.Allow)

	// A fresh run reads the stored refusal rather than asking again.
	next, out := asker(t, whoisAsk, "y\n")
	next.path = a.path
	require.False(t, next.allowed(net.ParseIP("8.8.8.8")))
	require.Empty(t, out.String())
}

func TestWhoisAskerDefaultsToNoOnEmptyAnswer(t *testing.T) {
	a, _ := asker(t, whoisAsk, "\n")
	require.False(t, a.allowed(net.ParseIP("8.8.8.8")))
}

func TestWhoisAskerFlagsSkipTheQuestion(t *testing.T) {
	always, out := asker(t, whoisAlways, "")
	require.True(t, always.allowed(net.ParseIP("8.8.8.8")))
	require.Empty(t, out.String())
	// A forced run must not overwrite a remembered answer.
	_, ok := loadWhoisConsent(always.path)
	require.False(t, ok)

	never, out := asker(t, whoisNever, "y\n")
	require.False(t, never.allowed(net.ParseIP("8.8.8.8")))
	require.Empty(t, out.String())
}

func TestWhoisAskerWithoutATerminalDoesNotAsk(t *testing.T) {
	a, out := asker(t, whoisAsk, "y\n")
	a.terminal = false

	require.False(t, a.allowed(net.ParseIP("8.8.8.8")))
	require.Contains(t, out.String(), "--whois")
	// Nothing was asked, so nothing should be remembered either.
	_, ok := loadWhoisConsent(a.path)
	require.False(t, ok)
}

func TestWhoisAskerCapsQueriesPerRun(t *testing.T) {
	a, out := asker(t, whoisAlways, "")

	allowed := 0
	for range maxWhoisQueries + 5 {
		if a.allowed(net.ParseIP("8.8.8.8")) {
			allowed++
		}
	}
	require.Equal(t, maxWhoisQueries, allowed)
	require.Contains(t, out.String(), "rate limits")
}

// A nil asker is what an engine built without the whois fallback carries.
func TestWhoisAskerNilIsNeverAllowed(t *testing.T) {
	var a *whoisAsker
	require.False(t, a.allowed(net.ParseIP("8.8.8.8")))
}
