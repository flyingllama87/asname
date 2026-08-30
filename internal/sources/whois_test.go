package sources

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
	info := ParseWhoisNetblock(`#
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

	require.Equal(t, "GOGL", info.Netname)
	require.Equal(t, "Google LLC", info.Org)
	require.Equal(t, "GOGL (Google LLC)", info.String())
}

func TestParseWhoisNetblockLACNIC(t *testing.T) {
	info := ParseWhoisNetblock(`% Joint Whois - whois.lacnic.net

inetnum:     200.3.12.0/22
status:      assigned
aut-num:     AS28001
owner:       LACNIC - Latin American and Caribbean IP address
ownerid:     UY-LACN-LACNIC
responsible: Ernesto Majó
country:     UY
`)

	require.Equal(t, "", info.Netname)
	require.Equal(t, "LACNIC - Latin American and Caribbean IP address", info.Org)
}

func TestParseWhoisNetblockRPSL(t *testing.T) {
	info := ParseWhoisNetblock(`% [whois.apnic.net]

inetnum:        183.177.54.128 - 183.177.54.135
netname:        SISS-SY4
descr:          Secure Internet Storage Solutions
country:        AU
`)

	require.Equal(t, "SISS-SY4", info.Netname)
	require.Equal(t, "Secure Internet Storage Solutions", info.Org)
}

func TestParseWhoisNetblockDropsPlaceholders(t *testing.T) {
	info := ParseWhoisNetblock(`inetnum:        8.0.0.0 - 8.255.255.255
netname:        IANA-NETBLOCK-8
descr:          This network range is not allocated to APNIC.
`)

	require.True(t, info.Empty())
}

func TestParseWhoisNetblockNoMatch(t *testing.T) {
	require.True(t, ParseWhoisNetblock("No match found for 203.0.113.1\n").Empty())
	require.True(t, ParseWhoisNetblock("").Empty())
}

func TestWhoisFieldPrefersTheOrderGiven(t *testing.T) {
	body := "owner: Second Choice\nOrgName: First Choice\n"
	require.Equal(t, "First Choice", WhoisField(body, "orgname", "owner"))
	require.Equal(t, "Second Choice", WhoisField(body, "owner", "orgname"))
	require.Equal(t, "", WhoisField(body, "netname"))
	require.Equal(t, "", WhoisField("% netname: Commented\n# netname: Also\n", "netname"))
}

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

	body, err := WhoisQueryOn(host, port, "8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", <-queries)
	require.Equal(t, "GOGL", ParseWhoisNetblock(body).Netname)
}

func TestIsWhoisRateLimited(t *testing.T) {
	require.True(t, IsWhoisRateLimited("#\n# Query rate limit exceeded. Please wait.\n#\n"))
	require.True(t, IsWhoisRateLimited("%% Excessive querying, grace period of 30 seconds\n"))
	require.False(t, IsWhoisRateLimited("No match found for 203.0.113.1\n"))
	require.False(t, IsWhoisRateLimited("NetName: GOGL\n"))
}

func TestWhoisQueryUnreachable(t *testing.T) {
	_, err := WhoisQueryOn("127.0.0.1", "0", "8.8.8.8")
	require.Error(t, err)
}

func TestWhoisConsentRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), WhoisConsentFilename)

	_, ok := LoadWhoisConsent(path)
	require.False(t, ok, "no answer has been given yet")

	require.NoError(t, SaveWhoisConsent(path, true))
	consent, ok := LoadWhoisConsent(path)
	require.True(t, ok)
	require.True(t, consent.Allow)

	require.NoError(t, SaveWhoisConsent(path, false))
	consent, ok = LoadWhoisConsent(path)
	require.True(t, ok)
	require.False(t, consent.Allow)
}

func TestWhoisConsentExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), WhoisConsentFilename)

	writeConsent := func(asked time.Time) {
		t.Helper()
		require.NoError(t, SaveWhoisConsent(path, true))
		consent, ok := LoadWhoisConsent(path)
		require.True(t, ok)
		consent.Asked = asked
		data, err := MarshalConsent(consent)
		require.NoError(t, err)
		require.NoError(t, WriteFileAtomic(path, data))
	}

	writeConsent(time.Now().Add(-WhoisConsentTTL + time.Minute))
	_, ok := LoadWhoisConsent(path)
	require.True(t, ok, "an answer given within the hour still holds")

	writeConsent(time.Now().Add(-WhoisConsentTTL - time.Minute))
	_, ok = LoadWhoisConsent(path)
	require.False(t, ok, "an answer older than the hour is asked again")

	writeConsent(time.Now().Add(24 * time.Hour))
	_, ok = LoadWhoisConsent(path)
	require.False(t, ok)
}

func TestWhoisConsentIgnoresUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), WhoisConsentFilename)
	require.NoError(t, WriteFileAtomic(path, []byte("not json")))

	_, ok := LoadWhoisConsent(path)
	require.False(t, ok)
}

func asker(t *testing.T, mode WhoisMode, answer string) (*WhoisAsker, *strings.Builder) {
	t.Helper()

	out := &strings.Builder{}
	a := NewWhoisAsker(filepath.Join(t.TempDir(), WhoisConsentFilename), mode)
	a.Out = out
	a.In = strings.NewReader(answer)
	a.Terminal = true
	return a, out
}

func TestWhoisAskerAsksOnceAndRemembers(t *testing.T) {
	a, out := asker(t, WhoisAsk, "y\n")

	require.True(t, a.Allowed(net.ParseIP("8.8.8.8")))
	require.Contains(t, out.String(), "8.8.8.8 has no offline netblock")

	before := out.String()
	require.True(t, a.Allowed(net.ParseIP("52.95.110.1")))
	require.Equal(t, before, out.String())

	consent, ok := LoadWhoisConsent(a.Path)
	require.True(t, ok)
	require.True(t, consent.Allow)
}

func TestWhoisAskerRemembersRefusal(t *testing.T) {
	a, _ := asker(t, WhoisAsk, "n\n")
	require.False(t, a.Allowed(net.ParseIP("8.8.8.8")))

	consent, ok := LoadWhoisConsent(a.Path)
	require.True(t, ok)
	require.False(t, consent.Allow)

	next, out := asker(t, WhoisAsk, "y\n")
	next.Path = a.Path
	require.False(t, next.Allowed(net.ParseIP("8.8.8.8")))
	require.Empty(t, out.String())
}

func TestWhoisAskerDefaultsToNoOnEmptyAnswer(t *testing.T) {
	a, _ := asker(t, WhoisAsk, "\n")
	require.False(t, a.Allowed(net.ParseIP("8.8.8.8")))
}

func TestWhoisAskerFlagsSkipTheQuestion(t *testing.T) {
	always, out := asker(t, WhoisAlways, "")
	require.True(t, always.Allowed(net.ParseIP("8.8.8.8")))
	require.Empty(t, out.String())
	_, ok := LoadWhoisConsent(always.Path)
	require.False(t, ok)

	never, out := asker(t, WhoisNever, "y\n")
	require.False(t, never.Allowed(net.ParseIP("8.8.8.8")))
	require.Empty(t, out.String())
}

func TestWhoisAskerWithoutATerminalDoesNotAsk(t *testing.T) {
	a, out := asker(t, WhoisAsk, "y\n")
	a.Terminal = false

	require.False(t, a.Allowed(net.ParseIP("8.8.8.8")))
	require.Contains(t, out.String(), "--whois")
	_, ok := LoadWhoisConsent(a.Path)
	require.False(t, ok)
}

func TestWhoisAskerCapsQueriesPerRun(t *testing.T) {
	a, out := asker(t, WhoisAlways, "")

	allowed := 0
	for range MaxWhoisQueries + 5 {
		if a.Allowed(net.ParseIP("8.8.8.8")) {
			allowed++
		}
	}
	require.Equal(t, MaxWhoisQueries, allowed)
	require.Contains(t, out.String(), "rate limits")
}

func TestWhoisAskerNilIsNeverAllowed(t *testing.T) {
	var a *WhoisAsker
	require.False(t, a.Allowed(net.ParseIP("8.8.8.8")))
}
