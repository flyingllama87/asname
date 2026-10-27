package sources

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// serveFiles serves body by escaped path, and records every path asked for.
func serveFiles(t *testing.T, files map[string]string) (*httptest.Server, *[]string) {
	t.Helper()

	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.EscapedPath())
		body, ok := files[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(strings.ReplaceAll(body, "{{base}}", "http://"+r.Host)))
	}))
	t.Cleanup(srv.Close)
	return srv, &asked
}

const gluetunListing = `[
	{"name":"manifest.json","type":"file","download_url":"{{base}}/g/manifest.json"},
	{"name":"mullvad.json","type":"file","download_url":"{{base}}/g/mullvad.json"},
	{"name":"private internet access.json","type":"file","download_url":"{{base}}/g/private%20internet%20access.json"},
	{"name":"gone.json","type":"file","download_url":"{{base}}/g/gone.json"},
	{"name":"README.md","type":"file","download_url":"{{base}}/g/README.md"},
	{"name":"old","type":"dir","download_url":null}]`

func gluetunFiles() map[string]string {
	return map[string]string{
		"/g/list": gluetunListing,
		"/g/mullvad.json": `{"version":4,"timestamp":1785990787,"servers":[
			{"vpn":"wireguard","hostname":"au-syd-wg-001","ips":["103.136.147.3","2404:f780:5:dec::c01f"]},
			{"vpn":"openvpn","hostname":"au-syd-ovpn-001","ips":["103.136.147.3"]}]}`,
		"/g/private%20internet%20access.json": `{"version":1,"servers":[
			{"vpn":"openvpn","hostname":"au-sydney","ips":["117.120.9.5","not-an-ip"]}]}`,
	}
}

func TestImportVPNServersFromGluetunAlone(t *testing.T) {
	srv, asked := serveFiles(t, gluetunFiles())

	b := newCategoryBuilder(context.Background())
	n, err := b.ImportVPNServers(nil, srv.URL+"/g/list")
	require.NoError(t, err)
	require.Equal(t, 3, n, "a list that fails is skipped and a repeated address counted once")
	require.NotContains(t, *asked, "/g/manifest.json", "the manifest is not a provider")
	require.NotContains(t, *asked, "/g/README.md")
	require.Equal(t, map[string]bool{"vpn:mullvad": true}, b.prefixes["103.136.147.3/32"])
	require.Equal(t, map[string]bool{"vpn:mullvad": true}, b.prefixes["2404:f780:5:dec::c01f/128"])
	require.Equal(t, map[string]bool{"vpn:private-internet-access": true}, b.prefixes["117.120.9.5/32"])
	require.Equal(t, map[string]VPNList{
		"vpn:mullvad":                 {Source: "gluetun server list for mullvad", Date: time.Unix(1785990787, 0).UTC()},
		"vpn:private-internet-access": {Source: "gluetun server list for private internet access"},
	}, b.vpnLists, "a list without a timestamp has no date")
}

func TestImportVPNServersPrefersTheProvidersOwnList(t *testing.T) {
	files := gluetunFiles()
	files["/mullvad"] = `[{"hostname":"au-syd-wg-101","ipv4_addr_in":"45.248.78.1","ipv6_addr_in":"2404:f780:8:3006::f001"}]`
	srv, asked := serveFiles(t, files)

	apis := []vpnAPI{{"mullvad", "Mullvad relay API", srv.URL + "/mullvad", readMullvad}}
	b := newCategoryBuilder(context.Background())
	before := time.Now().UTC().Add(-time.Second)
	n, err := b.ImportVPNServers(apis, srv.URL+"/g/list")
	require.NoError(t, err)
	require.Equal(t, 3, n)

	require.Equal(t, map[string]bool{"vpn:mullvad": true}, b.prefixes["45.248.78.1/32"])
	require.Equal(t, map[string]bool{"vpn:mullvad": true}, b.prefixes["2404:f780:8:3006::f001/128"])
	require.NotContains(t, b.prefixes, "103.136.147.3/32", "gluetun's older copy is not used")
	require.NotContains(t, *asked, "/g/mullvad.json")
	require.Contains(t, b.prefixes, "117.120.9.5/32", "providers without their own list still come from gluetun")

	list := b.vpnLists["vpn:mullvad"]
	require.Equal(t, "Mullvad relay API", list.Source)
	require.True(t, list.Date.After(before), "a provider's own list is as of the build")
}

func TestImportVPNServersFallsBackToGluetun(t *testing.T) {
	files := gluetunFiles()
	files["/mullvad"] = `[]`
	srv, _ := serveFiles(t, files)

	apis := []vpnAPI{
		{"mullvad", "Mullvad relay API", srv.URL + "/mullvad", readMullvad},
		{"private internet access", "PIA server list", srv.URL + "/missing", readPIA},
	}
	b := newCategoryBuilder(context.Background())
	n, err := b.ImportVPNServers(apis, srv.URL+"/g/list")
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Contains(t, b.prefixes, "103.136.147.3/32", "an empty list falls back")
	require.Contains(t, b.prefixes, "117.120.9.5/32", "an unreachable list falls back")
	require.Equal(t, "gluetun server list for mullvad", b.vpnLists["vpn:mullvad"].Source)
}

func TestImportVPNServersResolvesHostnames(t *testing.T) {
	srv, _ := serveFiles(t, map[string]string{
		"/ivpn": `{"servers":[
			{"hostnames":{"openvpn":"au-nsw1.gw.ivpn.net","wireguard":"au-nsw1.wg.ivpn.net"}},
			{"hostnames":{"openvpn":"nl1.gw.ivpn.net","wireguard":""}}]}`,
	})
	hosts := map[string][]string{
		"au-nsw1.gw.ivpn.net": {"46.102.153.246"},
		"au-nsw1.wg.ivpn.net": {"46.102.153.246", "2a0d:5600:24:13::1"},
		"nl1.gw.ivpn.net":     {"185.102.219.26"},
	}
	b := newCategoryBuilder(context.Background())
	b.lookupHost = func(_ context.Context, host string) ([]string, error) {
		if addrs, ok := hosts[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host")
	}

	apis := []vpnAPI{{"ivpn", "IVPN server API", srv.URL + "/ivpn", readIVPN}}
	n, err := b.ImportVPNServers(apis, srv.URL+"/no-gluetun")
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, map[string]bool{"vpn:ivpn": true}, b.prefixes["2a0d:5600:24:13::1/128"])
	require.Equal(t, "IVPN server API", b.vpnLists["vpn:ivpn"].Source)

	// With most names failing, the provider's own list is not trusted.
	delete(hosts, "au-nsw1.gw.ivpn.net")
	delete(hosts, "nl1.gw.ivpn.net")
	b = newCategoryBuilder(context.Background())
	b.lookupHost = func(_ context.Context, host string) ([]string, error) {
		if addrs, ok := hosts[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host")
	}
	_, err = b.ImportVPNServers(apis, srv.URL+"/no-gluetun")
	require.Error(t, err)
	require.Empty(t, b.prefixes)
}

// TestVPNAPIReaders checks each provider's reader against a trimmed copy of
// the shape its API returns.
func TestVPNAPIReaders(t *testing.T) {
	cases := []struct {
		read  func(*categoryBuilder, string) ([]string, []string, error)
		files map[string]string
		addrs []string
		hosts []string
	}{
		{readNordVPN, map[string]string{"/": `{"servers":[{"name":"Australia #500","station":"103.137.12.3","station_ipv6":"",
			"hostname":"au500.nordvpn.com","ips":[{"type":"entry","ip":{"ip":"103.137.12.3","version":4}},{"type":"exit","ip":{"ip":"103.137.12.4","version":4}}]}],
			"groups":[],"services":[],"locations":[],"technologies":[]}`},
			[]string{"103.137.12.3", "", "103.137.12.3", "103.137.12.4"}, nil},
		{readMullvad, map[string]string{"/": `[{"hostname":"au-syd-wg-101","country_name":"Australia","ipv4_addr_in":"45.248.78.1","ipv6_addr_in":"2404:f780:8:3006::f001","type":"wireguard"}]`},
			[]string{"45.248.78.1", "2404:f780:8:3006::f001"}, nil},
		{readSurfshark, map[string]string{
			"/generic":    `[{"connectionName":"au-syd.prod.surfshark.com","info":[{"entry":{"value":"U2FsdGVkX1+..."}}]}]`,
			"/double":     `[{"connectionName":"au-syd.prod.surfshark.com"}]`,
			"/static":     `[{"connectionName":"au-syd-st001.prod.surfshark.com"}]`,
			"/obfuscated": `[]`},
			nil, []string{"au-syd-st001.prod.surfshark.com", "au-syd.prod.surfshark.com"}},
		{readPIA, map[string]string{"/": `{"groups":{},"regions":[{"id":"aus","name":"AU Sydney","servers":{
			"ovpnudp":[{"ip":"117.120.9.5","cn":"sydney402"}],"wg":[{"ip":"117.120.9.6","cn":"sydney402"}],"meta":[{"ip":"117.120.9.2","cn":"sydney402"}]}}]}
SIGNATURE-NOT-JSON`},
			[]string{"117.120.9.2", "117.120.9.5", "117.120.9.6"}, nil},
		{readAirVPN, map[string]string{"/": `{"servers":[{"public_name":"Acrux","country_name":"Australia","ip_v4_in1":"103.75.117.10","ip_v4_in2":"103.75.117.11",
			"ip_v6_in1":"2403:9fc0:6:1::a","ip_v4_out":"103.75.117.12","users":17,"health":"ok"}]}`},
			[]string{"103.75.117.10", "103.75.117.11", "103.75.117.12", "2403:9fc0:6:1::a"}, nil},
		{readPrivado, map[string]string{"/": `{"servers":[{"country":"Australia","city":"Sydney","hostname":"syd-001.vpn.privado.io","ip":"91.148.235.1"}]}`},
			[]string{"91.148.235.1"}, nil},
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			srv, _ := serveFiles(t, c.files)
			addrs, hosts, err := c.read(newCategoryBuilder(context.Background()), srv.URL+"/")
			require.NoError(t, err)
			require.ElementsMatch(t, c.addrs, addrs)
			require.Equal(t, c.hosts, hosts)
		})
	}
}

func TestReadWindscribeAddsACacheBreaker(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Write([]byte(`{"data":[{"name":"Australia","groups":[{"city":"Sydney","nodes":[
			{"hostname":"au-001.whiskergalaxy.com","ip":"103.77.234.1","ip2":"103.77.234.2","ip3":"103.77.234.3"}]}]}]}`))
	}))
	defer srv.Close()

	addrs, hosts, err := readWindscribe(newCategoryBuilder(context.Background()), srv.URL+"/serverlist/mob-v2/1/")
	require.NoError(t, err)
	require.Equal(t, []string{"103.77.234.1", "103.77.234.2", "103.77.234.3"}, addrs)
	require.Empty(t, hosts)
	require.Regexp(t, `^/serverlist/mob-v2/1/\d+$`, path)
}

func TestCategoryDBRecordsVPNLists(t *testing.T) {
	asOf := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("45.32.0.0/16", "cloud:vultr")
		b.addVPNServers("mullvad", VPNList{Source: "Mullvad relay API", Date: asOf}, []string{"45.32.1.1"})
		b.addVPNServers("hidemyass", VPNList{Source: "gluetun server list for hidemyass"}, []string{"45.32.1.2"})
	})

	require.Equal(t, map[string]VPNList{"vpn:mullvad": {Source: "Mullvad relay API", Date: asOf}},
		db.VPNLists(db.Lookup(net.ParseIP("45.32.1.1"), 0, false)))
	require.Equal(t, map[string]VPNList{"vpn:hidemyass": {Source: "gluetun server list for hidemyass"}},
		db.VPNLists(db.Lookup(net.ParseIP("45.32.1.2"), 0, false)), "a list without a date stays undated")
	require.Nil(t, db.VPNLists(db.Lookup(net.ParseIP("45.32.2.1"), 0, false)))
}

func TestOpenCategoryDBReadsDatabasesWithoutVPNLists(t *testing.T) {
	b := newCategoryBuilder(context.Background())
	b.addPrefix("45.32.1.1", "vpn:mullvad")
	data, err := b.Marshal()
	require.NoError(t, err)

	// Without the trailing count, this is a database from before VPN lists.
	path := filepath.Join(t.TempDir(), CategoryFilename)
	require.NoError(t, os.WriteFile(path, data[:len(data)-4], 0o644))
	db, err := OpenCategoryDB(path)
	require.NoError(t, err)
	require.Equal(t, "vpn:mullvad", db.Lookup(net.ParseIP("45.32.1.1"), 0, false))
	require.Nil(t, db.VPNLists("vpn:mullvad"))
}
