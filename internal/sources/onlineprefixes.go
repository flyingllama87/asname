package sources

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const OnlinePrefixConsentFilename = "online-prefixes-consent.json"

// PrefixAsker decides whether an ASN missing from the offline prefix database
// may be looked up on RIPEstat. It follows WhoisAsker: WhoisAlways and
// WhoisNever are fixed answers, and WhoisAsk asks once on a terminal and
// remembers the answer for WhoisConsentTTL.
type PrefixAsker struct {
	Path     string
	Mode     WhoisMode
	Out      io.Writer
	In       io.Reader
	Terminal bool

	decided bool
	allow   bool
}

func NewPrefixAsker(path string, mode WhoisMode) *PrefixAsker {
	return &PrefixAsker{
		Path:     path,
		Mode:     mode,
		Out:      os.Stderr,
		In:       os.Stdin,
		Terminal: isTerminal(os.Stdin),
	}
}

func (a *PrefixAsker) Allowed(asn uint32) bool {
	if a == nil || a.Mode == WhoisNever {
		return false
	}
	if a.decided {
		return a.allow
	}
	a.decided = true

	if a.Mode == WhoisAlways {
		a.allow = true
		return true
	}

	if consent, ok := LoadWhoisConsent(a.Path); ok {
		a.allow = consent.Allow
		return a.allow
	}

	if !a.Terminal {
		fmt.Fprintf(a.Out, "asname: AS%d has no offline prefixes; pass --online-prefixes to ask RIPEstat for them\n", asn)
		a.allow = false
		return false
	}

	a.allow = a.ask(asn)
	if err := SaveWhoisConsent(a.Path, a.allow); err != nil {
		fmt.Fprintln(a.Out, "asname: could not remember that answer:", err)
	}
	return a.allow
}

func (a *PrefixAsker) ask(asn uint32) bool {
	fmt.Fprintf(a.Out, "asname: AS%d announces nothing in the offline prefix database. Ask RIPEstat\n", asn)
	fmt.Fprintf(a.Out, "asname: (stat.ripe.net) over the network for the prefixes of ASNs like it?\n")
	fmt.Fprintf(a.Out, "asname: Either answer is remembered for an hour. [y/N] ")

	line, err := bufio.NewReader(a.In).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(a.Out)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
