package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// bgp.tools publishes the operator tags the category database leans on for
// everything no provider ships a range file for, and asks in return that
// clients identify themselves with a contact address rather than a default
// user agent. So asname asks for one, once, the first time it needs it.
//
// The address goes to bgp.tools and nowhere else: every other source is fetched
// with the plain user agent, since none of them asked and handing a personal
// email to a dozen unrelated hosts is not a fair trade for a tag.
const (
	contactFilename = "contact.json"
	contactEnvVar   = "ASNAME_CONTACT_EMAIL"
)

// contactRecord is the remembered answer, stored beside the databases.
type contactRecord struct {
	// Email is empty when the user declined, which is remembered so that the
	// question is asked once rather than on every build.
	Email string    `json:"email"`
	Asked time.Time `json:"asked"`
}

// contactAsker resolves the contact address for a build, from a flag, the
// environment, a remembered answer, or the user.
type contactAsker struct {
	path     string
	override string // --contact-email or ASNAME_CONTACT_EMAIL
	out      io.Writer
	in       io.Reader
	terminal bool

	decided bool
	email   string
}

func newContactAsker(path, override string) *contactAsker {
	return &contactAsker{
		path:     path,
		override: override,
		out:      os.Stderr,
		in:       os.Stdin,
		terminal: isTerminal(os.Stdin),
	}
}

// contact returns the address to identify with, and whether there is one. A
// build with no address simply leaves the bgp.tools sources out.
func (a *contactAsker) contact() (string, bool) {
	if a.decided {
		return a.email, a.email != ""
	}
	a.decided = true

	if a.override != "" {
		if !validContactEmail(a.override) {
			fmt.Fprintf(a.out, "asname: %q does not look like an email address, skipping bgp.tools\n", a.override)
			return "", false
		}
		a.email = a.override
		return a.email, true
	}

	if record, ok := loadContact(a.path); ok {
		a.email = record.Email
		return a.email, a.email != ""
	}

	if !a.terminal {
		fmt.Fprintf(a.out, "asname: bgp.tools wants a contact address and there is no terminal to ask on;\n")
		fmt.Fprintf(a.out, "asname: set %s to include its operator tags\n", contactEnvVar)
		return "", false
	}

	a.email = a.ask()
	if err := saveContact(a.path, a.email); err != nil {
		fmt.Fprintln(a.out, "asname: could not remember that answer:", err)
	}
	if a.email == "" {
		fmt.Fprintf(a.out, "asname: building without bgp.tools tags; set %s, or delete\n", contactEnvVar)
		fmt.Fprintf(a.out, "asname: %s, to be asked again\n", a.path)
	}
	return a.email, a.email != ""
}

// ask puts the question, and keeps asking while the answer is malformed.
func (a *contactAsker) ask() string {
	fmt.Fprintf(a.out, "asname: some of the categories (hosting, ISP, VPN, CDN) come from bgp.tools,\n")
	fmt.Fprintf(a.out, "asname: which asks that clients identify themselves with a contact address so\n")
	fmt.Fprintf(a.out, "asname: they can get in touch if a client misbehaves. It is sent to bgp.tools\n")
	fmt.Fprintf(a.out, "asname: alone, in the User-Agent header, and to none of the other sources.\n")

	reader := bufio.NewReader(a.in)
	for range 3 {
		fmt.Fprintf(a.out, "asname: Contact email (blank to skip bgp.tools): ")
		line, err := reader.ReadString('\n')
		answer := strings.TrimSpace(line)
		if answer == "" {
			return ""
		}
		if validContactEmail(answer) {
			return answer
		}
		fmt.Fprintf(a.out, "asname: %q does not look like an email address.\n", answer)
		if err != nil {
			return ""
		}
	}
	return ""
}

// validContactEmail is a deliberately loose check: the address only has to be
// something a human could be reached at and something safe to put in a header,
// so it rejects the shapes that are certainly wrong rather than trying to
// decide which addresses are real.
func validContactEmail(s string) bool {
	if len(s) < 6 || len(s) > 254 {
		return false
	}
	// A newline here would let the rest of the User-Agent be forged into extra
	// headers, so anything that is not printable ASCII is out.
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	dot := strings.LastIndex(domain, ".")
	return dot > 0 && dot < len(domain)-1
}

func loadContact(path string) (contactRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contactRecord{}, false
	}
	var record contactRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return contactRecord{}, false
	}
	// An address that has somehow become malformed is worth asking about
	// again rather than sending as-is.
	if record.Email != "" && !validContactEmail(record.Email) {
		return contactRecord{}, false
	}
	return record, true
}

func saveContact(path, email string) error {
	data, err := json.Marshal(contactRecord{Email: email, Asked: time.Now().UTC()})
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// bgpToolsUserAgent is the identification bgp.tools asks for, in the format
// their documentation suggests.
func bgpToolsUserAgent(email string) string {
	return fmt.Sprintf("asname/%s bgp.tools - %s", version, email)
}
