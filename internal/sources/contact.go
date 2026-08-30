package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	ContactFilename = "contact.json"
	ContactEnvVar   = "ASNAME_CONTACT_EMAIL"
)

// Version is stamped in at build time or defaults to "dev".
var Version = "dev"

type contactRecord struct {
	Email string    `json:"email"`
	Asked time.Time `json:"asked"`
}

type ContactAsker struct {
	Path     string
	Override string
	Out      io.Writer
	In       io.Reader
	Terminal bool

	decided bool
	email   string
}

func NewContactAsker(path, override string) *ContactAsker {
	return &ContactAsker{
		Path:     path,
		Override: override,
		Out:      os.Stderr,
		In:       os.Stdin,
		Terminal: isTerminal(os.Stdin),
	}
}

func (a *ContactAsker) Contact() (string, bool) {
	if a.decided {
		return a.email, a.email != ""
	}
	a.decided = true

	if a.Override != "" {
		if !ValidContactEmail(a.Override) {
			fmt.Fprintf(a.Out, "asname: %q does not look like an email address, skipping bgp.tools\n", a.Override)
			return "", false
		}
		a.email = a.Override
		return a.email, true
	}

	if record, ok := LoadContact(a.Path); ok {
		a.email = record.Email
		return a.email, a.email != ""
	}

	if !a.Terminal {
		fmt.Fprintf(a.Out, "asname: bgp.tools wants a contact address and there is no terminal to ask on;\n")
		fmt.Fprintf(a.Out, "asname: set %s to include its operator tags\n", ContactEnvVar)
		return "", false
	}

	a.email = a.ask()
	if err := SaveContact(a.Path, a.email); err != nil {
		fmt.Fprintln(a.Out, "asname: could not remember that answer:", err)
	}
	if a.email == "" {
		fmt.Fprintf(a.Out, "asname: building without bgp.tools tags; set %s, or delete\n", ContactEnvVar)
		fmt.Fprintf(a.Out, "asname: %s, to be asked again\n", a.Path)
	}
	return a.email, a.email != ""
}

func (a *ContactAsker) ask() string {
	fmt.Fprintf(a.Out, "asname: some of the categories (hosting, ISP, VPN, CDN) come from bgp.tools,\n")
	fmt.Fprintf(a.Out, "asname: which asks that clients identify themselves with a contact address so\n")
	fmt.Fprintf(a.Out, "asname: they can get in touch if a client misbehaves. It is sent to bgp.tools\n")
	fmt.Fprintf(a.Out, "asname: alone, in the User-Agent header, and to none of the other sources.\n")

	reader := bufio.NewReader(a.In)
	for range 3 {
		fmt.Fprintf(a.Out, "asname: Contact email (blank to skip bgp.tools): ")
		line, err := reader.ReadString('\n')
		answer := strings.TrimSpace(line)
		if answer == "" {
			return ""
		}
		if ValidContactEmail(answer) {
			return answer
		}
		fmt.Fprintf(a.Out, "asname: %q does not look like an email address.\n", answer)
		if err != nil {
			return ""
		}
	}
	return ""
}

func ValidContactEmail(s string) bool {
	if len(s) < 6 || len(s) > 254 {
		return false
	}
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

func LoadContact(path string) (contactRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contactRecord{}, false
	}
	var record contactRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return contactRecord{}, false
	}
	if record.Email != "" && !ValidContactEmail(record.Email) {
		return contactRecord{}, false
	}
	return record, true
}

func SaveContact(path, email string) error {
	data, err := json.Marshal(contactRecord{Email: email, Asked: time.Now().UTC()})
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func BGPToolsUserAgent(email string) string {
	return fmt.Sprintf("asname/%s bgp.tools - %s", Version, email)
}
