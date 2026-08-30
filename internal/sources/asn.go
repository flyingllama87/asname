package sources

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DirEnvVar      = "ASNAME_DIR"
	DBEnvVar       = "ASNAME_DB"
	NamesEnvVar    = "ASNAME_NAMES"
	DefaultMaxAge  = 30 * 24 * time.Hour
	DBFilename     = "asname.db"
	NamesFilename  = "asn_db.txt"
	DefaultDirName = ".asname"
)

// Config bundles the resolved file locations for a run.
type Config struct {
	DBPath       string
	NamesPath    string
	CountryPath  string
	CityPath     string
	NetblockPath string
	CategoryPath string
	ConsentPath  string
	ContactPath  string
}

func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return DefaultDirName
	}
	return filepath.Join(home, DefaultDirName)
}

// LoadNames reads an ASN->name mapping file.
func LoadNames(path string) (map[uint32]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	names := make(map[uint32]string)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		token, rest, ok := SplitFirstField(line)
		if !ok {
			continue
		}
		num, err := ParseASNToken(token)
		if err != nil {
			continue
		}
		names[num] = strings.TrimSpace(rest)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

// WriteNamesFromRIPE converts the RIPE asn.txt stream into padded format.
func WriteNamesFromRIPE(r io.Reader, w io.Writer) (int, error) {
	bw := bufio.NewWriter(w)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		token, name, ok := SplitFirstField(line)
		if !ok {
			continue
		}
		if _, err := strconv.ParseUint(token, 10, 32); err != nil {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, err := fmt.Fprintf(bw, "%-14s%s\n", "AS"+token, name); err != nil {
			return count, err
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, err
	}
	return count, bw.Flush()
}

// SplitFirstField splits s into its first whitespace-delimited field and the remainder.
func SplitFirstField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		if s == "" {
			return "", "", false
		}
		return s, "", true
	}
	return s[:i], strings.TrimLeft(s[i:], " \t"), true
}

// ParseASNToken parses an "AS15169" or "15169" token into its numeric value.
func ParseASNToken(token string) (uint32, error) {
	token = strings.TrimPrefix(strings.ToUpper(token), "AS")
	num, err := strconv.ParseUint(token, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(num), nil
}
