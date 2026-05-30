package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// loadNames reads an ASN->name mapping file. Each line is expected to start
// with an "AS<number>" token followed by the AS name, e.g.:
//
//	AS15169       GOOGLE - Google LLC, US
//
// Padding between the token and the name is irrelevant; anything after the
// first whitespace-delimited token is taken as the name.
func loadNames(path string) (map[uint32]string, error) {
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
		token, rest, ok := splitFirstField(line)
		if !ok {
			continue
		}
		num, err := parseASNToken(token)
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

// writeNamesFromRIPE converts the RIPE asn.txt stream (lines of "<number>
// <name>") into our padded "AS<number> <name>" format and writes it to w.
func writeNamesFromRIPE(r io.Reader, w io.Writer) (int, error) {
	bw := bufio.NewWriter(w)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		token, name, ok := splitFirstField(line)
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
		// Keep the column layout of the legacy asn_db.txt so the file stays
		// human-readable and greppable.
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

// splitFirstField splits s into its first whitespace-delimited field and the
// remainder. ok is false when s has no field.
func splitFirstField(s string) (field, rest string, ok bool) {
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

// parseASNToken parses an "AS15169" or "15169" token into its numeric value.
func parseASNToken(token string) (uint32, error) {
	token = strings.TrimPrefix(strings.ToUpper(token), "AS")
	num, err := strconv.ParseUint(token, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(num), nil
}
