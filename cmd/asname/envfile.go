package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The settings file holds ASNAME_* variables that would otherwise have to be
// exported in every shell and service: account keys (MaxMind, ARIN), a
// contact address. It is read at startup; a variable already set in the
// environment wins. Lines are NAME=value, '#' starts a comment, and quotes
// around a value are dropped.

// EnvFileVar names an env file to read instead of the default one.
const EnvFileVar = "ASNAME_ENV_FILE"

// envFilePath is $ASNAME_ENV_FILE, else $XDG_CONFIG_HOME/asname/env, else
// ~/.config/asname/env.
func envFilePath() string {
	if p := os.Getenv(EnvFileVar); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "asname", "env")
}

// loadEnvFile sets the ASNAME_* variables in the file at path that the
// environment does not already set. A missing file is fine. Problems are
// reported to warn and do not stop asname.
func loadEnvFile(path string, warn io.Writer) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		fmt.Fprintf(warn, "asname: reading %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(warn, "asname: warning: %s can be read by others; it may hold keys (chmod 600 %s)\n", path, path)
	}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || !strings.HasPrefix(name, "ASNAME_") || strings.ContainsAny(name, " \t") {
			fmt.Fprintf(warn, "asname: %s:%d: expected ASNAME_NAME=value\n", path, n)
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if _, set := os.LookupEnv(name); !set {
			os.Setenv(name, value)
		}
	}
}
