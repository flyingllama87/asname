package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	require.NoError(t, os.WriteFile(path, []byte(`# MaxMind
ASNAME_TEST_ACCOUNT=319
export ASNAME_TEST_KEY="abc def"
ASNAME_TEST_SET=from-file
PATH=/evil
not a line
`), 0o600))
	t.Setenv("ASNAME_TEST_SET", "from-env")
	for _, k := range []string{"ASNAME_TEST_ACCOUNT", "ASNAME_TEST_KEY"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}
	oldPath := os.Getenv("PATH")
	var warn bytes.Buffer
	loadEnvFile(path, &warn)
	require.Equal(t, "319", os.Getenv("ASNAME_TEST_ACCOUNT"))
	require.Equal(t, "abc def", os.Getenv("ASNAME_TEST_KEY"))
	require.Equal(t, "from-env", os.Getenv("ASNAME_TEST_SET"), "the environment wins")
	require.Equal(t, oldPath, os.Getenv("PATH"), "only ASNAME_ variables are set")
	require.Contains(t, warn.String(), ":5: expected")
	require.Contains(t, warn.String(), ":6: expected")
	require.NotContains(t, warn.String(), "read by others")

	require.NoError(t, os.Chmod(path, 0o644))
	warn.Reset()
	loadEnvFile(path, &warn)
	require.Contains(t, warn.String(), "read by others")

	warn.Reset()
	loadEnvFile(filepath.Join(t.TempDir(), "missing"), &warn)
	require.Empty(t, warn.String())
}
