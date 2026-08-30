package engine

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/sources"
	"github.com/flyingllama87/asname/pkg/database"
)

// BuildTestDatabase creates an in-memory test database.
func BuildTestDatabase(t *testing.T, prefix string, value uint32) database.Database {
	t.Helper()

	_, ipNet, err := net.ParseCIDR(prefix)
	require.NoError(t, err)

	b := database.NewBuilder()
	require.NoError(t, b.InsertMapping(ipNet, value))
	db, err := b.Build()
	require.NoError(t, err)
	return db
}

// NewTestEngine creates a populated Engine for testing.
func NewTestEngine(t *testing.T) *Engine {
	t.Helper()

	return &Engine{
		db:        BuildTestDatabase(t, "8.8.8.0/24", 15169),
		names:     map[uint32]string{15169: "GOOGLE - Google LLC, US"},
		countryDB: BuildTestDatabase(t, "8.8.8.0/24", sources.EncodeCC("US")),
	}
}
