package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/flyingllama87/asname/internal/sources"
)

func TestWithOnlineLeavesTheEngineAlone(t *testing.T) {
	e := NewTestEngine(t)
	v := e.WithOnline(Online{Whois: true, Prefixes: true})

	assert.Equal(t, sources.WhoisAlways, v.whois.Mode)
	assert.Equal(t, sources.WhoisAlways, v.onlinePrefixes.Mode)
	assert.True(t, v.showNetblock, "asking for whois shows the netblock")
	assert.Nil(t, e.whois, "the engine keeps its own askers")
	assert.False(t, e.showNetblock)
	assert.Same(t, e.asnReps, v.asnReps, "the view shares the ASN reputation cache")
}
