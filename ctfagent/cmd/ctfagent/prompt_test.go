package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ctfagent/internal/kernel"
)

func TestNewTracerRedactsSensitiveFieldsAndUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	trace, closeTrace, err := newTracer(path)
	if err != nil {
		t.Fatal(err)
	}
	trace(kernel.TraceEvent{
		Kind:   "tool",
		Args:   `{"headers":{"Authorization":"Bearer trace-secret","X-Session-Token":"session-header-secret"}}`,
		Output: `{"password":"db-secret","session_token":"session-json-secret","flag":"flag{abcdef}"}`,
	})
	closeTrace()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"trace-secret", "session-header-secret", "db-secret", "session-json-secret", "flag{"} {
		if strings.Contains(text, secret) {
			t.Fatalf("trace leaked %q: %s", secret, text)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("trace mode=%o, want 600", info.Mode().Perm())
	}
}
