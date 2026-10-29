package kernel

import (
	"testing"

	"ctfagent/internal/llm"
)

func TestOutputFingerprintIgnoresVolatileMetadata(t *testing.T) {
	a := "HTTP 200\nDate: Mon, 01 Jan 2024 00:00:00 GMT\n用时=4ms\nX-Request-ID: abc\nbody"
	b := "HTTP 200\nDate: Tue, 02 Jan 2024 00:00:00 GMT\n用时=9ms\nX-Request-ID: xyz\nbody"
	if outputFingerprint(a) != outputFingerprint(b) {
		t.Fatal("volatile headers/timing should not create a false-new response")
	}
	if outputFingerprint(a) == outputFingerprint(b+" changed") {
		t.Fatal("meaningful body change should change fingerprint")
	}
}

func TestCanonicalToolCallIgnoresJSONKeyOrder(t *testing.T) {
	a := llm.ToolCall{Name: "http", Args: `{"url":"http://example.invalid","method":"GET"}`}
	b := llm.ToolCall{Name: "http", Args: `{"method":"GET","url":"http://example.invalid"}`}
	if canonicalToolCall(a) != canonicalToolCall(b) {
		t.Fatal("JSON field order should not defeat duplicate detection")
	}
}
