package safety

import (
	"strings"
	"testing"
)

func TestRedactSensitiveText(t *testing.T) {
	input := "Authorization: Bearer header-secret\nX-Session-Token: header-session-secret\n" +
		`{"password":"db-secret","session_token":"json-session-secret","session_id":"session-id-secret","csrf_token":"csrf-secret","Authorization":"Bearer json-bearer-secret","access_token":"eyJhbGci.eyJzdWg.dGVzdA","ok":"visible"}` +
		" https://example.test/?session_token=query-session-secret&csrf_token=query-csrf-secret&sig=signed-secret flag{01234567-89ab-cdef-0123-456789abcdef}"
	got := RedactSensitiveText(input)
	for _, secret := range []string{"header-secret", "header-session-secret", "db-secret", "json-session-secret", "session-id-secret", "csrf-secret", "json-bearer-secret", "eyJhbGci", "query-session-secret", "query-csrf-secret", "signed-secret", "flag{"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q leaked in %q", secret, got)
		}
	}
	if !strings.Contains(got, "visible") || !strings.Contains(got, "[REDACTED") {
		t.Fatalf("redaction removed useful context or did not mark redaction: %q", got)
	}
}

func TestRedactNonSensitiveTextUnchanged(t *testing.T) {
	input := `{"bucket":"infra-artifacts","key":"terraform/prod.tfstate","status_code":200}`
	if got := RedactSensitiveText(input); got != input {
		t.Fatalf("non-sensitive text changed: %q", got)
	}
}
