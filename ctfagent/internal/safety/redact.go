// Package safety provides conservative redaction helpers for persisted or previewed data.
package safety

import "regexp"

var (
	secretJSON   = regexp.MustCompile(`(?i)(["']?(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|session(?:[_-]?(?:id|token|key|cookie))?|csrf[_-]?(?:token)?|xsrf[_-]?token|password|passwd|secret(?:[_-]?key)?|access[_-]?key|(?:access|refresh|id)[_-]?token|client[_-]?secret|api[_-]?key|device[_-]?code|sas[_-]?token|signature|private[_-]?key|aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|database[_-]?password|minio[_-]?root[_-]?(?:user|password))["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^"'&,\s}\]]+)`)
	secretHeader = regexp.MustCompile(`(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-session-token|x-session-id|x-csrf-token|x-xsrf-token)\s*:\s*).+$`)
	secretQuery  = regexp.MustCompile(`(?i)([?&](?:access_token|refresh_token|id_token|session(?:_id|_token)?|csrf(?:_token)?|xsrf_token|token|sig|signature|code|password|secret|api_key|sas_token)=)([^&#\s]+)`)
	jwtToken     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`)
	flagValue    = regexp.MustCompile(`(?i)\bflag\{[^}\r\n]+\}`)
)

// RedactSensitiveText masks common credentials, bearer tokens and CTF flags.
// It is intended for logs, mailbox previews and traces, never for live solver evidence.
func RedactSensitiveText(s string) string {
	s = secretHeader.ReplaceAllString(s, `${1}[REDACTED]`)
	s = secretJSON.ReplaceAllString(s, `${1}"[REDACTED]"`)
	s = secretQuery.ReplaceAllString(s, `${1}[REDACTED]`)
	s = jwtToken.ReplaceAllString(s, `[REDACTED_JWT]`)
	s = flagValue.ReplaceAllString(s, `[REDACTED_FLAG]`)
	return s
}
