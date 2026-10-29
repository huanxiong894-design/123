package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"ctfagent/internal/llm"
)

var volatileOutputLine = regexp.MustCompile(`(?im)^(date|set-cookie|content-length|x-request-id|request-id|trace-id|span-id):.*$`)
var elapsedOutput = regexp.MustCompile(`(?i)用时=[^\r\n]+`)

func canonicalToolCall(tc llm.ToolCall) string {
	var value any
	if json.Unmarshal([]byte(tc.Args), &value) == nil {
		if b, err := json.Marshal(value); err == nil {
			return tc.Name + "\x00" + string(b)
		}
	}
	return tc.Name + "\x00" + strings.TrimSpace(tc.Args)
}

func toolScopeKey(tc llm.ToolCall) string {
	var args map[string]any
	_ = json.Unmarshal([]byte(tc.Args), &args)
	for _, key := range []string{"url", "host", "endpoint"} {
		v, _ := args[key].(string)
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			u.RawQuery, u.Fragment = "", ""
			return tc.Name + ":" + strings.ToLower(u.Scheme+"://"+u.Host+u.EscapedPath())
		}
		return tc.Name + ":" + strings.ToLower(v)
	}
	return tc.Name
}

func outputFingerprint(output string) string {
	output = strings.ReplaceAll(output, "\r\n", "\n")
	output = volatileOutputLine.ReplaceAllString(output, "")
	output = elapsedOutput.ReplaceAllString(output, "用时=<elapsed>")
	lines := strings.Split(output, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	flat := strings.Join(lines, "\n")
	sum := sha256.Sum256([]byte(flat))
	return hex.EncodeToString(sum[:])
}
