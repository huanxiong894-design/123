package kernel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"ctfagent/internal/llm"
)

// targetScopeError checks the direct network destinations exposed by structured
// tools. It deliberately does not inspect SSRF values embedded in request bodies:
// those are application inputs to the explicitly authorized target endpoint.
// Shell/Python networking remains subject to the sandbox network policy and prompt.
func targetScopeError(tc llm.ToolCall, allowed []string) string {
	if len(allowed) == 0 {
		return ""
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(tc.Args), &args); err != nil {
		return ""
	}
	checkURL := func(label, raw string) string {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return ""
		}
		// tunnel.finish accepts either a bare URL or a request line such as
		// "GET https://target/retrieve?session={session}".
		if label == "finish" {
			parts := strings.Fields(raw)
			if len(parts) > 1 && !strings.Contains(parts[0], "://") {
				raw = strings.Join(parts[1:], " ")
			}
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Sprintf("范围检查拒绝 %s：需要有效的 http(s) URL", label)
		}
		if !authorizedURL(u, allowed) {
			return fmt.Sprintf("范围检查拒绝 %s：目标 %q 不在本题授权目标/端口范围中（仅允许：%s）", label, u.Host, strings.Join(allowed, ", "))
		}
		return ""
	}
	checkHost := func(label, raw string) string {
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		host := strings.TrimSpace(raw)
		if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		} else if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else {
			host = strings.Trim(host, "[]")
		}
		if !authorizedHost(host, allowed) {
			return fmt.Sprintf("范围检查拒绝 %s：主机 %q 不在本题授权目标中（仅允许：%s）", label, host, strings.Join(allowed, ", "))
		}
		return ""
	}
	getString := func(key string) string {
		v, _ := args[key].(string)
		return v
	}

	switch tc.Name {
	case "http", "recon", "fuzz", "paramfuzz":
		return checkURL("url", getString("url"))
	case "ports":
		if msg := checkHost("host", getString("host")); msg != "" {
			return msg
		}
		if !authorizedPortScan(getString("host"), getString("ports"), allowed) {
			return fmt.Sprintf("范围检查拒绝 ports=%q：超出本题明确授权的目标端口", getString("ports"))
		}
	case "raw", "fcgi":
		if msg := checkHost("host", getString("host")); msg != "" {
			return msg
		}
		port := 0
		if n, ok := args["port"].(float64); ok {
			port = int(n)
		}
		if tc.Name == "fcgi" && port == 0 {
			port = 9000
		}
		if port > 0 && !authorizedEndpointPort(getString("host"), port, allowed) {
			return fmt.Sprintf("范围检查拒绝端口 %d：不在本题授权目标中", port)
		}
	case "tunnel":
		for _, key := range []string{"source", "endpoint", "finish"} {
			if msg := checkURL(key, getString(key)); msg != "" {
				return msg
			}
		}
	}
	return ""
}

func parseTargetAuthority(raw string) (host, port string, portBound bool) {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		host = u.Hostname()
		port = u.Port()
		if port != "" {
			return host, port, true
		}
		switch strings.ToLower(u.Scheme) {
		case "http":
			return host, "80", true
		case "https":
			return host, "443", true
		default:
			return host, "", false
		}
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return h, p, true
	}
	return strings.Trim(raw, "[]"), "", false
}

func authorizedEndpointPort(rawHost string, port int, allowed []string) bool {
	host, _, _ := parseTargetAuthority(rawHost)
	host = normalizeHost(host)
	for _, raw := range allowed {
		targetHost, targetPort, bound := parseTargetAuthority(raw)
		if host == normalizeHost(targetHost) && (!bound || targetPort == strconv.Itoa(port)) {
			return true
		}
	}
	return false
}

func authorizedPortScan(rawHost, spec string, allowed []string) bool {
	host, _, _ := parseTargetAuthority(rawHost)
	host = normalizeHost(host)
	allowedPorts := map[int]bool{}
	portBound := false
	for _, raw := range allowed {
		targetHost, targetPort, bound := parseTargetAuthority(raw)
		if host != normalizeHost(targetHost) {
			continue
		}
		if !bound {
			return true // host-only authorization permits the tool's bounded scan choices
		}
		portBound = true
		if n, err := strconv.Atoi(targetPort); err == nil {
			allowedPorts[n] = true
		}
	}
	if !portBound {
		return true
	}
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "quick" || spec == "all" {
		return false
	}
	for _, item := range strings.Split(spec, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "-", 2)
		lo, err := strconv.Atoi(parts[0])
		if err != nil || lo < 1 || lo > 65535 {
			return false
		}
		hi := lo
		if len(parts) == 2 {
			hi, err = strconv.Atoi(parts[1])
			if err != nil || hi < lo || hi > 65535 {
				return false
			}
		}
		for p := lo; p <= hi; p++ {
			if !allowedPorts[p] {
				return false
			}
		}
	}
	return true
}

func authorizedURL(target *url.URL, allowed []string) bool {
	host := normalizeHost(target.Hostname())
	port := target.Port()
	if port == "" {
		switch strings.ToLower(target.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if host == "" {
		return false
	}
	for _, raw := range allowed {
		candidate := strings.TrimSpace(raw)
		targetPort := ""
		portBound := false
		if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
			candidate = u.Hostname()
			targetPort = u.Port()
			if targetPort != "" {
				portBound = true
			} else if u.Scheme == "http" {
				targetPort, portBound = "80", true
			} else if u.Scheme == "https" {
				targetPort, portBound = "443", true
			}
		} else if h, p, err := net.SplitHostPort(candidate); err == nil {
			candidate, targetPort, portBound = h, p, true
		} else {
			candidate = strings.Trim(candidate, "[]")
		}
		if host == normalizeHost(candidate) && (!portBound || targetPort == port) {
			return true
		}
	}
	return false
}

func authorizedHost(host string, allowed []string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, raw := range allowed {
		candidate := strings.TrimSpace(raw)
		if u, err := url.Parse(candidate); err == nil && u.Hostname() != "" {
			candidate = u.Hostname()
		} else if h, _, err := net.SplitHostPort(candidate); err == nil {
			candidate = h
		} else {
			candidate = strings.Trim(candidate, "[]")
		}
		if host == normalizeHost(candidate) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	host = strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}
