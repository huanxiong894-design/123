package kernel

// 内置大字典（embed）。
// 经验：手工列的几十个词远远不够——真实参数名经常排在公开词典的 1000 名开外，
// 所以内置的是「公开词表 + 通用命名约定」的大集合，而不是某道题的答案。

import (
	"embed"
	"sort"
	"strings"
	"sync"
)

//go:embed prompts/wordlists/*.txt
var wordlistFS embed.FS

var wordlistCache = map[string][]string{}

// loadEmbeddedWordlist 读取内置字典：
//
//	params / dirs / traversal / ssti / cmdi / cmdi-bypass / sqli / ssrf-hosts
func loadEmbeddedWordlist(name string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	if xs, ok := wordlistCache[name]; ok {
		return xs
	}
	raw, err := wordlistFS.ReadFile("prompts/wordlists/" + name + ".txt")
	if err != nil {
		return nil
	}
	var xs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		w := strings.TrimSpace(line)
		if w == "" || strings.HasPrefix(w, "#") || seen[w] {
			continue
		}
		seen[w] = true
		xs = append(xs, w)
	}
	wordlistCache[name] = xs
	return xs
}

// subdomainWordlist 子域/主机名字典：把 params 里的「服务名」类词与常见内网名组合。
func subdomainWordlist() []string {
	base := []string{
		"internal-api", "admin-api", "web", "api", "internal", "admin", "backend",
		"db", "mysql", "redis", "cache", "mongo", "postgres", "internal-db",
		"gateway", "proxy", "nginx", "app", "service", "svc", "auth", "sso",
		"flag", "flags", "secret", "metadata", "log", "logs", "monitor",
		"metrics", "storage", "file", "files", "static", "cdn", "queue",
		"worker", "task", "scheduler", "console", "panel", "manage", "ops",
	}
	seen := map[string]bool{}
	var out []string
	for _, b := range base {
		for _, cand := range []string{b, "internal-" + b, b + "-service", b + "-server", b + "-api"} {
			if !seen[cand] {
				seen[cand] = true
				out = append(out, cand)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// 复合参数名生成
// ---------------------------------------------------------------------------
// 公开词典只收"单词"（url / file / target），但真实接口大量使用 <名词>_<类别>
// 的复合命名（xxx_url / xxx_endpoint / xxx_path）。这是**命名约定**，与具体题目无关，
// 所以用组合规则现场生成，而不是把某道题里见过的名字塞进字典。

var compoundPrefix = []string{
	"target", "callback", "redirect", "file", "upload", "download", "image", "avatar",
	"api", "webhook", "notify", "return", "next", "source", "dest", "remote", "server",
	"proxy", "fetch", "sync", "import", "export", "data", "resource", "link", "media",
	"asset", "partner", "vendor", "provider", "feed", "report", "log", "archive",
	"backup", "storage", "template", "render", "preview", "thumb", "site", "base",
	"service", "upstream", "internal", "admin", "user", "share", "public",
}

var compoundSuffix = []string{
	"url", "uri", "endpoint", "path", "file", "host", "addr", "address", "name", "id",
	"key", "token", "link", "src", "dest", "dir", "folder", "domain", "port",
}

var compoundOnce struct {
	sync.Once
	xs []string
}

// expandCompoundParams 生成 <prefix>_<suffix> 形式的候选名（去重，约 800 个）。
func expandCompoundParams() []string {
	compoundOnce.Do(func() {
		seen := make(map[string]bool, 1024)
		var out []string
		for _, p := range compoundPrefix {
			for _, suf := range compoundSuffix {
				w := p + "_" + suf
				if !seen[w] {
					seen[w] = true
					out = append(out, w)
				}
			}
		}
		compoundOnce.xs = out
	})
	return compoundOnce.xs
}
