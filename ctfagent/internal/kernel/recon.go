package kernel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
)

// ---------------------------------------------------------------------------
// 侦察工具：把「指纹 + 目录爆破 + 敏感文件」压成一次调用。
// 设计目标：减少一次 solve 的往返轮次（每一步都是一次模型调用，往返最贵）。
// ---------------------------------------------------------------------------

var defaultPaths = []string{
	// 常规入口
	"", "index.php", "index.html", "admin", "admin/", "login", "login/", "dashboard",
	"api", "api/", "api/v1", "api/v1/", "v1", "v2", "graphql", "rest", "console",
	// 框架/中间件特征
	"actuator", "actuator/env", "actuator/health", "swagger-ui.html", "swagger-ui/",
	"swagger.json", "openapi.json", "api-docs", "docs", "redoc", ".well-known/security.txt",
	"server-status", "phpinfo.php", "info.php", "test.php", "debug",
	// 备份/源码泄露
	".git/HEAD", ".git/config", ".svn/entries", ".DS_Store", ".env", ".env.bak",
	"www.zip", "www.tar.gz", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
	"dump.sql", "data.sql", "config.php.bak", "index.php.bak", "index.php~",
	"robots.txt", "sitemap.xml", "crossdomain.xml", "web.config", "composer.json",
	"package.json", "Dockerfile", "docker-compose.yml", "Makefile", "README.md",
	// 常见业务路径
	"upload", "uploads", "upload.php", "download", "download.php", "download/",
	"file", "files", "static", "assets", "js", "css", "images", "img", "media",
	"user", "users", "profile", "account", "register", "signup", "logout",
	"search", "query", "list", "export", "import", "report", "reports",
	"config", "settings", "system", "status", "health", "metrics", "monitor",
	// 通用 flag 落点（任何平台都可能出现；平台自己的约定由 meta.flag_paths 注入）
	"flag", "flag.txt", "flag.md", "FLAG", "flag/", "flag.php", "getflag",
	"secret", "secret.txt", "secrets", "private",
	// 源码/构建脚本（源码在手比盲打快十倍）
	"src", "source", "app.py", "main.py", "wsgi.py", "application.py", "server.py",
	"hint.txt", "start.sh", "entrypoint.sh", "docker-entrypoint.sh", "run.sh",
	"debug/vars", "debug/config", "debug/pprof", "api/services/status", "api/status",
	// REST 端点形状
	"api/track", "api/tasks", "api/tasks/recent", "api/services", "api/import", "api/export",
	"api/config", "api/info", "api/list", "api/query", "api/sync", "api/proxy",
	"api/admin", "api/admin/info", "api/internal", "api/internal/archive",
	"api/v2/fetch", "api/v1/user", "api/v1/users", "api/v1/status",
	"admin/info", "admin/config", "admin/users", "admin/logs", "admin/status", "admin/token",
	// 文件系统线索
	"proc/self/environ", "keys/", "keys/prod.key", "config/prod.key",
	// 常见漏洞点
	"proxy", "fetch", "redirect", "url", "load", "include", "read", "preview",
	"comment", "feedback", "message", "notice", "news", "article", "detail",
	"admin/login", "admin/index.php", "manage", "manager", "backend", "cms",
	"wp-admin", "wp-login.php", "administrator", "phpmyadmin", "pma",
	"shell", "cmd", "exec", "run", "eval", "ping", "check", "diagnose", "tool",
}

type probeResult struct {
	path   string
	status int
	size   int
	ctype  string
	loc    string
}

func (t *ToolSet) doRecon(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		URL      string   `json:"url"`
		Paths    []string `json:"paths"`
		Wordlist string   `json:"wordlist"` // 可选：dirs（内置 ~4700 条大字典）
		Threads  int      `json:"threads"`
		TimeoutS int      `json:"timeout_s"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	base := strings.TrimRight(strings.TrimSpace(a.URL), "/")
	if base == "" {
		return "url 不能为空"
	}
	paths := defaultPaths
	// 平台可以在 Challenge.Meta["flag_paths"]（逗号/空格分隔）里声明本平台的 flag 约定位置。
	// 这些路径排在最前面：它们是「平台契约」，不是某道题的答案。
	if extra := platformFlagPaths(t.board); len(extra) > 0 {
		paths = append(append([]string{}, extra...), paths...)
	}
	if len(a.Paths) > 0 {
		paths = a.Paths
	} else if strings.TrimSpace(a.Wordlist) != "" {
		if extra := loadEmbeddedWordlist(a.Wordlist); len(extra) > 0 {
			// 大字典模式：把内置快速表放前面（高价值路径优先出结果），再接全量字典
			seen := make(map[string]bool, len(defaultPaths)+len(extra))
			merged := make([]string, 0, len(defaultPaths)+len(extra))
			for _, p := range defaultPaths {
				if !seen[p] {
					seen[p] = true
					merged = append(merged, p)
				}
			}
			for _, p := range extra {
				if !seen[p] {
					seen[p] = true
					merged = append(merged, p)
				}
			}
			paths = merged
		}
	}
	threads := a.Threads
	if threads <= 0 {
		threads = 24
	}
	to := secs(a.TimeoutS)
	if to <= 0 {
		to = 8 * time.Second
	}
	client := &http.Client{
		Timeout: to,
		Jar:     t.jar, // share the authenticated session established by http calls
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不要把 302 跟成 200，跳转本身就是情报
		},
	}

	// 1) 指纹
	var b strings.Builder
	baseRes := probe(ctx, client, base)
	fmt.Fprintf(&b, "== 指纹 ==\nGET %s -> %d %dB %s\n", base, baseRes.status, baseRes.size, baseRes.ctype)
	if body, hdr := fetch(ctx, client, base); body != "" {
		fmt.Fprintf(&b, "server=%s powered=%s\n", hdr.Get("Server"), hdr.Get("X-Powered-By"))
		fmt.Fprintf(&b, "title=%s\n", pageTitle(body))
		if hints := techHints(body, hdr); len(hints) > 0 {
			fmt.Fprintf(&b, "技术线索=%s\n", strings.Join(hints, ", "))
		}
		fmt.Fprintf(&b, "首页片段=%.240s\n", oneLine(body))
	}

	// 1.5) 假 200 基线：很多站对任意路径返回 200+首页，先探一个必然不存在的路径。
	//     凡与基线「状态码+长度」完全一致的命中都要降权，否则会把噪音当成发现
	noise := probe(ctx, client, base+"/__ctfagent_noise_8f3a__")
	if noise.status >= 200 && noise.status < 300 {
		fmt.Fprintf(&b, "假200基线: /__ctfagent_noise_8f3a__ -> %d %dB（与之同码同长的命中已标记 [疑似假200]）\n", noise.status, noise.size)
	}

	// 2) 并发目录/文件探测
	results := make([]probeResult, 0, 64)
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for _, p := range paths {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			u := base + "/"
			if p != "" {
				u = base + "/" + strings.TrimLeft(p, "/")
			}
			r := probe(ctx, client, u)
			r.path = "/" + p
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].path < results[j].path })

	var ok, denied, redirects, methodMismatch []string
	for _, r := range results {
		fake := noise.status >= 200 && noise.status < 300 && r.status == noise.status && r.size == noise.size
		suffix := ""
		if fake {
			suffix = " [疑似假200]"
		}
		switch {
		case r.status == 0:
			continue
		case r.status == 401 || r.status == 403:
			// 401/403 是「路由存在」的强证据：拿到凭据后必须回来打这些路径
			denied = append(denied, fmt.Sprintf("%s %d%s", r.path, r.status, suffix))
		case r.status == 405:
			// 405 = 路由存在，只是方法不对：换 POST 再打一次，往往就是真正的接口
			methodMismatch = append(methodMismatch, r.path)
		case r.status >= 300 && r.status < 400:
			redirects = append(redirects, fmt.Sprintf("%s %d->%s", r.path, r.status, r.loc))
		case r.status < 400:
			ok = append(ok, fmt.Sprintf("%s %d %dB %s%s", r.path, r.status, r.size, r.ctype, suffix))
		}
	}
	fmt.Fprintf(&b, "\n== 可访问 (%d) ==\n%s\n", len(ok), strings.Join(ok, "\n"))
	if len(redirects) > 0 {
		fmt.Fprintf(&b, "\n== 跳转 (%d) ==\n%s\n", len(redirects), strings.Join(redirects, "\n"))
	}
	if len(methodMismatch) > 0 {
		fmt.Fprintf(&b, "\n== 方法不对 405（路由存在，换 POST/PUT 再打）(%d) ==\n%s\n",
			len(methodMismatch), strings.Join(methodMismatch, "\n"))
	}
	if len(denied) > 0 {
		fmt.Fprintf(&b, "\n== 受保护 401/403 (%d) ==\n%s\n", len(denied), strings.Join(denied, "\n"))
		b.WriteString("（401/403 = 路由存在，只是没权限。拿到 token/key 后回来打这些路径；）\n")
	}
	// 3) 下一步建议：把「这类指纹该干什么」直接写出来，省掉模型一轮思考
	var tips []string
	joined := strings.ToLower(b.String())
	// flag 类命中：直接读，不再绕路
	for _, f := range []string{"/flag ", "/flag.txt ", "/flag.md ", "/secret "} {
		if strings.Contains(joined, f) {
			tips = append(tips, "命中 flag 类路径：先直接读它，别再做别的")
			break
		}
	}
	for _, p := range []string{"/src ", "/source ", "/app.py "} {
		if strings.Contains(joined, p) {
			tips = append(tips, "有源码泄露：先把源码读全，过滤条件/固定错误串/真实参数名/flag 路径都在里面")
			break
		}
	}
	if len(methodMismatch) > 0 {
		tips = append(tips, "有 405 路由：这些是 POST/PUT 接口，先 POST 空 body 拿固定错误串，再用 paramfuzz 爆参数名")
	}
	if strings.Contains(joined, "/admin ") || strings.Contains(joined, "/api ") {
		tips = append(tips, "有 api/admin 路由：接口拿到固定错误串时用 paramfuzz 爆参数名")
	}
	if strings.Contains(joined, ".git/head") {
		tips = append(tips, "有 .git：用 git-dumper 或按 refs/objects 手工还原源码")
	}
	if len(tips) > 0 {
		b.WriteString("\n【下一步】\n")
		for _, t := range tips {
			b.WriteString("- " + t + "\n")
		}
	}
	return b.String()
}

func (t *ToolSet) doFuzz(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		URL      string            `json:"url"`      // 含 FUZZ 占位符
		Words    []string          `json:"words"`    // 内联字典
		Wordlist string            `json:"wordlist"` // 内置字典名：dirs/api/files/params/numbers
		Method   string            `json:"method"`   //
		Headers  map[string]string `json:"headers"`
		Body     string            `json:"body"`
		Threads  int               `json:"threads"`
		Match    []string          `json:"match"` // 只保留这些状态码
		Hide     []string          `json:"hide"`  // 过滤这些状态码
		TimeoutS int               `json:"timeout_s"`
		Diff     bool              `json:"diff"`     // 差分模式：只报告与基线不同的响应
		Baseline string            `json:"baseline"` // 差分的基线 URL（默认把 FUZZ 换成一个随机噪音词）
		Preview  bool              `json:"preview"`  // 命中时附响应片段
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if !strings.Contains(a.URL, "FUZZ") && !strings.Contains(a.Body, "FUZZ") {
		return "url 或 body 里必须包含 FUZZ 占位符"
	}
	words := a.Words
	if len(words) == 0 {
		words = builtinWordlist(a.Wordlist)
	}
	if len(words) == 0 {
		return "没有可用的字典：给 words 或选一个内置 wordlist（dirs/api/files/params/numbers）"
	}
	threads := a.Threads
	if threads <= 0 {
		threads = 24
	}
	to := secs(a.TimeoutS)
	if to <= 0 {
		to = 8 * time.Second
	}
	client := &http.Client{
		Timeout: to,
		Jar:     t.jar, // reuse the session established by prior http calls
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	matchSet := map[int]bool{}
	for _, c := range a.Match {
		if n, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
			matchSet[n] = true
		}
	}
	hideSet := map[int]bool{}
	for _, c := range a.Hide {
		if n, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
			hideSet[n] = true
		}
	}
	// 差分模式的基线：用「必然不存在」的随机词探一次，记录状态码/长度/内容指纹。
	var baseStatus, baseLen int
	var baseHash uint64
	if a.Diff {
		bu := strings.ReplaceAll(a.URL, "FUZZ", "__ctfagent_noise_7b1d__")
		bb := strings.ReplaceAll(a.Body, "FUZZ", "__ctfagent_noise_7b1d__")
		bm := "GET"
		if strings.TrimSpace(a.Method) != "" {
			bm = strings.ToUpper(a.Method)
		}
		if req, err := http.NewRequestWithContext(ctx, bm, bu, strings.NewReader(bb)); err == nil {
			for k, v := range a.Headers {
				req.Header.Set(k, v)
			}
			if resp, err := client.Do(req); err == nil {
				raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				baseStatus, baseLen, baseHash = resp.StatusCode, len(raw), bodyHash(raw)
			}
		}
	}

	type hit struct {
		w       string
		status  int
		size    int
		differ  bool
		preview string
	}
	var mu sync.Mutex
	var hits []hit
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for _, w := range words {
		w := w
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			u := strings.ReplaceAll(a.URL, "FUZZ", w)
			method := strings.ToUpper(a.Method)
			if method == "" {
				method = "GET"
			}
			body := strings.ReplaceAll(a.Body, "FUZZ", w)
			req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
			if err != nil {
				return
			}
			for k, v := range a.Headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			n := len(raw)
			if len(matchSet) > 0 && !matchSet[resp.StatusCode] {
				return
			}
			if hideSet[resp.StatusCode] {
				return
			}
			// 差分判定：状态码变 / 长度差超过阈值 / 内容指纹不同
			differ := resp.StatusCode != baseStatus || absInt(n-baseLen) > 24 || bodyHash(raw) != baseHash
			if a.Diff && !differ {
				return // 与基线一模一样 = 噪音，直接丢
			}
			pv := ""
			if a.Preview {
				pv = oneLine(trimSnippet(string(raw), 160))
			}
			mu.Lock()
			hits = append(hits, hit{w, resp.StatusCode, n, differ, pv})
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].status != hits[j].status {
			return hits[i].status < hits[j].status
		}
		return hits[i].w < hits[j].w
	})
	var b strings.Builder
	mode := ""
	if a.Diff {
		mode = fmt.Sprintf("，差分模式 基线 %d/%dB", baseStatus, baseLen)
	}
	fmt.Fprintf(&b, "== fuzz %s（%d 词，%d 命中%s）==\n", a.URL, len(words), len(hits), mode)
	if a.Diff && len(hits) == 0 {
		b.WriteString("所有候选与基线一致 —— 说明该位置对这些输入不敏感。\n")
		b.WriteString("建议：换占位位置（query/body/header）、换字典（traversal/ssti/cmdi/cmdi-bypass/sqli/ssrf-hosts）、或先找真正的输入点。\n")
	}
	for _, h := range hits {
		mark := ""
		if a.Diff && h.differ {
			mark = "  <= 差异"
		}
		fmt.Fprintf(&b, "%s\t%d\t%dB%s\n", h.w, h.status, h.size, mark)
		if h.preview != "" {
			fmt.Fprintf(&b, "    %s\n", h.preview)
		}
	}
	return b.String()
}

func builtinWordlist(name string) []string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "dirs":
		return defaultPaths
	case "traversal", "ssti", "cmdi", "cmdi-bypass", "sqli", "ssrf-hosts":
		return loadEmbeddedWordlist(strings.ToLower(strings.TrimSpace(name)))
	case "api":
		return []string{
			"api", "api/v1", "api/v2", "api/user", "api/users", "api/login", "api/register",
			"api/admin", "api/config", "api/flag", "api/health", "api/status", "api/info",
			"api/query", "api/search", "api/exec", "api/run", "api/upload", "api/download",
			"api/file", "api/read", "api/proxy", "api/fetch", "api/export", "api/import",
			"api/v1/user", "api/v1/users", "api/v1/admin", "api/v1/flag", "api/v1/config",
		}
	case "files":
		return []string{
			"flag", "flag.txt", "flag.php", "flag.jsp", "flag.html", "flag.json",
			".env", ".env.bak", ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
			"robots.txt", "sitemap.xml", "backup.zip", "backup.tar.gz", "www.zip",
			"db.sql", "dump.sql", "config.php", "config.php.bak", "config.json",
			"index.php.bak", "index.php~", "web.config", "composer.json", "package.json",
			"Dockerfile", "docker-compose.yml", "README.md", "Makefile", "phpinfo.php",
		}
	case "params":
		// 公开单词词典 + 复合命名规则生成的候选
		return append(append([]string{}, loadEmbeddedWordlist("params")...), expandCompoundParams()...)
	case "numbers":
		out := make([]string, 0, 200)
		for i := 0; i <= 199; i++ {
			out = append(out, fmt.Sprint(i))
		}
		return out
	}
	return nil
}

func probe(ctx context.Context, c *http.Client, u string) probeResult {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return probeResult{status: 0}
	}
	resp, err := c.Do(req)
	if err != nil {
		return probeResult{status: 0}
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return probeResult{
		status: resp.StatusCode,
		size:   int(n),
		ctype:  strings.Split(resp.Header.Get("Content-Type"), ";")[0],
		loc:    resp.Header.Get("Location"),
	}
}

func fetch(ctx context.Context, c *http.Client, u string) (string, http.Header) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return string(body), resp.Header
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func pageTitle(body string) string {
	if m := titleRe.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(oneLine(m[1]))
	}
	return ""
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return strings.TrimSpace(s)
}

func techHints(body string, h http.Header) []string {
	var out []string
	low := strings.ToLower(body)
	table := map[string]string{
		"wp-content":  "WordPress",
		"thinkphp":    "ThinkPHP",
		"__viewstate": "ASP.NET WebForms",
		"laravel":     "Laravel",
		"spring":      "Spring",
		"shiro":       "Shiro",
		"struts":      "Struts2",
		"swagger":     "Swagger UI",
		"graphql":     "GraphQL",
		"element-ui":  "Element UI",
		"react":       "React",
		"vue":         "Vue",
		"jquery":      "jQuery",
		"hugegraph":   "HugeGraph",
		"flask":       "Flask",
		"werkzeug":    "Werkzeug(Flask)",
		"django":      "Django",
		"tomcat":      "Tomcat",
		"jenkins":     "Jenkins",
		"druid":       "Druid",
		"nacos":       "Nacos",
		"actuator":    "Spring Actuator",
		"php":         "PHP",
		"sql":         "SQL 相关",
		"jwt":         "JWT",
		"upload":      "上传点",
		"login":       "登录口",
		"admin":       "后台入口",
		"flag":        "疑似 flag 线索",
		"<form":       "表单",
	}
	seen := map[string]bool{}
	for k, v := range table {
		if strings.Contains(low, k) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if s := h.Get("Server"); s != "" {
		out = append(out, "Server:"+s)
	}
	if s := h.Get("X-Powered-By"); s != "" {
		out = append(out, "Powered:"+s)
	}
	sort.Strings(out)
	return out
}

// platformFlagPaths 读取平台声明的 flag 约定位置。
// 设计上刻意让内核保持平台无关：内核只提供「通用落点」，
// 任何平台私有的约定都由适配器写进 Challenge.Meta 传进来。
func platformFlagPaths(b *core.Board) []string {
	if b == nil || b.Hints == nil {
		return nil
	}
	raw := strings.TrimSpace(b.Hints["flag_paths"])
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(strings.TrimPrefix(f, "/"))
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// bodyHash 是响应体的稳定指纹（FNV-1a），用于差分模式判断"内容有没有变"。
func bodyHash(b []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}
