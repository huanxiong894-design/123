package kernel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
	"ctfagent/internal/sandbox"
)

func newTestToolSet(t *testing.T) (*ToolSet, *core.Board, *sandbox.Local) {
	t.Helper()
	root := t.TempDir()
	rt, err := sandbox.NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	board := core.NewBoard(&core.Challenge{ID: "t1", Category: "misc"})
	policy := core.DefaultPolicy()
	_ = policy.Compile()
	ts := NewToolSet(rt, board, policy, core.NewGate(5), Hooks{
		Grounding: true,
		Submit: func(_ context.Context, flag string) (core.SubmitResult, error) {
			return core.SubmitResult{Correct: flag == "flag{right_one}", TotalFlags: 1, CorrectFlags: 1}, nil
		},
	})
	return ts, board, rt
}

func call(t *testing.T, ts *ToolSet, name, args string) string {
	t.Helper()
	return ts.Call(context.Background(), llm.ToolCall{ID: "c", Name: name, Args: args})
}

func TestToolDefinitionsHaveValidJSONSchemas(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	var validate func(label string, raw any)
	validate = func(label string, raw any) {
		schema, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s: schema must be an object, got %T (%v)", label, raw, raw)
		}
		typ, ok := schema["type"].(string)
		if !ok {
			t.Fatalf("%s: missing string type: %#v", label, schema)
		}
		switch typ {
		case "object":
			var props map[string]any
			if rawProps, exists := schema["properties"]; exists {
				props, ok = rawProps.(map[string]any)
				if !ok {
					t.Fatalf("%s.properties must be an object, got %T", label, rawProps)
				}
				for name, prop := range props {
					validate(label+"."+name, prop)
				}
			}
			if required, exists := schema["required"]; exists {
				names, ok := required.([]string)
				if !ok {
					t.Fatalf("%s.required must be a string array, got %T", label, required)
				}
				for _, name := range names {
					if _, exists := props[name]; !exists {
						t.Fatalf("%s.required references missing property %q", label, name)
					}
				}
			}
			if additional, exists := schema["additionalProperties"]; exists {
				if _, isBool := additional.(bool); !isBool {
					validate(label+".additionalProperties", additional)
				}
			}
		case "array":
			validate(label+".items", schema["items"])
		case "string", "number", "integer", "boolean":
		default:
			t.Fatalf("%s: unsupported schema type %q", label, typ)
		}
	}

	for _, tool := range ts.Definitions() {
		if tool.Schema["type"] != "object" {
			t.Fatalf("tool %s: parameters schema must be an object", tool.Name)
		}
		validate(tool.Name, tool.Schema)
	}
}

func TestShellToolRunsInWorkdir(t *testing.T) {
	ts, board, rt := newTestToolSet(t)
	out := call(t, ts, "sh", `{"command":"echo hello-ctf > a.txt && cat a.txt"}`)
	if !strings.Contains(out, "hello-ctf") || !strings.Contains(out, "exit=0") {
		t.Fatalf("输出异常: %s", out)
	}
	if _, err := rt.ReadFile(context.Background(), "a.txt", 100); err != nil {
		t.Fatalf("命令没在工作目录生效: %v", err)
	}
	if len(board.Attempts) != 1 || board.Attempts[0].Verdict != "ok" {
		t.Fatalf("attempt 未记录: %+v", board.Attempts)
	}
}

func TestPythonToolWritesAndRuns(t *testing.T) {
	ts, _, rt := newTestToolSet(t)
	out := call(t, ts, "py", `{"code":"print('py-ok', 6*7)","name":"probe"}`)
	if !strings.Contains(out, "py-ok 42") {
		t.Fatalf("python 未执行: %s", out)
	}
	if _, err := rt.ReadFile(context.Background(), "probe.py", 1000); err != nil {
		t.Fatalf("脚本未保存: %v", err)
	}
}

func TestFactRequiresRealEvidence(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	// 没有输出就打事实 → 拒
	if out := call(t, ts, "fact", `{"text":"存在 SQL 注入","evidence":"sqlmap found injection"}`); !strings.Contains(out, "证据校验失败") {
		t.Fatalf("幻觉证据应被拒: %s", out)
	}
	if len(board.Facts) != 0 {
		t.Fatal("被拒的事实不该入板")
	}
	// 打一条真实输出，再引用它的原文 → 通过
	call(t, ts, "sh", `{"command":"echo 'Server: nginx/1.18.0'"}`)
	if out := call(t, ts, "fact", `{"text":"版本是 nginx 1.18","evidence":"Server: nginx/1.18.0"}`); !strings.Contains(out, "已记录事实") {
		t.Fatalf("真实证据应通过: %s", out)
	}
	if len(board.Facts) != 1 {
		t.Fatalf("facts=%d", len(board.Facts))
	}
}

func TestSubmitBlockedWithoutGrounding(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	out := call(t, ts, "submit", `{"flag":"flag{right_one}","evidence":"我在输出里看到了"}`)
	if !strings.Contains(out, "grounding") {
		t.Fatalf("未接地气的提交应被拦: %s", out)
	}
	if len(board.Flags) != 0 {
		t.Fatal("被拦的提交不该记录")
	}

	// 打印真实 flag 后提交。evidence 是备注，不要求逐字出现在输出里。
	call(t, ts, "sh", `{"command":"echo 'flag{right_one}'"}`)
	out = call(t, ts, "submit", `{"flag":"flag{right_one}","evidence":"shell 输出中的 flag 文件"}`)
	if !strings.Contains(out, "✅") {
		t.Fatalf("flag 有真实输出证据时应成功，不应因备注措辞被拒: %s", out)
	}
	if board.SolvedFlags() != 1 {
		t.Fatalf("solved=%d", board.SolvedFlags())
	}

	// 重复提交同一个 → 闸门拦下
	if out := call(t, ts, "submit", `{"flag":"flag{right_one}","evidence":"flag{right_one}"}`); !strings.Contains(out, "已提交过") {
		t.Fatalf("重复提交应被拦: %s", out)
	}

	// evidence 字段确实可省略；flag 本身仍必须有真实输出依据。
	ts2, _, _ := newTestToolSet(t)
	call(t, ts2, "sh", `{"command":"echo 'flag{right_one}'"}`)
	if out := call(t, ts2, "submit", `{"flag":"flag{right_one}"}`); !strings.Contains(out, "✅") {
		t.Fatalf("evidence 可选时应允许提交: %s", out)
	}
}

func TestCandidateLedgerSurvivesRecentOutputEviction(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	call(t, ts, "sh", `{"command":"echo 'flag{right_one}'"}`)
	candidate, ok := ts.candidateEvidence("flag{right_one}")
	if !ok || candidate.ID == "" || candidate.Tool != "sh" {
		t.Fatalf("candidate provenance missing: %+v, ok=%v", candidate, ok)
	}
	if len(board.Candidates) != 1 || board.Candidates[0].Status != "observed" {
		t.Fatalf("candidate board not updated: %+v", board.Candidates)
	}
	// Evict the original raw output; exact provenance in this round must still ground it.
	ts.remember(strings.Repeat("x", recentCap+1))
	if !ts.grounded("flag{right_one}") {
		t.Fatal("candidate should remain grounded after recent output eviction")
	}
	if out := call(t, ts, "submit", `{"flag":"flag{right_one}","evidence_id":"wrong-id"}`); !strings.Contains(out, "grounding 校验失败") {
		t.Fatalf("wrong evidence id should be rejected: %s", out)
	}
	if out := call(t, ts, "submit", `{"flag":"flag{right_one}","evidence_id":"`+candidate.ID+`"}`); !strings.Contains(out, "✅") {
		t.Fatalf("verified evidence id should submit: %s", out)
	}
	if board.Candidates[0].Status != "accepted" {
		t.Fatalf("candidate status=%s", board.Candidates[0].Status)
	}
}

func TestSubmitMarksCandidateSubmittedBeforePlatformReply(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	call(t, ts, "sh", `{"command":"echo 'flag{right_one}'"}`)
	var sawSubmitted bool
	ts.hooks.Submit = func(context.Context, string) (core.SubmitResult, error) {
		sawSubmitted = len(board.Candidates) == 1 && board.Candidates[0].Status == "submitted"
		return core.SubmitResult{Correct: true}, nil
	}
	out := call(t, ts, "submit", `{"flag":"flag{right_one}"}`)
	if !sawSubmitted || !strings.Contains(out, "✅") || board.Candidates[0].Status != "accepted" {
		t.Fatalf("submit lifecycle mismatch: sawSubmitted=%v status=%s output=%s", sawSubmitted, board.Candidates[0].Status, out)
	}
}

func TestTargetScopeRejectsUnlistedHosts(t *testing.T) {
	allowed := []string{"10.23.4.5:80", "http://10.23.4.6:8080"}
	bad := llm.ToolCall{Name: "http", Args: `{"url":"http://example.invalid/"}`}
	if msg := targetScopeError(bad, allowed); !strings.Contains(msg, "不在本题授权目标") {
		t.Fatalf("unlisted host not blocked: %q", msg)
	}
	good := llm.ToolCall{Name: "fuzz", Args: `{"url":"http://10.23.4.5/FUZZ"}`}
	if msg := targetScopeError(good, allowed); msg != "" {
		t.Fatalf("listed host and default port should pass: %q", msg)
	}
	wrongPort := llm.ToolCall{Name: "http", Args: `{"url":"http://10.23.4.6/"}`}
	if msg := targetScopeError(wrongPort, allowed); !strings.Contains(msg, "目标") {
		t.Fatalf("explicit target URL port should be enforced: %q", msg)
	}
	rightPort := llm.ToolCall{Name: "http", Args: `{"url":"http://10.23.4.6:8080/"}`}
	if msg := targetScopeError(rightPort, allowed); msg != "" {
		t.Fatalf("explicitly authorized URL port should pass: %q", msg)
	}
	portScan := llm.ToolCall{Name: "ports", Args: `{"host":"10.23.4.5","ports":"quick"}`}
	if msg := targetScopeError(portScan, allowed); !strings.Contains(msg, "授权的目标端口") {
		t.Fatalf("quick scan should not exceed an explicit port-only target: %q", msg)
	}
	portScan = llm.ToolCall{Name: "ports", Args: `{"host":"10.23.4.5","ports":"80"}`}
	if msg := targetScopeError(portScan, allowed); msg != "" {
		t.Fatalf("explicitly authorized port scan should pass: %q", msg)
	}
	rawPort := llm.ToolCall{Name: "raw", Args: `{"host":"10.23.4.5","port":9000}`}
	if msg := targetScopeError(rawPort, allowed); !strings.Contains(msg, "授权目标") {
		t.Fatalf("raw TCP port outside the target authority should be blocked: %q", msg)
	}
	bodyOnly := llm.ToolCall{Name: "http", Args: `{"url":"http://10.23.4.5/api","body":"http://127.0.0.1/"}`}
	if msg := targetScopeError(bodyOnly, allowed); msg != "" {
		t.Fatalf("application-level body value must not be mistaken for a direct destination: %q", msg)
	}
	tunnel := llm.ToolCall{Name: "tunnel", Args: `{"endpoint":"http://10.23.4.5/send","finish":"GET http://10.23.4.6:8080/retrieve?session={session}"}`}
	if msg := targetScopeError(tunnel, allowed); msg != "" {
		t.Fatalf("authorized tunnel finish request line should pass: %q", msg)
	}
	badTunnel := llm.ToolCall{Name: "tunnel", Args: `{"endpoint":"http://10.23.4.5/send","finish":"GET http://example.invalid/retrieve"}`}
	if msg := targetScopeError(badTunnel, allowed); !strings.Contains(msg, "不在本题授权目标") {
		t.Fatalf("out-of-scope tunnel finish should be blocked: %q", msg)
	}
}

func TestToolCallRejectsUnlistedHostAndRedirect(t *testing.T) {
	ts, _, rt := newTestToolSet(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/out-of-scope", http.StatusFound)
	}))
	defer server.Close()
	rt.SetTargets([]string{server.URL})
	if out := call(t, ts, "http", `{"url":"http://example.invalid/"}`); !strings.Contains(out, "不在本题授权目标") {
		t.Fatalf("direct unlisted host should be blocked: %s", out)
	}
	out := call(t, ts, "http", `{"url":"`+server.URL+`/"}`)
	if !strings.Contains(out, "HTTP 302") {
		t.Fatalf("authorized request should stop at out-of-scope redirect: %s", out)
	}
	otherPort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("out of scope"))
	}))
	defer otherPort.Close()
	portRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherPort.URL+"/out-of-scope", http.StatusFound)
	}))
	defer portRedirect.Close()
	rt.SetTargets([]string{portRedirect.URL})
	out = call(t, ts, "http", `{"url":"`+portRedirect.URL+`/"}`)
	if !strings.Contains(out, "HTTP 302") || strings.Contains(out, "out of scope") {
		t.Fatalf("redirect to unlisted port should not be followed: %s", out)
	}
}

func TestHTTPOutputMarksReadLimitTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("z", 100)))
	}))
	defer server.Close()
	ts, _, rt := newTestToolSet(t)
	ts.hooks.OutputBytes = 64
	rt.SetTargets([]string{server.URL})
	out := call(t, ts, "http", `{"url":"`+server.URL+`/"}`)
	if !strings.Contains(out, "响应已截断") {
		t.Fatalf("truncated response should be disclosed: %.300s", out)
	}
}

func TestParallelSafeToolClassification(t *testing.T) {
	cases := []struct {
		call llm.ToolCall
		want bool
	}{
		{llm.ToolCall{Name: "recon", Args: `{"url":"http://10.0.0.1"}`}, true},
		{llm.ToolCall{Name: "ports", Args: `{"host":"10.0.0.1","ports":"quick"}`}, true},
		{llm.ToolCall{Name: "ports", Args: `{"host":"10.0.0.1","ports":"all"}`}, false},
		{llm.ToolCall{Name: "fuzz", Args: `{"url":"http://10.0.0.1/FUZZ","method":"GET"}`}, true},
		{llm.ToolCall{Name: "fuzz", Args: `{"url":"http://10.0.0.1/FUZZ","method":"POST"}`}, false},
		{llm.ToolCall{Name: "http", Args: `{"url":"http://10.0.0.1"}`}, false},
	}
	for _, tc := range cases {
		if got := parallelSafeToolCall(tc.call); got != tc.want {
			t.Fatalf("parallelSafeToolCall(%s,%s)=%v want %v", tc.call.Name, tc.call.Args, got, tc.want)
		}
	}
}

func TestCallBatchRunsIndependentReconInParallel(t *testing.T) {
	var active, maxActive int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&maxActive)
			if n <= old || atomic.CompareAndSwapInt32(&maxActive, old, n) {
				break
			}
		}
		time.Sleep(80 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	ts, _, rt := newTestToolSet(t)
	rt.SetTargets([]string{srv.URL})
	calls := []llm.ToolCall{
		{ID: "r1", Name: "recon", Args: `{"url":` + `"` + srv.URL + `","paths":["/alpha"],"threads":1}`},
		{ID: "r2", Name: "recon", Args: `{"url":` + `"` + srv.URL + `","paths":["/beta"],"threads":1}`},
	}
	outs := ts.CallBatch(context.Background(), calls)
	if len(outs) != 2 || atomic.LoadInt32(&maxActive) < 2 {
		t.Fatalf("independent recon calls did not overlap; maxActive=%d outputs=%d", atomic.LoadInt32(&maxActive), len(outs))
	}
}

func TestCallBatchSuppressesConsecutiveIdenticalReadOnlyProbe(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	ts, _, rt := newTestToolSet(t)
	rt.SetTargets([]string{srv.URL})
	probe := llm.ToolCall{ID: "r", Name: "recon", Args: `{"url":"` + srv.URL + `","paths":["/one"],"threads":1}`}
	first := ts.Call(context.Background(), probe)
	firstHits := atomic.LoadInt32(&hits)
	if firstHits == 0 || first == "" {
		t.Fatal("initial read-only probe did not execute")
	}
	second := ts.Call(context.Background(), probe)
	if atomic.LoadInt32(&hits) != firstHits || !strings.Contains(second, "[LOOP_GUARD_SKIPPED]") || len(second) > 240 {
		t.Fatalf("repeat was not suppressed: before=%d after=%d output=%s", firstHits, atomic.LoadInt32(&hits), second)
	}
}

func TestCompactModelOutputPreservesCandidateAndSpills(t *testing.T) {
	ts, _, rt := newTestToolSet(t)
	long := strings.Repeat("A", 7000) + " flag{right_one} " + strings.Repeat("B", 7000)
	ts.recordCandidates(llm.ToolCall{Name: "read", Args: `{"path":"capture.txt"}`}, long, 4)
	compact := ts.compactModelOutput(long, 4)
	if len(compact) >= len(long) || !strings.Contains(compact, "flag{right_one}") || !strings.Contains(compact, "r0-s4-c1") {
		t.Fatalf("bad compact preview (len=%d): %.200s", len(compact), compact)
	}
	data, err := rt.ReadFile(context.Background(), "evidence-output/r0-step4.txt", int64(len(long)+1))
	if err != nil || string(data) != long {
		t.Fatalf("spill file mismatch: err=%v len=%d", err, len(data))
	}
}

func TestSubmitRejectsWrongFlagAndCounts(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	call(t, ts, "sh", `{"command":"echo 'flag{nope_1234}'"}`)
	out := call(t, ts, "submit", `{"flag":"flag{nope_1234}","evidence":"flag{nope_1234}"}`)
	if !strings.Contains(out, "❌") {
		t.Fatalf("错误 flag 应返回失败: %s", out)
	}
	if board.SolvedFlags() != 0 || len(board.Flags) != 1 {
		t.Fatalf("board flags=%+v", board.Flags)
	}
}

func TestScanForFlagsDoesNotAutoSubmit(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	call(t, ts, "sh", `{"command":"printf 'noise flag{candidate_xyz} tail'"}`)
	found := false
	for _, a := range board.Artifacts {
		if a.Value == "flag{candidate_xyz}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("候选 flag 未登记为产物: %+v", board.Artifacts)
	}
	if len(board.Flags) != 0 {
		t.Fatal("不应自动提交")
	}
}

func TestIdeaAndArtifactTools(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	if out := call(t, ts, "idea", `{"text":"试试 SSTI"}`); !strings.Contains(out, "已登记假设 #1") {
		t.Fatalf("idea: %s", out)
	}
	if out := call(t, ts, "idea", `{"id":1,"status":"done","verdict":"没有模板注入"}`); !strings.Contains(out, "done") {
		t.Fatalf("idea update: %s", out)
	}
	if board.Ideas[0].Status != "done" {
		t.Fatal("假设状态未更新")
	}
	if out := call(t, ts, "artifact", `{"kind":"cred","value":"admin:p@ss"}`); !strings.Contains(out, "已记录产物") {
		t.Fatalf("artifact: %s", out)
	}
	if out := call(t, ts, "artifact", `{"kind":"cred","value":"admin:p@ss"}`); !strings.Contains(out, "已存在") {
		t.Fatalf("产物去重失效: %s", out)
	}
}

func TestUnknownToolIsReported(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	if out := call(t, ts, "nmap", `{}`); !strings.Contains(out, "未知工具") {
		t.Fatalf("未知工具应提示: %s", out)
	}
}

func TestReadWriteTools(t *testing.T) {
	ts, board, _ := newTestToolSet(t)
	if out := call(t, ts, "write", `{"path":"notes/x.txt","content":"hello"}`); !strings.Contains(out, "已写入") {
		t.Fatalf("write: %s", out)
	}
	if out := call(t, ts, "read", `{"path":"notes/x.txt"}`); out != "hello" {
		t.Fatalf("read=%q", out)
	}
	if len(board.Artifacts) != 1 || board.Artifacts[0].Kind != core.ArtifactFile {
		t.Fatalf("写入未记产物: %+v", board.Artifacts)
	}
}

// 附件必须自动落地到工作目录：模型不该把步数浪费在"文件在哪"上。
func TestAttachmentsAreStaged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ELF-PAYLOAD-BYTES"))
	}))
	defer srv.Close()

	host := filepath.Join(t.TempDir(), "local.bin")
	if err := os.WriteFile(host, []byte("from-host"), 0o644); err != nil {
		t.Fatal(err)
	}

	rt := mustLocal(t)
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"cat remote.bin local.bin | tr '\\n' ' '"}`),
		llm.Call("submit", `{"flag":"flag{attached}","evidence":"flag{attached}"}`),
	)
	// 让第二步能"看到"flag：脚本里并未真的输出它，所以这里关掉 grounding 只验证落地。
	ch := &core.Challenge{
		ID: "att", FlagCount: 1,
		Attachments: []core.Attachment{
			{Name: "remote.bin", URL: srv.URL + "/a.bin"},
			{Name: "../../evil.txt", Path: host},
			{Name: "missing.txt"},
		},
	}
	cfg := DefaultConfig()
	cfg.MaxSteps = 4
	res, err := New(model, cfg).Solve(context.Background(), ch, rt, nil, nil, Hooks{
		Submit: func(_ context.Context, f string) (core.SubmitResult, error) {
			return core.SubmitResult{Correct: f == "flag{attached}"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Solved {
		t.Fatalf("未解出: %+v", res)
	}
	// 附件真的在沙箱里
	if data, err := rt.ReadFile(context.Background(), "remote.bin", 100); err != nil || string(data) != "ELF-PAYLOAD-BYTES" {
		t.Fatalf("URL 附件未落地: %q %v", data, err)
	}
	if data, err := rt.ReadFile(context.Background(), "evil.txt", 100); err != nil || string(data) != "from-host" {
		t.Fatalf("Path 附件未落地（或没做路径净化）: %q %v", data, err)
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"a.bin":            "a.bin",
		"../../etc/passwd": "passwd",
		`..\..\x.txt`:      "x.txt",
		"":                 "",
		"..":               "",
	}
	for in, want := range cases {
		if got := safeName(in); got != want {
			t.Fatalf("safeName(%q)=%q want %q", in, got, want)
		}
	}
}
