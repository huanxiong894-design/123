package kernel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	// 打印真实 flag 后再提交 → 通过
	call(t, ts, "sh", `{"command":"echo 'flag{right_one}'"}`)
	out = call(t, ts, "submit", `{"flag":"flag{right_one}","evidence":"flag{right_one}"}`)
	if !strings.Contains(out, "✅") {
		t.Fatalf("接地气的提交应成功: %s", out)
	}
	if board.SolvedFlags() != 1 {
		t.Fatalf("solved=%d", board.SolvedFlags())
	}

	// 重复提交同一个 → 闸门拦下
	if out := call(t, ts, "submit", `{"flag":"flag{right_one}","evidence":"flag{right_one}"}`); !strings.Contains(out, "已提交过") {
		t.Fatalf("重复提交应被拦: %s", out)
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
