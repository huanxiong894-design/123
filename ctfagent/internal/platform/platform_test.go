package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ctfagent/internal/core"
)

// ---------------------------------------------------------------------------
// 本地题库
// ---------------------------------------------------------------------------

func writeSuite(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mk := func(name string, files map[string]string) {
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for n, c := range files {
			if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("hello", map[string]string{
		"challenge.json": `{"id":"hello","title":"你好","category":"misc","prompt":"读 flag.txt","flag_count":1}`,
		"flag.txt":       "flag{local_one}\n",
		"hint.txt":       "就在工作目录里\n",
		"note.md":        "附件内容",
	})
	mk("two", map[string]string{
		"challenge.json": `{"id":"two","category":"crypto","flag_file":"answer.txt","flag_count":2}`,
		"answer.txt":     "flag{alpha}\nflag{beta}\n",
	})
	mk("checked", map[string]string{
		"challenge.json": `{"id":"checked","category":"web"}`,
		"checker.sh":     "#!/bin/sh\ntest \"$1\" = \"flag{via_checker}\"\n",
	})
	return dir
}

func TestLocalSuiteList(t *testing.T) {
	s, err := NewLocalSuite(writeSuite(t))
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("应发现 3 题，实际 %d", len(list))
	}
	byID := map[string]bool{}
	for _, ch := range list {
		byID[ch.ID] = true
	}
	for _, id := range []string{"hello", "two", "checked"} {
		if !byID[id] {
			t.Fatalf("缺少题目 %s", id)
		}
	}
}

func TestLocalSuiteAcquireNoDocker(t *testing.T) {
	dir := writeSuite(t)
	s, _ := NewLocalSuite(dir)
	c, err := s.Acquire(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if c.Container != "" {
		t.Fatalf("无 docker 配置不该起容器: %q", c.Container)
	}
	if c.WorkDir == "" || c.HostDir == "" {
		t.Fatalf("工作目录缺失: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(c.WorkDir, "note.md")); err != nil {
		t.Fatalf("附件应在工作目录里: %v", err)
	}
	// 答案隔离：flag.txt / hint.txt 绝不能出现在 agent 的工作目录里
	for _, leak := range []string{"flag.txt", "hint.txt", "challenge.json"} {
		if _, err := os.Stat(filepath.Join(c.WorkDir, leak)); err == nil {
			t.Fatalf("%s 泄漏到了工作目录，agent 可以直接抄答案", leak)
		}
	}
	// 工作目录与题库目录必须是两个地方
	if c.WorkDir == filepath.Join(dir, "hello") {
		t.Fatal("工作目录不该就是题库目录")
	}
	if err := s.Release(context.Background(), "hello"); err != nil {
		t.Fatalf("Release 应幂等: %v", err)
	}
}

// 跨轮保留：agent 在第一轮写下的文件，第二轮还在（不然重跑等于从头再来）。
func TestLocalSuiteWorkPersists(t *testing.T) {
	dir := writeSuite(t)
	s, _ := NewLocalSuite(dir)
	c1, err := s.Acquire(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c1.WorkDir, "scratch.txt"), []byte("round1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	c2, _ := s.Acquire(context.Background(), "hello")
	if data, err := os.ReadFile(filepath.Join(c2.WorkDir, "scratch.txt")); err != nil || string(data) != "round1" {
		t.Fatalf("跨轮产物丢了: %q %v", data, err)
	}

	// Fresh 模式要清空
	s.Fresh = true
	c3, _ := s.Acquire(context.Background(), "hello")
	if _, err := os.Stat(filepath.Join(c3.WorkDir, "scratch.txt")); err == nil {
		t.Fatal("Fresh 模式没有清空工作目录")
	}
	if _, err := os.Stat(filepath.Join(c3.WorkDir, "note.md")); err != nil {
		t.Fatal("Fresh 之后附件应重新复制")
	}
	if err := s.ResetWork("hello"); err != nil {
		t.Fatal(err)
	}
}

func TestLocalSuiteSubmit(t *testing.T) {
	s, _ := NewLocalSuite(writeSuite(t))
	ctx := context.Background()

	if r, err := s.Submit(ctx, "hello", "flag{local_one}"); err != nil || !r.Correct {
		t.Fatalf("正确 flag 未通过: %v %+v", err, r)
	}
	if r, err := s.Submit(ctx, "hello", "flag{wrong}"); err != nil || r.Correct {
		t.Fatalf("错误 flag 应失败: %v %+v", err, r)
	}
	// 多 flag 题：两行都算对
	for _, f := range []string{"flag{alpha}", "flag{beta}"} {
		if r, err := s.Submit(ctx, "two", f); err != nil || !r.Correct {
			t.Fatalf("%s 应正确: %v %+v", f, err, r)
		}
	}
	// checker.sh 自定义判定
	if r, err := s.Submit(ctx, "checked", "flag{via_checker}"); err != nil || !r.Correct {
		t.Fatalf("checker 判定失败: %v %+v", err, r)
	}
	if r, _ := s.Submit(ctx, "checked", "flag{nope}"); r.Correct {
		t.Fatal("checker 应拒绝错误 flag")
	}
	if _, err := s.Submit(ctx, "missing", "x"); err == nil {
		t.Fatal("不存在的题目应报错")
	}
}

func TestLocalSuiteHint(t *testing.T) {
	s, _ := NewLocalSuite(writeSuite(t))
	h, err := s.Hint(context.Background(), "hello")
	if err != nil || h != "就在工作目录里" {
		t.Fatalf("hint=%q err=%v", h, err)
	}
	if _, err := s.Hint(context.Background(), "two"); err == nil {
		t.Fatal("无提示文件应返回错误")
	} else {
		var u *UnsupportedError
		if !errors.As(err, &u) {
			t.Fatalf("应是 Unsupported 错误: %v", err)
		}
	}
}

func TestLocalSuitePolicy(t *testing.T) {
	s, _ := NewLocalSuite(writeSuite(t))
	p := s.Policy(nil)
	if !p.AllowUUID {
		t.Fatal("默认策略应允许 UUID")
	}
	p2 := s.Policy(&core.Challenge{FlagPattern: `flag\{[^}]+\}`})
	if p2.AllowUUID || len(p2.Patterns) != 1 {
		t.Fatal("题目自定义正则应覆盖默认策略")
	}
}

// ---------------------------------------------------------------------------
// TSecBench（用 httptest 假扮平台，验证的是契约，不是网络）
// ---------------------------------------------------------------------------

type fakeTSec struct {
	token    string
	started  map[string]bool
	submits  []map[string]string
	hintCall int
}

func newFakeTSec(t *testing.T) (*fakeTSec, *httptest.Server) {
	f := &fakeTSec{started: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi/v1/challenges", func(w http.ResponseWriter, r *http.Request) {
		f.token = r.Header.Get("BENCHMARK_TOKEN")
		if r.Method != http.MethodGet {
			http.Error(w, "method", 405)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"unique_code": "q1", "total_score": 250, "flag_count": 1, "description": "题目一", "container_addr": []string{"http://x:8080"}, "difficulty": "easy", "level": 2},
		})
	})
	mux.HandleFunc("/openapi/v1/challenges/start", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("unique_code")
		if id == "" || r.Method != http.MethodPost {
			http.Error(w, "bad request", 400)
			return
		}
		f.started[id] = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"unique_code": id, "container_addr": []string{"http://10.0.0.9:8080"},
		})
	})
	mux.HandleFunc("/openapi/v1/challenges/close", func(w http.ResponseWriter, r *http.Request) {
		delete(f.started, r.URL.Query().Get("unique_code"))
		w.WriteHeader(204)
	})
	mux.HandleFunc("/openapi/v1/challenges/submit", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.submits = append(f.submits, body)
		switch body["flag"] {
		case "flag{right}":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"correct": true, "awarded": 250, "cumulative_score": 250,
				"correct_flag_count": 1, "total_flag_count": 1,
			})
		case "flag{dupe}":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"code":"duplicate","message":"duplicate submission"}`))
		case "flag{expired}":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"code":"invalid_state","message":"task ended"}`))
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"correct": false})
		}
	})
	mux.HandleFunc("/openapi/v1/challenges/hint", func(w http.ResponseWriter, r *http.Request) {
		f.hintCall++
		_ = json.NewEncoder(w).Encode(map[string]any{"hint": "看看 /tmp"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func TestTSecContract(t *testing.T) {
	f, srv := newFakeTSec(t)
	ts := NewTSec(TSecConfig{BaseURL: srv.URL, Token: "tok-123", SkipVPNCheck: true})
	ctx := context.Background()

	list, err := ts.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "q1" || list[0].FlagCount != 1 || list[0].MaxScore != 250 {
		t.Fatalf("list=%+v", list)
	}
	if len(list[0].Targets) != 1 || list[0].Targets[0] != "http://x:8080" {
		t.Fatalf("targets=%v", list[0].Targets)
	}
	if f.token != "tok-123" {
		t.Fatalf("token 头未发送: %q", f.token)
	}

	conn, err := ts.Acquire(ctx, "q1")
	if err != nil {
		t.Fatal(err)
	}
	if !f.started["q1"] || len(conn.Targets) != 1 || conn.Targets[0] != "http://10.0.0.9:8080" {
		t.Fatalf("acquire=%+v started=%v", conn, f.started)
	}

	if r, err := ts.Submit(ctx, "q1", "flag{right}"); err != nil || !r.Correct || r.Awarded != 250 || r.Cumulative != 250 {
		t.Fatalf("submit=%+v err=%v", r, err)
	}
	if r, err := ts.Submit(ctx, "q1", "flag{bad}"); err != nil || r.Correct {
		t.Fatalf("错误 flag: %+v err=%v", r, err)
	}
	// 409 重复提交必须当成"已计分"，而不是错误（否则会白白重试）
	if r, err := ts.Submit(ctx, "q1", "flag{dupe}"); err != nil || !r.Correct {
		t.Fatalf("重复提交应视为正确: %+v err=%v", r, err)
	}
	if r, err := ts.Submit(ctx, "q1", "flag{expired}"); err == nil || r.Correct || errors.Is(err, errDuplicate) {
		t.Fatalf("invalid_state 不可误判为已正确提交: %+v err=%v", r, err)
	}

	h, err := ts.Hint(ctx, "q1")
	if err != nil || h != "看看 /tmp" || f.hintCall != 1 {
		t.Fatalf("hint=%q err=%v", h, err)
	}

	if err := ts.Release(ctx, "q1"); err != nil {
		t.Fatal(err)
	}
	if f.started["q1"] {
		t.Fatal("close 未生效")
	}

	if got := ts.Policy(nil); !got.AllowUUID {
		t.Fatal("TSecBench 的 flag 是 UUID，策略必须允许")
	}
	if got := ts.Name(); got != "tsecbench" {
		t.Fatalf("name=%s", got)
	}
}

func TestTSecErrorsAreNotSwallowed(t *testing.T) {
	_, srv := newFakeTSec(t)
	ts := NewTSec(TSecConfig{BaseURL: srv.URL, Token: "t", SkipVPNCheck: true})
	// 路径不存在 → 404，必须报错而不是返回空结果
	if _, err := ts.Acquire(context.Background(), ""); err == nil {
		t.Fatal("空 id 应报错")
	} else if errors.Is(err, errDuplicate) {
		t.Fatal("400 不该被当成重复提交")
	}
	// 服务端挂掉
	srv.Close()
	if _, err := ts.List(context.Background()); err == nil {
		t.Fatal("服务不可用时应报错")
	}
}

func TestTSecVPNCheckFailsFast(t *testing.T) {
	ts := NewTSec(TSecConfig{BaseURL: "http://127.0.0.1:1", Token: "t", VPNProbe: "http://127.0.0.1:1", Timeout: 300 * time.Millisecond})
	if err := ts.CheckVPN(context.Background()); err == nil {
		t.Fatal("VPN 不可达时应报错")
	}
	if err := NewTSec(TSecConfig{SkipVPNCheck: true}).CheckVPN(context.Background()); err != nil {
		t.Fatalf("跳过预检时不该报错: %v", err)
	}
}
