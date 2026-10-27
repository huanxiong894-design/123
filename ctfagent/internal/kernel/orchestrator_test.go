package kernel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
	"ctfagent/internal/platform"
	"ctfagent/internal/sandbox"
)

// fakeAdapter 是一个内存平台：每题一个临时目录 + 一个固定 flag。
// 用它就能在没有网络、没有真实平台的情况下验证整个调度层。
type fakeAdapter struct {
	dirs    map[string]string // id -> 工作目录
	flags   map[string]string // id -> 正确 flag
	mu      sync.Mutex
	order   []string // Acquire 的调用顺序
	submit  int
	failAcq map[string]error
}

func (f *fakeAdapter) Name() string { return "fake" }

func (f *fakeAdapter) List(context.Context) ([]core.Challenge, error) { return nil, nil }

func (f *fakeAdapter) Acquire(_ context.Context, id string) (*platform.Conn, error) {
	if err := f.failAcq[id]; err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.order = append(f.order, id)
	dir := f.dirs[id]
	f.mu.Unlock()
	return &platform.Conn{WorkDir: dir, HostDir: dir}, nil
}

func (f *fakeAdapter) Release(context.Context, string) error { return nil }

func (f *fakeAdapter) Submit(_ context.Context, id, flag string) (core.SubmitResult, error) {
	f.mu.Lock()
	f.submit++
	f.mu.Unlock()
	if flag == f.flags[id] {
		return core.SubmitResult{Correct: true, Awarded: 100, Cumulative: 100, CorrectFlags: 1, TotalFlags: 1}, nil
	}
	return core.SubmitResult{Correct: false}, nil
}

func (f *fakeAdapter) Hint(context.Context, string) (string, error) {
	return "", platform.Unsupported("hint")
}

func (f *fakeAdapter) Policy(*core.Challenge) core.FlagPolicy {
	p := core.DefaultPolicy()
	p.AllowUUID = false
	return p
}

func (f *fakeAdapter) acquired() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

func newFakeAdapter(t *testing.T, ids ...string) *fakeAdapter {
	t.Helper()
	f := &fakeAdapter{dirs: map[string]string{}, flags: map[string]string{}, failAcq: map[string]error{}}
	for _, id := range ids {
		f.dirs[id] = t.TempDir()
		f.flags[id] = "flag{" + id + "_secret}"
	}
	return f
}

// 一轮之内按「高分优先、同分 flag 少优先」调度；解出的题下一轮不再跑。
func TestOrchestratorPriority(t *testing.T) {
	fa := newFakeAdapter(t, "a", "b", "c")
	model := llm.NewScripted() // 剧本为空：立刻收工（不算解出）
	cfg := RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{time.Second},
		Solver:      Config{MaxSteps: 3},
	}
	o := NewOrchestrator(fa, model, cfg)

	challenges := []core.Challenge{
		{ID: "a", MaxScore: 100, FlagCount: 2},
		{ID: "b", MaxScore: 300, FlagCount: 1},
		{ID: "c", MaxScore: 100, FlagCount: 1},
	}
	rep, err := o.Run(context.Background(), challenges)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 3 || rep.Solved != 0 {
		t.Fatalf("report=%+v", rep)
	}
	got := strings.Join(fa.acquired(), ",")
	// b(300) 先，然后 c(100,1 flag) 再 a(100,2 flags)
	if got != "b,c,a" {
		t.Fatalf("调度顺序=%s", got)
	}
}

// 第一轮卡住 → 第二轮带着交接摘要重跑并解出。
func TestOrchestratorRetryCarriesHandoff(t *testing.T) {
	fa := newFakeAdapter(t, "x")
	// 直接放好 flag.txt，模型第二轮读它
	dir := fa.dirs["x"]
	if err := writeFile(dir, "flag.txt", "flag{x_secret}\n"); err != nil {
		t.Fatal(err)
	}

	var sawHandoff bool
	model := llm.NewScripted(
		// 第一轮：只记一条事实就收工
		llm.Call("fact", `{"text":"目录是空的","evidence":"total 0"}`),
		llm.Call("finish", `{"status":"stuck","summary":"第一轮没找到"}`),
	)
	// 上面第一条事实的 evidence 不真实 → 会被拒；改用真实链路：先 ls 再收工
	model = llm.NewScripted(
		llm.Call("sh", `{"command":"ls -la"}`),
		llm.Call("fact", `{"text":"工作目录里有 flag.txt","evidence":"flag.txt"}`),
		llm.Call("finish", `{"status":"stuck","summary":"第一轮没读文件"}`),
		// 第二轮：交接之后应当先看到上一轮的事实
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{x_secret}","evidence":"flag{x_secret}"}`),
	)
	model.OnCall = func(_ int, req llm.Request) {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "上一轮交接") && strings.Contains(m.Content, "工作目录里有 flag.txt") {
				sawHandoff = true
			}
		}
	}

	o := NewOrchestrator(fa, model, RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{2 * time.Second, 2 * time.Second},
		Solver:      Config{MaxSteps: 5},
	})
	rep, err := o.Run(context.Background(), []core.Challenge{{ID: "x", FlagCount: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !sawHandoff {
		t.Fatal("第二轮没有拿到上一轮的交接摘要")
	}
	if rep.Solved != 1 || rep.Total != 1 || rep.Flags != 1 {
		t.Fatalf("report=%+v", rep)
	}
	if len(fa.acquired()) != 2 {
		t.Fatalf("应重跑一轮，实际 acquire=%v", fa.acquired())
	}
}

// 起环境失败要计入报告，而不是让整场崩掉。
func TestOrchestratorAcquireFailure(t *testing.T) {
	fa := newFakeAdapter(t, "ok", "bad")
	fa.failAcq["bad"] = errors.New("容器起不来")
	if err := writeFile(fa.dirs["ok"], "flag.txt", "flag{ok_secret}\n"); err != nil {
		t.Fatal(err)
	}
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{ok_secret}","evidence":"flag{ok_secret}"}`),
	)
	rep, err := NewOrchestrator(fa, model, RunConfig{
		Concurrency: 2,
		Rounds:      []time.Duration{3 * time.Second},
		Solver:      Config{MaxSteps: 4},
	}).Run(context.Background(), []core.Challenge{{ID: "ok", MaxScore: 50}, {ID: "bad", MaxScore: 10}})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]ChallengeReport{}
	for _, c := range rep.Challenges {
		byID[c.ChallengeID] = c
	}
	if !byID["ok"].Solved {
		t.Fatalf("ok 题应解出: %+v", byID["ok"])
	}
	if byID["bad"].Reason != "acquire_failed" {
		t.Fatalf("bad 题应标记 acquire_failed: %+v", byID["bad"])
	}
}

// 并发跑多题：验证 boardStore 没有数据竞争（配合 -race）。
func TestOrchestratorConcurrent(t *testing.T) {
	ids := []string{"c1", "c2", "c3", "c4"}
	fa := newFakeAdapter(t, ids...)
	var chs []core.Challenge
	for _, id := range ids {
		if err := writeFile(fa.dirs[id], "flag.txt", "flag{"+id+"_secret}\n"); err != nil {
			t.Fatal(err)
		}
		chs = append(chs, core.Challenge{ID: id, FlagCount: 1})
	}
	// 每个 challenges 都走同一剧本：读 flag → 提交
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{c1_secret}","evidence":"flag{c1_secret}"}`),
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{c2_secret}","evidence":"flag{c2_secret}"}`),
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{c3_secret}","evidence":"flag{c3_secret}"}`),
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{c4_secret}","evidence":"flag{c4_secret}"}`),
	)
	rep, err := NewOrchestrator(fa, model, RunConfig{
		Concurrency: 4,
		Rounds:      []time.Duration{5 * time.Second},
		Solver:      Config{MaxSteps: 6},
	}).Run(context.Background(), chs)
	if err != nil {
		t.Fatal(err)
	}
	// 并发下剧本顺序不确定，只要求都跑完且不 panic
	if rep.Total != 4 {
		t.Fatalf("total=%d", rep.Total)
	}
}

// 默认开启 grounding：没在输出里出现过的 flag 提交不出去。
func TestOrchestratorGroundingDefault(t *testing.T) {
	fa := newFakeAdapter(t, "g")
	model := llm.NewScripted(
		llm.Call("submit", `{"flag":"flag{g_secret}","evidence":"猜的"}`), // 没先读文件
		llm.Call("finish", `{"status":"stuck","summary":"交不出去"}`),
	)
	rep, err := NewOrchestrator(fa, model, RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{2 * time.Second},
		Solver:      Config{MaxSteps: 3},
	}).Run(context.Background(), []core.Challenge{{ID: "g"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Solved != 0 || fa.submit != 0 {
		t.Fatalf("grounding 未生效: solved=%d submit=%d", rep.Solved, fa.submit)
	}

	// 显式关闭 grounding 后应能提交
	fa2 := newFakeAdapter(t, "g")
	off := false
	model2 := llm.NewScripted(llm.Call("submit", `{"flag":"flag{g_secret}"}`))
	rep2, err := NewOrchestrator(fa2, model2, RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{2 * time.Second},
		Solver:      Config{MaxSteps: 2},
		Grounding:   &off,
	}).Run(context.Background(), []core.Challenge{{ID: "g"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Solved != 1 {
		t.Fatalf("关闭 grounding 后应能提交: %+v", rep2)
	}
}

// 总预算用尽时不再开新一轮。
func TestOrchestratorTotalBudget(t *testing.T) {
	fa := newFakeAdapter(t, "p", "q")
	model := llm.NewScripted(llm.Call("sh", `{"command":"sleep 0.2"}`))
	rep, err := NewOrchestrator(fa, model, RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{2 * time.Second, 2 * time.Second},
		TotalBudget: 150 * time.Millisecond,
		Solver:      Config{MaxSteps: 3},
	}).Run(context.Background(), []core.Challenge{{ID: "p"}, {ID: "q"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Solved != 0 {
		t.Fatal("不该解出")
	}
	if rep.Total > 2 {
		t.Fatalf("total=%d", rep.Total)
	}
}

// 报告表格不能缺关键信息。
func TestReportTable(t *testing.T) {
	rep := Report{
		Platform: "local", Model: "scripted", Elapsed: 3 * time.Second,
		Total: 1, Solved: 1, Flags: 1,
		Challenges: []ChallengeReport{{ChallengeID: "hello", Category: "misc", Solved: true, Steps: 4, Reason: "solved"}},
	}
	out := rep.Table()
	for _, frag := range []string{"hello", "YES", "1/1", "local"} {
		if !strings.Contains(out, frag) {
			t.Fatalf("表格缺少 %q:\n%s", frag, out)
		}
	}
}

// ---------------------------------------------------------------

func writeFile(dir, name, content string) error {
	rt, err := sandbox.NewLocal(dir)
	if err != nil {
		return err
	}
	defer rt.Close(context.Background())
	if err := rt.WriteFile(context.Background(), name, []byte(content)); err != nil {
		return fmt.Errorf("写 %s: %w", name, err)
	}
	return nil
}
