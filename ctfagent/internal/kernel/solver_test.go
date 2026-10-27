package kernel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
	"ctfagent/internal/sandbox"
)

// fakePlatform 是一个只有内存的"平台"：把 flag 存在变量里。
// 这说明内核确实不认识任何具体平台——测试里都不需要 network。
type fakePlatform struct {
	flag     string
	submitN  int
	lastFlag string
}

func (f *fakePlatform) submit(_ context.Context, flag string) (core.SubmitResult, error) {
	f.submitN++
	f.lastFlag = flag
	if flag == f.flag {
		return core.SubmitResult{Correct: true, Awarded: 100, Cumulative: 100, CorrectFlags: 1, TotalFlags: 1}, nil
	}
	return core.SubmitResult{Correct: false}, nil
}

func mustLocal(t *testing.T) *sandbox.Local {
	t.Helper()
	rt, err := sandbox.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	return rt
}

// 完整回路：侦察 → 记事实 → 读 flag → 提交 → 循环检测到解出并退出。
func TestSolveEndToEnd(t *testing.T) {
	rt := mustLocal(t)
	if err := os.WriteFile(filepath.Join(rt.Workdir(), "flag.txt"), []byte("flag{end_to_end_ok}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp := &fakePlatform{flag: "flag{end_to_end_ok}"}
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"ls -la && cat flag.txt"}`),
		llm.Call("fact", `{"text":"工作目录里有 flag.txt","evidence":"flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{end_to_end_ok}","evidence":"flag{end_to_end_ok}"}`),
	)
	cfg := DefaultConfig()
	cfg.MaxSteps = 10
	cfg.Budget = 30 * time.Second
	s := New(model, cfg)

	ch := &core.Challenge{ID: "e2e", Category: "misc", FlagCount: 1}
	res, err := s.Solve(context.Background(), ch, rt, nil, core.NewGate(0), Hooks{
		Submit:    fp.submit,
		Grounding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Solved || res.Reason != "solved" {
		t.Fatalf("未解出: %+v", res)
	}
	if len(res.Flags) != 1 || res.Flags[0] != "flag{end_to_end_ok}" {
		t.Fatalf("flags=%v", res.Flags)
	}
	if fp.submitN != 1 || fp.lastFlag != "flag{end_to_end_ok}" {
		t.Fatalf("提交次数=%d flag=%q", fp.submitN, fp.lastFlag)
	}
	if res.Board.SolvedFlags() != 1 || len(res.Board.Facts) != 1 {
		t.Fatalf("board 未记录: %+v", res.Board.Flags)
	}
}

// 模型只说话不动手：应被推两次，第二次后强制收尾，不能无限空转。
func TestSolveEmptyTurnNudge(t *testing.T) {
	rt := mustLocal(t)
	var sawPush, sawStop bool
	model := llm.NewScripted(
		llm.Say("我想想……"),
		llm.Say("再想想……"),
		llm.Say("还是想想……"),
	)
	model.OnCall = func(turn int, req llm.Request) {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "把你的下一步变成一个具体工具调用") {
				sawPush = true
			}
			if strings.Contains(m.Content, "连续两轮没有调用任何工具") {
				sawStop = true
			}
		}
	}
	cfg := DefaultConfig()
	cfg.MaxSteps = 3
	cfg.Budget = 10 * time.Second
	res, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "idle"}, rt, nil, nil, Hooks{
		Submit: func(context.Context, string) (core.SubmitResult, error) { return core.SubmitResult{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawPush || !sawStop {
		t.Fatalf("缺少空转推动: push=%v stop=%v", sawPush, sawStop)
	}
	if res.Solved {
		t.Fatal("不该算解出")
	}
}

// 停滞检测：连续多步毫无进展时注入"换路线"提示。
func TestSolveStagnationNudge(t *testing.T) {
	rt := mustLocal(t)
	var nudge bool
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"true"}`),
		llm.Call("sh", `{"command":"true"}`),
		llm.Call("sh", `{"command":"true"}`),
		llm.Call("sh", `{"command":"true"}`),
		llm.Call("sh", `{"command":"true"}`),
		llm.Call("sh", `{"command":"true"}`),
		llm.Call("sh", `{"command":"true"}`),
	)
	model.OnCall = func(_ int, req llm.Request) {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "原地打转") {
				nudge = true
			}
		}
	}
	cfg := DefaultConfig()
	cfg.MaxSteps = 7
	cfg.Budget = 10 * time.Second
	_, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "loop"}, rt, nil, nil, Hooks{
		Submit: func(context.Context, string) (core.SubmitResult, error) { return core.SubmitResult{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !nudge {
		t.Fatal("连续无进展却没有注入停滞提示")
	}
}

// 多轮重跑：上一轮的 board 必须以"交接摘要"的形式进入新一轮。
func TestSolveCarriesHandoff(t *testing.T) {
	rt := mustLocal(t)
	prev := core.NewBoard(&core.Challenge{ID: "c", Category: "web"})
	prev.AddFact("登录框有 SQLi", "you have an error in your SQL syntax")
	prev.AddIdea("试试 union 注入")

	var sawHandoff bool
	model := llm.NewScripted(llm.Call("finish", `{"status":"stuck","summary":"第二轮也卡住"}`))
	model.OnCall = func(_ int, req llm.Request) {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "上一轮交接") && strings.Contains(m.Content, "登录框有 SQLi") {
				sawHandoff = true
			}
		}
	}
	cfg := DefaultConfig()
	cfg.MaxSteps = 2
	_, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "c"}, rt, prev, nil, Hooks{
		Submit: func(context.Context, string) (core.SubmitResult, error) { return core.SubmitResult{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawHandoff {
		t.Fatal("上一轮事实没有通过交接摘要进入新一轮")
	}
}

// 预算耗尽应干净退出，而不是报错。
func TestSolveBudgetExhausted(t *testing.T) {
	rt := mustLocal(t)
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"sleep 0.3"}`),
		llm.Call("sh", `{"command":"sleep 0.3"}`),
	)
	cfg := DefaultConfig()
	cfg.MaxSteps = 50
	cfg.Budget = 200 * time.Millisecond
	res, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "slow"}, rt, nil, nil, Hooks{
		Submit: func(context.Context, string) (core.SubmitResult, error) { return core.SubmitResult{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "budget" {
		t.Fatalf("reason=%q", res.Reason)
	}
	if res.Solved {
		t.Fatal("不该解出")
	}
}

// finish 的三种状态要如实反映到 Result。
func TestSolveFinishStatus(t *testing.T) {
	rt := mustLocal(t)
	model := llm.NewScripted(llm.Call("finish", `{"status":"out_of_scope","summary":"目标端口不可达"}`))
	cfg := DefaultConfig()
	cfg.MaxSteps = 5
	res, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "dead"}, rt, nil, nil, Hooks{
		Submit: func(context.Context, string) (core.SubmitResult, error) { return core.SubmitResult{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "out_of_scope" || res.Summary != "目标端口不可达" {
		t.Fatalf("res=%+v", res)
	}
}

// 平台自定义 flag 形态（UUID）也要能提交。
func TestSolveCustomFlagPattern(t *testing.T) {
	rt := mustLocal(t)
	uuid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	if err := os.WriteFile(filepath.Join(rt.Workdir(), "out.txt"), []byte("token: "+uuid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp := &fakePlatform{flag: uuid}
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"cat out.txt"}`),
		llm.Call("submit", `{"flag":"`+uuid+`","evidence":"`+uuid+`"}`),
	)
	cfg := DefaultConfig()
	cfg.MaxSteps = 6
	ch := &core.Challenge{ID: "uuid", FlagPattern: `\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`}
	res, err := New(model, cfg).Solve(context.Background(), ch, rt, nil, nil, Hooks{Submit: fp.submit, Grounding: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Solved {
		t.Fatalf("UUID flag 未解出: %+v", res)
	}
}

// trace 必须能把"模型原话 / 工具 / 参数 / 真实输出"都记下来，否则事后没法复盘。
func TestSolveEmitsTrace(t *testing.T) {
	rt := mustLocal(t)
	if err := os.WriteFile(filepath.Join(rt.Workdir(), "flag.txt"), []byte("flag{trace_ok}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"cat flag.txt"}`),
		llm.Call("submit", `{"flag":"flag{trace_ok}","evidence":"flag{trace_ok}"}`),
	)
	cfg := DefaultConfig()
	cfg.MaxSteps = 5
	var kinds []string
	var sawOutput bool
	res, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "tr", FlagCount: 1}, rt, nil, nil, Hooks{
		Grounding: true,
		Submit: func(_ context.Context, f string) (core.SubmitResult, error) {
			return core.SubmitResult{Correct: f == "flag{trace_ok}"}, nil
		},
		Trace: func(ev TraceEvent) {
			kinds = append(kinds, ev.Kind)
			if ev.Kind == "tool" && strings.Contains(ev.Output, "flag{trace_ok}") {
				sawOutput = true
			}
		},
	})
	if err != nil || !res.Solved {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	joined := strings.Join(kinds, ",")
	for _, want := range []string{"start", "model", "tool", "done"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("trace 缺少 %s 事件: %s", want, joined)
		}
	}
	if !sawOutput {
		t.Fatal("trace 里没有记录工具的真实输出")
	}
}

// 没有判题接口时，要明确标记"未验证"，不能让报告看起来像真解出来了。
func TestSolveUnverifiedSubmit(t *testing.T) {
	rt := mustLocal(t)
	if err := os.WriteFile(filepath.Join(rt.Workdir(), "f.txt"), []byte("flag{manual_paste}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"cat f.txt"}`),
		llm.Call("submit", `{"flag":"flag{manual_paste}","evidence":"flag{manual_paste}"}`),
	)
	cfg := DefaultConfig()
	cfg.MaxSteps = 4
	res, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "u"}, rt, nil, nil, Hooks{
		Grounding: true,
		Submit: func(context.Context, string) (core.SubmitResult, error) {
			return core.SubmitResult{Correct: true, Unverified: true, Message: "无判题接口"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Solved {
		t.Fatal("应该算解出（有 flag 了）")
	}
	if !res.Unverified {
		t.Fatal("必须标记为未验证，否则会被当成平台认可的成绩")
	}
}

// 模型不能靠"说"拿到成绩：finish(solved) 但没有任何 flag 通过校验，必须降级。
func TestSolveClaimedSolvedWithoutFlag(t *testing.T) {
	rt := mustLocal(t)
	model := llm.NewScripted(
		llm.Call("sh", `{"command":"echo nothing-here"}`),
		llm.Call("finish", `{"status":"solved","summary":"我觉得解出来了"}`),
	)
	cfg := DefaultConfig()
	cfg.MaxSteps = 3
	res, err := New(model, cfg).Solve(context.Background(), &core.Challenge{ID: "lie"}, rt, nil, nil, Hooks{
		Submit: func(context.Context, string) (core.SubmitResult, error) {
			return core.SubmitResult{Correct: false}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Solved {
		t.Fatal("没有 flag 不能算解出")
	}
	if res.Reason != "claimed_solved_no_flag" {
		t.Fatalf("reason=%q，应该把「自称解出」标出来", res.Reason)
	}
}
