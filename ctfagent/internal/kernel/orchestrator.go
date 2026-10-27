package kernel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
	"ctfagent/internal/platform"
	"ctfagent/internal/sandbox"
)

// Orchestrator 负责"一次跑一整批题"：并发窗口、时间片、重试、交接、统计。
//
// 它与 Solver 的分工：
//   - Solver 只懂一道题、不知道时间的意义；
//   - Orchestrator 只懂调度，不知道题目内容。
// 这样换平台、换模型、换题库，都不用改调度逻辑。

// RunConfig 是整场跑分的参数。
type RunConfig struct {
	Concurrency int             // 同时进行的题目数
	Rounds      []time.Duration // 每一轮的单题预算，长度 = 最大轮数
	TotalBudget time.Duration   // 整场预算
	Gate        *core.Gate
	Solver      Config
	// Grounding 控制是否要求 flag/证据逐字出现在真实输出里。
	// nil = 开启（默认；这是"通用 agent"和"乱交 flag"的分水岭），显式 false 才关闭。
	Grounding *bool
	Logf      func(format string, args ...any)
	// OnChallenge 每题结束时回调（CLI 用来实时打印）。
	OnChallenge func(r ChallengeReport)
	// Trace 逐事件回调（JSONL 落盘用）。
	Trace func(ev TraceEvent)
}

// Orchestrator 调度一批题目。
type Orchestrator struct {
	adapter platform.Adapter
	client  llm.Client
	cfg     RunConfig
}

// NewOrchestrator 构造调度器。
func NewOrchestrator(adapter platform.Adapter, client llm.Client, cfg RunConfig) *Orchestrator {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if len(cfg.Rounds) == 0 {
		cfg.Rounds = []time.Duration{20 * time.Minute}
	}
	if cfg.Grounding == nil {
		on := true
		cfg.Grounding = &on
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Gate == nil {
		cfg.Gate = core.NewGate(0)
	}
	return &Orchestrator{adapter: adapter, client: client, cfg: cfg}
}

// Run 跑完整批题，返回报告。
func (o *Orchestrator) Run(ctx context.Context, challenges []core.Challenge) (Report, error) {
	start := time.Now()
	rep := Report{Platform: o.adapter.Name(), Model: o.client.Name(), Started: start}
	var deadline time.Time
	if o.cfg.TotalBudget > 0 {
		deadline = start.Add(o.cfg.TotalBudget)
	}

	boards := newBoardStore()
	results := map[string]*ChallengeReport{}
	var mu sync.Mutex

	// 熔断器：连续 3 道题都卡在"模型调不通"，说明是环境问题，继续跑只是浪费时间。
	var modelErrs atomic.Int32
	var abort atomic.Bool

	// 优先级：分值高的先跑、同分按 flag 少的先跑（更容易拿分）。
	order := append([]core.Challenge(nil), challenges...)
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.MaxScore != b.MaxScore {
			return a.MaxScore > b.MaxScore
		}
		if a.FlagCount != b.FlagCount {
			return a.FlagCount < b.FlagCount
		}
		return a.ID < b.ID
	})

	for round := 0; round < len(o.cfg.Rounds); round++ {
		if !deadline.IsZero() && time.Now().After(deadline) {
			o.cfg.Logf("[plan] 总预算耗尽，收场")
			break
		}
		// 本轮要跑的题：还没解的
		var todo []core.Challenge
		for _, ch := range order {
			if cr, ok := results[ch.ID]; ok && cr.Solved {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			todo = append(todo, ch)
		}
		if len(todo) == 0 {
			break
		}
		budget := o.cfg.Rounds[round]
		o.cfg.Logf("[round %d] 待跑 %d 题，单题预算 %s，并发 %d", round+1, len(todo), budget, o.cfg.Concurrency)

		var wg sync.WaitGroup
		queue := make(chan core.Challenge)
		for i := 0; i < o.cfg.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ch := range queue {
					if abort.Load() || ctx.Err() != nil {
						continue
					}
					if !deadline.IsZero() && time.Now().After(deadline) {
						continue
					}
					res := o.runOne(ctx, ch, round+1, budget, boards)
					mu.Lock()
					boards.put(ch.ID, res.Board)
					results[ch.ID] = &res
					mu.Unlock()
					if res.Reason == "model_error" {
						if modelErrs.Add(1) >= 3 {
							if !abort.Swap(true) {
								o.cfg.Logf("[plan] 连续 %d 道题模型调用失败，判定为环境问题，提前收场", modelErrs.Load())
							}
						}
					} else {
						modelErrs.Store(0)
					}
					if o.cfg.OnChallenge != nil {
						o.cfg.OnChallenge(res)
					}
				}
			}()
		}
		for _, ch := range todo {
			select {
			case <-ctx.Done():
			case queue <- ch:
			}
		}
		close(queue)
		wg.Wait()
	}

	// 汇总：没跑到（熔断/预算切断）的题也要出现在报告里，否则统计会偏乐观。
	for _, ch := range challenges {
		if _, ok := results[ch.ID]; !ok {
			cr := ChallengeReport{ChallengeID: ch.ID, Category: ch.Category, Reason: "skipped"}
			results[ch.ID] = &cr
		}
	}
	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rep.Challenges = append(rep.Challenges, *results[id])
	}
	for _, cr := range rep.Challenges {
		rep.Total++
		if cr.Solved {
			rep.Solved++
		}
		rep.Flags += len(cr.Flags)
		rep.TokensIn += cr.TokensIn
		rep.TokensOut += cr.TokensOut
	}
	rep.Ended = time.Now()
	rep.Elapsed = rep.Ended.Sub(start)
	return rep, nil
}

// runOne 跑一道题的一轮（含起停靶场）。
func (o *Orchestrator) runOne(ctx context.Context, ch core.Challenge, round int, budget time.Duration, boards *boardStore) (cr ChallengeReport) {
	cr = ChallengeReport{ChallengeID: ch.ID, Category: ch.Category, Round: round}
	start := time.Now()
	defer func() { cr.Duration = time.Since(start) }()

	conn, err := o.adapter.Acquire(ctx, ch.ID)
	if err != nil {
		cr.Reason = "acquire_failed"
		cr.Summary = err.Error()
		o.cfg.Logf("[%s] 起环境失败: %v", ch.ID, err)
		return cr
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := o.adapter.Release(c, ch.ID); err != nil {
			o.cfg.Logf("[%s] 释放环境失败: %v", ch.ID, err)
		}
	}()

	rt, err := buildRuntime(conn, ch)
	if err != nil {
		cr.Reason = "runtime_failed"
		cr.Summary = err.Error()
		return cr
	}
	defer rt.Close(context.WithoutCancel(ctx))

	// 题面里补上真实可达地址（有些平台 List 时不返回地址）
	ch2 := ch
	if len(conn.Targets) > 0 {
		ch2.Targets = conn.Targets
	}

	policy := o.adapter.Policy(&ch2)
	if err := policy.Compile(); err != nil {
		cr.Reason = "policy_invalid"
		cr.Summary = err.Error()
		return cr
	}

	budgetCfg := o.cfg.Solver
	budgetCfg.Budget = budget
	solver := New(o.client, budgetCfg)

	hooks := Hooks{
		Grounding:   *o.cfg.Grounding,
		OutputBytes: 32 << 10,
		Logf:        o.cfg.Logf,
		Submit: func(c context.Context, flag string) (core.SubmitResult, error) {
			return o.adapter.Submit(c, ch2.ID, flag)
		},
		Hint: func(c context.Context) (string, error) {
			return o.adapter.Hint(c, ch2.ID)
		},
	}
	if o.cfg.Trace != nil {
		hooks.Trace = func(ev TraceEvent) {
			ev.Challenge = ch2.ID
			o.cfg.Trace(ev)
		}
	}

	prev := boards.get(ch.ID)
	res, err := solver.Solve(ctx, &ch2, rt, prev, o.cfg.Gate, hooks)
	if err != nil {
		cr.Reason = "error"
		cr.Summary = err.Error()
		return cr
	}
	cr.Solved = res.Solved
	cr.Flags = res.Flags
	cr.Steps = res.Steps
	cr.Reason = res.Reason
	cr.Summary = res.Summary
	cr.Unverified = res.Unverified
	cr.TokensIn = res.Usage.In
	cr.TokensOut = res.Usage.Out
	cr.Duration = res.Duration
	cr.Board = res.Board

	// 把本轮结果并入累积 board（下一轮交接用）
	merged := mergeBoards(prev, res.Board)
	cr.Board = merged
	return cr
}

// boardStore 是跨轮累积的作战板仓库。多 worker 并发读写，必须加锁
// （直接传 map 会在同一轮里被别的 worker 并发写，go test -race 会抓到）。
type boardStore struct {
	mu sync.Mutex
	m  map[string]*core.Board
}

func newBoardStore() *boardStore { return &boardStore{m: map[string]*core.Board{}} }

func (s *boardStore) get(id string) *core.Board {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}

func (s *boardStore) put(id string, b *core.Board) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = b
}

// buildRuntime 把 Conn 翻译成一个具体的沙箱实现。
func buildRuntime(conn *platform.Conn, ch core.Challenge) (sandbox.Runtime, error) {
	if conn.Container != "" {
		rt, err := sandbox.NewDocker(conn.Container, conn.WorkDir, conn.Targets)
		if err != nil {
			return nil, err
		}
		return rt, nil
	}
	dir := conn.WorkDir
	if dir == "" {
		dir = conn.HostDir
	}
	rt, err := sandbox.NewLocal(dir)
	if err != nil {
		return nil, err
	}
	rt.SetTargets(conn.Targets)
	return rt, nil
}

// mergeBoards 把新一轮的事实/假设/产物并入累积板，避免下轮从零开始。
func mergeBoards(prev, cur *core.Board) *core.Board {
	if cur == nil {
		return prev
	}
	if prev == nil {
		return cur
	}
	out := prev.Clone()
	out.Steps = cur.Steps
	out.TokensIn += cur.TokensIn
	out.TokensOut += cur.TokensOut
	for _, f := range cur.Facts {
		seen := false
		for _, pf := range out.Facts {
			if pf.Text == f.Text {
				seen = true
				break
			}
		}
		if !seen {
			out.Facts = append(out.Facts, f)
		}
	}
	for _, i := range cur.Ideas {
		found := false
		for k, pi := range out.Ideas {
			if pi.Text == i.Text {
				out.Ideas[k].Status = i.Status
				out.Ideas[k].Verdict = i.Verdict
				found = true
				break
			}
		}
		if !found {
			out.Ideas = append(out.Ideas, i)
		}
	}
	for _, a := range cur.Artifacts {
		out.AddArtifact(a.Kind, a.Value, a.Note)
	}
	for _, f := range cur.Flags {
		out.RecordFlag(f.Value, f.Correct)
	}
	out.PriorSummary = out.Handoff()
	return out
}

// Report 是一次跑分的完整结果。
type Report struct {
	Platform   string            `json:"platform"`
	Model      string            `json:"model"`
	Started    time.Time         `json:"started"`
	Ended      time.Time         `json:"ended"`
	Elapsed    time.Duration     `json:"elapsed_ms"`
	Total      int               `json:"total"`
	Solved     int               `json:"solved"`
	Flags      int               `json:"flags"`
	TokensIn   int               `json:"tokens_in"`
	TokensOut  int               `json:"tokens_out"`
	Challenges []ChallengeReport `json:"challenges"`
}

// ChallengeReport 是单题结果。
type ChallengeReport struct {
	ChallengeID string        `json:"challenge_id"`
	Category    string        `json:"category"`
	Round       int           `json:"round"`
	Solved      bool          `json:"solved"`
	Unverified  bool          `json:"unverified,omitempty"`
	Flags       []string      `json:"flags,omitempty"`
	Steps       int           `json:"steps"`
	Reason      string        `json:"reason"`
	Summary     string        `json:"summary,omitempty"`
	TokensIn    int           `json:"tokens_in"`
	TokensOut   int           `json:"tokens_out"`
	Duration    time.Duration `json:"duration_ms"`
	Board       *core.Board   `json:"-"`
}

// Table 渲染一个人看的总结表。
func (r Report) Table() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n──────── %s · %s ────────\n", r.Platform, r.Model)
	fmt.Fprintf(&b, "%-28s %-10s %-6s %-6s %-8s %s\n", "CHALLENGE", "CATEGORY", "SOLVED", "STEPS", "耗时", "结论")
	for _, c := range r.Challenges {
		solved := "no"
		if c.Solved {
			solved = "YES"
			if c.Unverified {
				solved = "YES?"
			}
			if len(c.Flags) > 1 {
				solved = fmt.Sprintf("YES×%d", len(c.Flags))
			}
		}
		fmt.Fprintf(&b, "%-28s %-10s %-6s %-6d %-8s %s\n",
			trunc(c.ChallengeID, 28), trunc(c.Category, 10), solved, c.Steps,
			c.Duration.Round(time.Second), trunc(c.Reason, 20))
	}
	fmt.Fprintf(&b, "\n总计：%d/%d 题解出 · flag %d · 耗时 %s · token %d/%d\n",
		r.Solved, r.Total, r.Flags, r.Elapsed.Round(time.Second), r.TokensIn, r.TokensOut)
	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
