package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
	FIFO        bool            // 严格按输入顺序逐题运行；开启时强制单 worker
	Rounds      []time.Duration // 每一轮的单题预算，长度 = 最大轮数
	TotalBudget time.Duration   // 整场预算
	Gate        *core.Gate
	Solver      Config
	// ClientForChallenge 为每个题目/轮次创建独立模型客户端；nil 时复用 Orchestrator 的默认客户端。
	// 外部大脑（FileChan）模式必须使用它，确保每个并行 agent 有自己的消息邮箱与轮次计数。
	ClientForChallenge func(challengeID string, round int) (llm.Client, error)
	// CheckpointDir 启用逐步落盘；Resume=true 时从该目录恢复未完成题目和已通过题目状态。
	CheckpointDir string
	Resume        bool
	// Grounding 控制是否要求 flag 原文逐字出现在本题真实工具输出里；submit.evidence 仅为可选备注。
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
	if cfg.FIFO {
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
	// Some platforms run shell tools in one shared agent filesystem. Give each run
	// a fresh root so challenge workdirs can be isolated without leaking artifacts
	// across runs; the per-challenge subdirectory is reused across retry rounds.
	runWorkRoot, err := os.MkdirTemp("", "ctfagent-run-")
	if err != nil {
		return Report{}, fmt.Errorf("create isolated work root: %w", err)
	}
	defer os.RemoveAll(runWorkRoot)
	var deadline time.Time
	if o.cfg.TotalBudget > 0 {
		deadline = start.Add(o.cfg.TotalBudget)
	}

	boards := newBoardStore()
	results := map[string]*ChallengeReport{}
	progress := map[string]ChallengeCheckpoint{}
	requested := make(map[string]core.Challenge, len(challenges))
	for _, ch := range challenges {
		requested[ch.ID] = ch
	}
	var checkpointStore *CheckpointStore
	if strings.TrimSpace(o.cfg.CheckpointDir) != "" {
		var err error
		checkpointStore, err = NewScopedCheckpointStore(o.cfg.CheckpointDir, o.adapter.Name())
		if err != nil {
			return Report{}, fmt.Errorf("checkpoint store: %w", err)
		}
		if o.cfg.Resume {
			loaded, err := checkpointStore.LoadAll()
			if err != nil {
				return Report{}, fmt.Errorf("load checkpoints: %w", err)
			}
			for id, cp := range loaded {
				ch, inScope := requested[id]
				if !inScope {
					continue
				}
				progress[id] = cp
				if cp.Board != nil {
					boards.put(id, cp.Board)
				}
				if cp.Status == "solved" {
					cr := reportFromCheckpoint(cp)
					cr.Category = ch.Category
					results[id] = &cr
				}
			}
		}
	}
	var mu sync.Mutex

	// 熔断器：连续 3 道题都卡在"模型调不通"，说明是环境问题，继续跑只是浪费时间。
	var modelErrs atomic.Int32
	var abort atomic.Bool

	order := append([]core.Challenge(nil), challenges...)
	if !o.cfg.FIFO {
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
	}

	// 固定 worker 按 order 领取题目。FIFO 模式下 order 保留调用方顺序且只有一个 worker；
	// priority 模式按分值排序。一个 worker 对同一题负责其全部重试轮次。
	queue := make(chan core.Challenge)
	var wg sync.WaitGroup
	for i := 0; i < o.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ch := range queue {
				if abort.Load() || ctx.Err() != nil {
					continue
				}
				mu.Lock()
				prior, alreadyDone := results[ch.ID]
				mu.Unlock()
				if alreadyDone && prior.Solved {
					continue
				}

				for round := 1; round <= len(o.cfg.Rounds); round++ {
					if abort.Load() || ctx.Err() != nil || (!deadline.IsZero() && !time.Now().Before(deadline)) {
						break
					}
					mu.Lock()
					prior, alreadyDone = results[ch.ID]
					cp, hasCheckpoint := progress[ch.ID]
					mu.Unlock()
					if alreadyDone && prior.Solved {
						break
					}
					if hasCheckpoint && cp.NextRound > round {
						continue
					}

					budget := o.cfg.Rounds[round-1]
					remaining, spent := budget, time.Duration(0)
					if hasCheckpoint && (cp.Status == "running" || (cp.Status == "paused" && cp.NextRound == round)) && cp.Round == round && cp.Spent > 0 {
						spent = cp.Spent
						remaining -= spent
						if remaining <= 0 {
							cp.Status = "paused"
							cp.NextRound = round + 1
							cp.Summary = "上次进程中断前该轮预算已用尽"
							mu.Lock()
							progress[ch.ID] = cp
							mu.Unlock()
							if checkpointStore != nil {
								if err := checkpointStore.Save(cp); err != nil {
									o.cfg.Logf("[%s] 保存 checkpoint 失败: %v", ch.ID, err)
								}
							}
							continue
						}
					}

					if !deadline.IsZero() {
						left := time.Until(deadline)
						if left <= 0 {
							break
						}
						if remaining > left {
							remaining = left
						}
					}
					o.cfg.Logf("[%s] 第 %d/%d 轮，预算 %s，并发 worker=%d", ch.ID, round, len(o.cfg.Rounds), remaining, o.cfg.Concurrency)
					res := o.runOne(ctx, ch, round, remaining, spent, boards, checkpointStore, runWorkRoot)
					cp = checkpointForResult(ch.ID, round, spent+res.budgetSpent, res)
					mu.Lock()
					if previous := results[ch.ID]; previous != nil {
						res.Steps += previous.Steps
						res.ModelCalls += previous.ModelCalls
						res.APIRequests += previous.APIRequests
						res.ToolCalls += previous.ToolCalls
						res.RepeatedActions += previous.RepeatedActions
						res.RepeatedResponses += previous.RepeatedResponses
						res.GroundingRejections += previous.GroundingRejections
						res.NetworkActionsSuppressed += previous.NetworkActionsSuppressed
						res.TokensIn += previous.TokensIn
						res.TokensOut += previous.TokensOut
						res.Duration += previous.Duration
					}
					res.AcceptedFlags = len(res.Flags)
					if res.Board != nil {
						res.CandidateCount = len(res.Board.Candidates)
					}
					boards.put(ch.ID, res.Board)
					results[ch.ID] = &res
					if checkpointStore != nil && res.Board != nil {
						progress[ch.ID] = cp
					}
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
					if res.Solved {
						break
					}
				}
			}
		}()
	}
	for _, ch := range order {
		select {
		case <-ctx.Done():
		case queue <- ch:
		}
	}
	close(queue)
	wg.Wait()

	for _, ch := range challenges {
		if _, ok := results[ch.ID]; !ok {
			if cp, exists := progress[ch.ID]; exists {
				cr := reportFromCheckpoint(cp)
				cr.Category = ch.Category
				if cr.Reason == "" {
					cr.Reason = "paused"
				}
				results[ch.ID] = &cr
			} else {
				cr := ChallengeReport{ChallengeID: ch.ID, Category: ch.Category, Reason: "skipped"}
				results[ch.ID] = &cr
			}
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
	for i := range rep.Challenges {
		cr := rep.Challenges[i]
		rep.Total++
		if cr.Solved {
			rep.Solved++
		}
		rep.Flags += len(cr.Flags)
		cr.AcceptedFlags = len(cr.Flags)
		if cr.Board != nil {
			cr.CandidateCount = len(cr.Board.Candidates)
		}
		rep.AcceptedFlags += cr.AcceptedFlags
		rep.CandidateCount += cr.CandidateCount
		rep.Challenges[i] = cr
		rep.TokensIn += cr.TokensIn
		rep.TokensOut += cr.TokensOut
		rep.ModelCalls += cr.ModelCalls
		rep.APIRequests += cr.APIRequests
		rep.ToolCalls += cr.ToolCalls
		rep.RepeatedActions += cr.RepeatedActions
		rep.RepeatedResponses += cr.RepeatedResponses
		rep.GroundingRejections += cr.GroundingRejections
		rep.NetworkActionsSuppressed += cr.NetworkActionsSuppressed
	}
	rep.Ended = time.Now()
	rep.Elapsed = rep.Ended.Sub(start)
	return rep, nil
}

func checkpointForResult(id string, round int, spent time.Duration, res ChallengeReport) ChallengeCheckpoint {
	status, nextRound := "paused", round+1
	if res.Solved {
		status = "solved"
	}
	if res.Reason == "cancelled" || res.Reason == "model_error" {
		nextRound = round
	}
	return ChallengeCheckpoint{
		ChallengeID: id, Status: status, Round: round, NextRound: nextRound,
		Spent: spent, Summary: res.Summary, Unverified: res.Unverified, Board: res.Board,
	}
}

func reportFromCheckpoint(cp ChallengeCheckpoint) ChallengeReport {
	cr := ChallengeReport{
		ChallengeID: cp.ChallengeID, Round: cp.Round, Summary: cp.Summary,
		Reason: cp.Status, Unverified: cp.Unverified, Board: cp.Board,
	}
	if cp.Board != nil {
		cr.Steps = cp.Board.Steps
		cr.TokensIn = cp.Board.TokensIn
		cr.TokensOut = cp.Board.TokensOut
		for _, f := range cp.Board.Flags {
			if f.Correct {
				cr.Flags = append(cr.Flags, f.Value)
				cr.Solved = true
			}
		}
	}
	if cp.Status == "solved" {
		cr.Solved = true
	}
	return cr
}

// runOne 跑一道题的一轮（含起停靶场）。
func (o *Orchestrator) runOne(ctx context.Context, ch core.Challenge, round int, budget, spentBefore time.Duration, boards *boardStore, checkpointStore *CheckpointStore, runWorkRoot string) (cr ChallengeReport) {
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

	if conn.IsolatedWorkDir {
		if conn.Container != "" {
			cr.Reason = "runtime_failed"
			cr.Summary = "平台请求本地隔离工作目录，但同时指定了容器运行时"
			return cr
		}
		conn.WorkDir = isolatedChallengeWorkDir(runWorkRoot, ch.ID)
		conn.HostDir = conn.WorkDir
		conn.IsolatedWorkDir = false
	}

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
	client := o.client
	if o.cfg.ClientForChallenge != nil {
		client, err = o.cfg.ClientForChallenge(ch.ID, round)
		if err != nil {
			cr.Reason = "client_failed"
			cr.Summary = err.Error()
			return cr
		}
		if client == nil {
			cr.Reason = "client_failed"
			cr.Summary = "ClientForChallenge returned nil"
			return cr
		}
	}
	prev := boards.get(ch.ID)
	remainingBudget := budget - time.Since(start)
	if remainingBudget <= 0 {
		cr.Reason = "budget"
		cr.Summary = "单题时间片在环境初始化期间耗尽"
		cr.Board = prev
		cr.budgetSpent = time.Since(start)
		if checkpointStore != nil && prev != nil {
			cp := checkpointForResult(ch.ID, round, spentBefore+cr.budgetSpent, cr)
			if err := checkpointStore.Save(cp); err != nil {
				o.cfg.Logf("[%s] 保存 checkpoint 失败: %v", ch.ID, err)
			}
		}
		return cr
	}
	budgetCfg.Budget = remainingBudget
	solver := New(client, budgetCfg)

	hooks := Hooks{
		Grounding:   *o.cfg.Grounding,
		OutputBytes: 32 << 10,
		Round:       round,
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

	if checkpointStore != nil {
		hooks.OnStep = func(_ int, b *core.Board) {
			cp := ChallengeCheckpoint{
				ChallengeID: ch2.ID, Status: "running", Round: round, NextRound: round,
				Spent: spentBefore + time.Since(start), Board: b,
			}
			if err := checkpointStore.Save(cp); err != nil {
				o.cfg.Logf("[%s] 保存 checkpoint 失败: %v", ch2.ID, err)
			}
		}
	}
	res, err := solver.Solve(ctx, &ch2, rt, prev, o.cfg.Gate, hooks)
	cr.budgetSpent = time.Since(start)
	if err != nil {
		cr.Reason = "error"
		cr.Summary = err.Error()
		return cr
	}
	cr.Solved = res.Solved
	cr.Flags = res.Flags
	cr.Steps = res.Steps
	cr.ModelCalls = res.ModelCalls
	cr.APIRequests = res.APIRequests
	cr.ToolCalls = res.ToolCalls
	cr.RepeatedActions = res.RepeatedActions
	cr.RepeatedResponses = res.RepeatedResponses
	cr.GroundingRejections = res.GroundingRejections
	cr.NetworkActionsSuppressed = res.NetworkActionsSuppressed
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
	if checkpointStore != nil && merged != nil {
		cp := checkpointForResult(ch.ID, round, spentBefore+cr.budgetSpent, cr)
		if err := checkpointStore.Save(cp); err != nil {
			o.cfg.Logf("[%s] 保存 checkpoint 失败: %v", ch.ID, err)
		}
	}
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

// isolatedChallengeWorkDir returns a stable, path-safe directory for one challenge
// within one Run. Hashing avoids path traversal and collisions from sanitization.
func isolatedChallengeWorkDir(root, challengeID string) string {
	sum := sha256.Sum256([]byte(challengeID))
	return filepath.Join(root, "challenge-"+hex.EncodeToString(sum[:8]))
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
	if cur.FlagCount > out.FlagCount {
		out.FlagCount = cur.FlagCount
	}
	if cur.Phase != "" {
		out.Phase = cur.Phase
	}
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
	for _, c := range cur.Candidates {
		out.AddCandidate(c.Value, c.EvidenceID, c.Tool, c.Source, c.Excerpt)
	}
	for _, f := range cur.Flags {
		out.RecordFlag(f.Value, f.Correct)
	}
	out.PriorSummary = out.Handoff()
	return out
}

// Report 是一次跑分的完整结果。
type Report struct {
	Platform                 string            `json:"platform"`
	Model                    string            `json:"model"`
	Started                  time.Time         `json:"started"`
	Ended                    time.Time         `json:"ended"`
	Elapsed                  time.Duration     `json:"elapsed_ms"`
	Total                    int               `json:"total"`
	Solved                   int               `json:"solved"`
	Flags                    int               `json:"flags"` // accepted flag values
	AcceptedFlags            int               `json:"accepted_flags"`
	CandidateCount           int               `json:"candidate_count"`
	TokensIn                 int               `json:"tokens_in"`
	TokensOut                int               `json:"tokens_out"`
	ModelCalls               int               `json:"model_calls"`
	APIRequests              int               `json:"api_requests"`
	ToolCalls                int               `json:"tool_calls"`
	RepeatedActions          int               `json:"repeated_actions"`
	RepeatedResponses        int               `json:"repeated_responses"`
	GroundingRejections      int               `json:"grounding_rejections"`
	NetworkActionsSuppressed int               `json:"network_actions_suppressed"`
	Challenges               []ChallengeReport `json:"challenges"`
}

// ChallengeReport 是单题结果。
type ChallengeReport struct {
	ChallengeID              string        `json:"challenge_id"`
	Category                 string        `json:"category"`
	Round                    int           `json:"round"`
	Solved                   bool          `json:"solved"`
	Unverified               bool          `json:"unverified,omitempty"`
	Flags                    []string      `json:"flags,omitempty"`
	AcceptedFlags            int           `json:"accepted_flags"`
	CandidateCount           int           `json:"candidate_count"`
	Steps                    int           `json:"steps"`
	ModelCalls               int           `json:"model_calls"`
	APIRequests              int           `json:"api_requests"`
	ToolCalls                int           `json:"tool_calls"`
	RepeatedActions          int           `json:"repeated_actions"`
	RepeatedResponses        int           `json:"repeated_responses"`
	GroundingRejections      int           `json:"grounding_rejections"`
	NetworkActionsSuppressed int           `json:"network_actions_suppressed"`
	Reason                   string        `json:"reason"`
	Summary                  string        `json:"summary,omitempty"`
	TokensIn                 int           `json:"tokens_in"`
	TokensOut                int           `json:"tokens_out"`
	Duration                 time.Duration `json:"duration_ms"`
	Board                    *core.Board   `json:"-"`
	budgetSpent              time.Duration
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
	fmt.Fprintf(&b, "\n总计：%d/%d 题解出 · 已接受 flag %d · 候选 %d · 耗时 %s · token %d/%d\n",
		r.Solved, r.Total, r.AcceptedFlags, r.CandidateCount, r.Elapsed.Round(time.Second), r.TokensIn, r.TokensOut)
	fmt.Fprintf(&b, "API 请求=%d（模型调用=%d）· 工具调用=%d · 重复动作=%d · 同响应=%d · grounding拒绝=%d · 网络动作抑制=%d\n",
		r.APIRequests, r.ModelCalls, r.ToolCalls, r.RepeatedActions, r.RepeatedResponses, r.GroundingRejections, r.NetworkActionsSuppressed)
	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
