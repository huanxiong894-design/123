package kernel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/llm"
	"ctfagent/internal/sandbox"
)

// Solver 是一道题的解题循环。
//
// 它借鉴 ARTEX 的三个关键机制，但按 CTF 的形状做了简化：
//
//	ARTEX                        → 这里
//	─────────────────────────────────────────────────────────────
//	planner 生成 intent           → 模型自己用 idea 登记假设（省掉一轮固定开销）
//	worker 执行 + record_fact     → 同一模型循环里 sh/py + fact（一次调用做完）
//	graph_overview 注入态势        → Board.Situation() 周期性回灌
//	cold digest 压缩冷节点         → 历史裁剪 + Board.Handoff()
//	report_finding 要证据          → fact 的 evidence 必须逐字来自工具输出
//	CAS 抢单（多 worker）          → 并发在题目粒度上（orchestrator），单题内不抢单
//
// 为什么不做 ARTEX 那种三角色机：CTF 单题目标收敛、时间片短，
// 每步都来一轮 planner 的固定成本大于收益。需要分工时用多轮交接（带 handoff 重跑）。

// Hooks 把平台能力注入内核，内核不认识任何具体平台。
type Hooks struct {
	Submit func(ctx context.Context, flag string) (core.SubmitResult, error)
	Hint   func(ctx context.Context) (string, error)
	Logf   func(format string, args ...any)
	OnStep func(step int, b *core.Board)
	// Trace 是逐事件回调（写 JSONL 用）；nil 表示不记录。
	Trace       func(TraceEvent)
	OutputBytes int64
	Grounding   bool
}

// Config 是解题循环的参数。
type Config struct {
	Model           string
	MaxSteps        int
	Budget          time.Duration
	Temperature     float64
	MaxTokens       int
	SituationBudget int
	SystemPrompt    string
	AllowHint       bool
	HintAfter       time.Duration
	// HistoryLimit 是保留在上下文里的最大消息条数（超过则裁剪并用 Board 摘要压缩）。
	HistoryLimit int
}

// DefaultConfig 给出适合大多数模型的默认值。
func DefaultConfig() Config {
	return Config{
		MaxSteps:        40,
		Budget:          30 * time.Minute,
		Temperature:     0.3,
		MaxTokens:       4096,
		SituationBudget: 4000,
		HistoryLimit:    36,
		HintAfter:       15 * time.Minute,
	}
}

// Result 是一轮解题的结果。
type Result struct {
	ChallengeID string        `json:"challenge_id"`
	Solved      bool          `json:"solved"`
	Unverified  bool          `json:"unverified,omitempty"`
	Flags       []string      `json:"flags,omitempty"`
	Steps       int           `json:"steps"`
	Reason      string        `json:"reason"` // solved | stuck | out_of_scope | budget | steps | error
	Summary     string        `json:"summary,omitempty"`
	Usage       llm.Usage     `json:"usage"`
	Duration    time.Duration `json:"duration_ms"`
	Board       *core.Board   `json:"-"`
}

// Solver 持有一个模型客户端。
type Solver struct {
	client llm.Client
	cfg    Config
}

// New 构造 Solver。
func New(client llm.Client, cfg Config) *Solver { return &Solver{client: client, cfg: cfg} }

// Solve 解一道题。board 为 nil 时新建；传入旧 board 表示"接着上一轮干"。
func (s *Solver) Solve(ctx context.Context, ch *core.Challenge, rt sandbox.Runtime, board *core.Board, gate *core.Gate, hooks Hooks) (Result, error) {
	cfg := s.cfg
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = 40
	}
	if cfg.Budget <= 0 {
		cfg.Budget = 30 * time.Minute
	}
	if cfg.HistoryLimit <= 0 {
		cfg.HistoryLimit = 36
	}
	if hooks.Logf == nil {
		hooks.Logf = func(string, ...any) {}
	}
	if hooks.Submit == nil {
		return Result{}, errors.New("kernel: 必须提供 Submit 钩子")
	}
	if gate == nil {
		gate = core.NewGate(0)
	}
	policy := core.DefaultPolicy()
	if ch.FlagPattern != "" {
		policy.Patterns = []string{ch.FlagPattern}
		policy.AllowUUID = false
	}
	if err := policy.Compile(); err != nil {
		return Result{}, err
	}

	if board == nil {
		board = core.NewBoard(ch)
	} else {
		board.PriorSummary = board.Handoff()
		board.Attempts = nil // 清掉旧动作记录，避免误判重复
	}

	start := time.Now()
	deadline := start.Add(cfg.Budget)
	tools := NewToolSet(rt, board, policy, gate, hooks)
	defs := tools.Definitions()

	sys := cfg.SystemPrompt
	if sys == "" {
		sys = DefaultSystemPrompt
	}
	sys = strings.ReplaceAll(sys, "{{CATEGORY}}", categoryOrUnknown(ch.Category))
	sys = strings.ReplaceAll(sys, "{{TARGETS}}", strings.Join(rt.Targets(), "\n"))

	// 先把附件落地，模型第一眼就知道"文件在哪"，不用花几步去摸。
	brief := ch.Brief()
	if notes := stageAttachments(ctx, rt, ch, hooks.Logf); len(notes) > 0 {
		brief += "\n## 附件已就位\n" + strings.Join(notes, "\n") + "\n"
	}
	history := []llm.Message{{Role: "user", Content: brief}}
	stepsSinceProgress := 0
	lastProgress := progressMark(board)
	emptyTurns := 0
	hintGiven := false

	var total llm.Usage
	res := Result{ChallengeID: ch.ID}
	hooks.trace(TraceEvent{Kind: "start", Note: ch.ID, Content: brief})

	for step := 1; step <= cfg.MaxSteps; step++ {
		if ctx.Err() != nil {
			res.Reason = "cancelled"
			break
		}
		if time.Now().After(deadline) {
			res.Reason = "budget"
			break
		}

		board.Steps = step
		history = injectSituation(history, board, cfg.SituationBudget, step, cfg.HistoryLimit)

		reply, err := s.client.Chat(ctx, llm.Request{
			Model:       cfg.Model,
			System:      sys,
			Messages:    history,
			Tools:       defs,
			Temperature: cfg.Temperature,
			MaxTokens:   cfg.MaxTokens,
		})
		if err != nil {
			// 单独标出来：这是"环境/模型不可用"，不是"这题解不出来"。
			// 调度层据此做熔断，避免 63 道题挨个撞同一堵墙。
			res.Reason = "model_error"
			res.Summary = "模型调用失败: " + err.Error()
			hooks.Logf("[%s] 模型调用失败: %v", ch.ID, err)
			break
		}
		hooks.trace(TraceEvent{
			Kind: "model", Step: step, Content: clipTrace(reply.Message.Content),
			TokensIn: reply.Usage.In, TokensOut: reply.Usage.Out,
		})
		total.In += reply.Usage.In
		total.Out += reply.Usage.Out
		board.TokensIn, board.TokensOut = total.In, total.Out

		history = append(history, reply.Message)

		if len(reply.Message.ToolCalls) == 0 {
			emptyTurns++
			hooks.trace(TraceEvent{Kind: "nudge", Step: step, Note: "no_tool_call"})
			// 模型只说话不动手：给一次明确的推动，两次就收工，避免空转烧 token。
			if emptyTurns >= 2 {
				history = append(history, llm.Message{
					Role:    "user",
					Content: "你已经连续两轮没有调用任何工具。要么立刻调用工具推进，要么调用 finish 说明为什么走不通。",
				})
			} else {
				history = append(history, llm.Message{
					Role:    "user",
					Content: "继续：把你的下一步变成一个具体工具调用（sh / py / http / read …）。",
				})
			}
			continue
		}
		emptyTurns = 0

		for _, tc := range reply.Message.ToolCalls {
			out := tools.Call(ctx, tc)
			hooks.trace(TraceEvent{Kind: "tool", Step: step, Tool: tc.Name, Args: clipTrace(tc.Args), Output: clipTrace(out)})
			history = append(history, llm.Message{
				Role:       "tool",
				ToolCallID: tc.ID,
				Name:       tc.Name,
				Content:    out,
			})
			hooks.Logf("[%s] step %d · %s → %s", ch.ID, step, tc.Name, firstLine(out, 160))
		}

		// 收尾信号
		if why, msg := tools.Finish(); why != "" {
			hooks.trace(TraceEvent{Kind: "finish", Step: step, Note: why, Content: clipTrace(msg)})
			res.Reason = why
			res.Summary = msg
			// 模型可以"自称解出"，但成绩只认提交结果。没有 flag 就不许记成 solved，
			// 否则报告会骗人（真实评测里这等于虚报分数）。
			if why == "solved" && board.SolvedFlags() == 0 {
				res.Reason = "claimed_solved_no_flag"
				res.Summary = strings.TrimSpace("模型声称已解出，但没有任何 flag 通过提交校验。" + msg)
			}
			break
		}

		// flag 数量达标就结束；只拿到部分则提示继续找
		solvedCount := board.SolvedFlags()
		if solvedCount > 0 && ch.FlagCount > 0 && solvedCount >= ch.FlagCount {
			res.Reason = "solved"
			break
		}
		if solvedCount > 0 && ch.FlagCount == 0 {
			res.Reason = "solved"
			break
		}

		// 进展/停滞检测
		mark := progressMark(board)
		if mark != lastProgress {
			lastProgress = mark
			stepsSinceProgress = 0
		} else {
			stepsSinceProgress++
		}
		if stepsSinceProgress >= 5 {
			hooks.trace(TraceEvent{Kind: "nudge", Step: step, Note: "stagnation"})
			history = append(history, llm.Message{
				Role: "user",
				Content: fmt.Sprintf(
					"⚠️ 你已经连续 %d 步没有产生新的事实/假设/产物了。这是典型的原地打转。\n"+
						"现在停下来做三件事之一：\n"+
						"1) 回到题目原文，找被你忽略的线索（附件、提示、非常规入口）；\n"+
						"2) 换一条**机理不同**的路线（不是改 payload 的措辞）；\n"+
						"3) 如果确实走不通，调用 finish 并把已排除的方向写清楚。",
					stepsSinceProgress),
			})
			stepsSinceProgress = 0
		}

		// 提示策略：只在卡够久、且平台支持时给一次
		if cfg.AllowHint && !hintGiven && hooks.Hint != nil && time.Since(start) > cfg.HintAfter && solvedCount == 0 {
			if h, err := hooks.Hint(ctx); err == nil && strings.TrimSpace(h) != "" {
				hooks.trace(TraceEvent{Kind: "hint", Step: step, Content: clipTrace(h)})
				history = append(history, llm.Message{Role: "user", Content: "【平台提示】" + h})
				hintGiven = true
				hooks.Logf("[%s] 已注入平台提示", ch.ID)
			}
		}

		if hooks.OnStep != nil {
			hooks.OnStep(step, board)
		}
	}

	if res.Reason == "" {
		res.Reason = "steps"
	}
	res.Solved = board.SolvedFlags() > 0
	res.Unverified = tools.Unverified()
	for _, f := range board.Flags {
		if f.Correct {
			res.Flags = append(res.Flags, f.Value)
		}
	}
	hooks.trace(TraceEvent{Kind: "done", Note: res.Reason, Reason: res.Reason, Step: board.Steps})
	res.Steps = board.Steps
	res.Usage = total
	res.Duration = time.Since(start)
	res.Board = board
	if res.Summary == "" && res.Reason == "budget" {
		res.Summary = "时间预算用尽"
	}
	return res, nil
}

// ---------------------------------------------------------------------------

// injectSituation 周期性把 Board 压成一条 user 消息塞进历史，并做窗口裁剪。
func injectSituation(history []llm.Message, b *core.Board, budget, step, limit int) []llm.Message {
	var out []llm.Message
	for _, m := range history {
		// 去掉上一条态势注入（避免堆积），只保留最新的
		if m.Role == "user" && strings.HasPrefix(m.Content, "## 当前态势") {
			continue
		}
		out = append(out, m)
	}
	situation := b.Situation(budget)
	out = append(out, llm.Message{
		Role:    "user",
		Content: situation + "\n\n请基于以上态势决定下一步动作（调用工具）。",
	})
	if limit > 0 && len(out) > limit {
		keep := make([]llm.Message, 0, limit)
		keep = append(keep, out[0]) // 题面
		cut := len(out) - (limit - 1)
		summary := llm.Message{
			Role:    "user",
			Content: "【上下文压缩】较早的对话已折叠，要点如下：\n" + b.Handoff(),
		}
		keep = append(keep, summary)
		keep = append(keep, out[cut:]...)
		out = keep
	}
	return out
}

func progressMark(b *core.Board) int {
	return len(b.Facts)*1000 + len(b.Ideas)*100 + len(b.Artifacts)*10 + len(b.Flags)
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func categoryOrUnknown(c string) string {
	if strings.TrimSpace(c) == "" {
		return "unknown"
	}
	return c
}
