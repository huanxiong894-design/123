package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/kernel"
	"ctfagent/internal/llm"
	"ctfagent/internal/platform"
)

// cmdDrive 用"外部大脑"驱动解题内核：内核每一步把态势写成文件，外部 agent 把决策写回来。
// 开启 --agents N 时，每个并行 Solver 使用独立的消息邮箱、Board、工具集和目标环境；
// 调用方需要为每个邮箱安排独立的外部 agent 会话。该命令不会假设或自动创建模型 API。
func cmdDrive(args []string) int {
	fs := flag.NewFlagSet("drive", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
	driveDir := fs.String("driver-dir", ".driver", "外部决策邮箱根目录")
	waitStep := fs.Duration("step-timeout", 45*time.Minute, "单步等待外部决策的上限")
	agents := fs.Int("agents", 1, "并行独立外部 agent 数（1-3；每个 agent 需监听自己的邮箱）")
	schedule := fs.String("schedule", "fifo", "调度顺序：fifo（默认，严格按输入单题串行）或 priority")
	rounds := fs.String("rounds", "20m,20m", "每题各轮时间预算；worker 连续完成当前题的轮次后立即领取下一题")
	specPaths := multiFlag{}
	fs.Var(&specPaths, "spec", "通用 prompt 题目 JSON（platform=prompt 时可重复或传目录；不接平台 API）")
	checkpointDir := fs.String("checkpoint-dir", defaultCheckpointDir(), "每题私有 checkpoint 目录（空字符串关闭）")
	resume := fs.Bool("resume", false, "从 checkpoint 恢复未完成题目")
	onlyIDs := fs.String("only", "", "只跑这些 id（逗号分隔）")
	_ = fs.Parse(args)
	if *agents < 1 || *agents > 3 {
		fmt.Fprintln(os.Stderr, "错误: --agents 必须在 1 到 3 之间（平台并发上限为 3）")
		return 2
	}
	if *schedule != "fifo" && *schedule != "priority" {
		fmt.Fprintln(os.Stderr, "错误: --schedule 只能是 fifo 或 priority")
		return 2
	}
	if *schedule == "fifo" && *agents != 1 {
		fmt.Fprintln(os.Stderr, "错误: fifo 模式保证严格单题顺序，必须使用 --agents 1；并行调度请显式使用 --schedule priority")
		return 2
	}
	budgets, err := parseDurations(*rounds)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误: --rounds:", err)
		return 2
	}
	if c.budget > 0 {
		budgets = []time.Duration{c.budget}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ad, err := buildDriveAdapter(ctx, &c, specPaths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	if c.platform == "prompt" {
		fmt.Println("[模式] 通用 prompt 输入；无 CTF²/平台 API，提交结果仅记录为待人工验证")
	}

	list, err := ad.List(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	list, err = selectDriveChallenges(list, *onlyIDs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 2
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 没有可跑的题目")
		return 1
	}

	root, err := filepath.Abs(*driveDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "邮箱目录解析失败:", err)
		return 1
	}
	fc, err := llm.NewFileChan(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}

	runRoot, err := os.MkdirTemp(fc.Dir, "run-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法创建本轮邮箱目录:", err)
		return 1
	}

	tracer, closeTrace, err := newTracer(c.tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	defer closeTrace()

	ids := make([]string, 0, len(list))
	for _, ch := range list {
		ids = append(ids, ch.ID)
	}
	fmt.Printf("[drive] schedule=%s；agents=%d；题目顺序：%s\n", *schedule, *agents, strings.Join(ids, " → "))
	fmt.Printf("[drive] 本轮邮箱：%s/<challenge>/round-NN/；用 ctfagent mailbox wait/reply 等待并校验 FileChan 消息\n", runRoot)
	orch := kernel.NewOrchestrator(ad, fc, kernel.RunConfig{
		Concurrency:   *agents,
		FIFO:          *schedule == "fifo",
		Rounds:        budgets,
		CheckpointDir: *checkpointDir,
		Resume:        *resume,
		Solver:        c.solverCfg(),
		ClientForChallenge: func(challengeID string, round int) (llm.Client, error) {
			dir := filepath.Join(runRoot, safeMailboxID(challengeID), fmt.Sprintf("round-%02d", round))
			worker, err := llm.NewFileChan(dir)
			if err != nil {
				return nil, err
			}
			worker.Timeout = *waitStep
			return worker, nil
		},
		Grounding: boolPtr(c.grounding),
		Logf:      c.logf,
		Trace:     tracer,
		OnChallenge: func(r kernel.ChallengeReport) {
			mark := "❌"
			if r.Solved {
				mark = "✅"
				if r.Unverified {
					mark = "📝"
				}
			}
			fmt.Printf("%s %-14s %-10s %d 步 %s\n", mark, r.ChallengeID, r.Reason, r.Steps, r.Duration.Round(time.Second))
		},
	})
	rep, err := orch.Run(ctx, list)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	fmt.Print(rep.Table())
	if recorder, ok := ad.(interface{ Recorded() []string }); ok {
		if recorded := recorder.Recorded(); len(recorded) > 0 {
			fmt.Println("\n====== 仅记录、尚未通过平台验证的候选 ======")
			for _, line := range recorded {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) == 2 {
					fmt.Printf("%-20s %s\n", parts[0], parts[1])
				}
			}
			fmt.Println("请只在题目指定的平台/实例提交；拒绝后停止，不尝试变体。")
		}
	}
	return 0
}

// selectDriveChallenges preserves the caller's explicit --only order. Without
// --only it leaves the adapter's list order unchanged.
func selectDriveChallenges(list []core.Challenge, only string) ([]core.Challenge, error) {
	if strings.TrimSpace(only) == "" {
		return list, nil
	}
	byID := make(map[string]core.Challenge, len(list))
	for _, ch := range list {
		byID[ch.ID] = ch
	}
	seen := make(map[string]struct{})
	var ordered []core.Challenge
	for _, raw := range strings.Split(only, ",") {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("--only 中题目 ID 重复: %s", id)
		}
		seen[id] = struct{}{}
		ch, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("--only 指定的题目不存在或不可用: %s", id)
		}
		ordered = append(ordered, ch)
	}
	return ordered, nil
}

// buildDriveAdapter adds generic prompt-spec input to drive without coupling it
// to any challenge platform API.
func buildDriveAdapter(ctx context.Context, c *commonFlags, specPaths multiFlag) (platform.Adapter, error) {
	if c.platform != "prompt" {
		if len(specPaths) > 0 {
			return nil, fmt.Errorf("--spec 仅适用于 --platform prompt")
		}
		return c.adapter(ctx)
	}
	if len(specPaths) == 0 {
		return nil, fmt.Errorf("--platform prompt 需要至少一个 --spec JSON")
	}
	specs, err := platform.LoadPromptSpecs(specPaths.values()...)
	if err != nil {
		return nil, fmt.Errorf("读取 prompt spec 失败: %w", err)
	}
	base := c.suite
	if base == "" {
		base = ".ctfagent-work"
	}
	ad, err := platform.NewPrompt(base, specs)
	if err != nil {
		return nil, fmt.Errorf("创建 prompt adapter 失败: %w", err)
	}
	return ad, nil
}

// safeMailboxID keeps platform IDs from escaping the mailbox root or colliding with path syntax.
func safeMailboxID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "._-")
	if name == "" {
		name = "challenge"
	}
	digest := sha256.Sum256([]byte(id))
	return fmt.Sprintf("%s-%x", name, digest[:4])
}
