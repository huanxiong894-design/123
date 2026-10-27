package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/kernel"
	"ctfagent/internal/llm"
)

// cmdDrive 用"外部大脑"驱动解题内核：内核每一步把态势写成文件，外部（人/另一个 agent）
// 把决策写回来。工具执行、沙箱、grounding、提交闸门、容器起停全由 agent 真实完成。
//
// 这是在没有模型 API 时评估 agent 的工程能力的最佳方式：决策可以很强，但工具链必须真的能跑。
func cmdDrive(args []string) int {
	fs := flag.NewFlagSet("drive", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
	driveDir := fs.String("driver-dir", ".driver", "外部决策目录（req-NNN.json / reply-NNN.json）")
	waitStep := fs.Duration("step-timeout", 45*time.Minute, "单步等待外部决策的上限")
	onlyIDs := fs.String("only", "", "只跑这些 id（逗号分隔）")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ad, err := c.adapter(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	list, err := ad.List(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	if *onlyIDs != "" {
		want := map[string]bool{}
		for _, s := range strings.Split(*onlyIDs, ",") {
			want[strings.TrimSpace(s)] = true
		}
		var keep []core.Challenge
		for _, ch := range list {
			if want[ch.ID] {
				keep = append(keep, ch)
			}
		}
		list = keep
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 没有可跑的题目")
		return 1
	}

	fc, err := llm.NewFileChan(*driveDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	fc.Timeout = *waitStep

	tracer, closeTrace, err := newTracer(c.tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	defer closeTrace()

	fmt.Printf("[drive] 外部决策目录：%s（每步读 req-NNN.json，写 reply-NNN.json）\n", fc.Dir)
	orch := kernel.NewOrchestrator(ad, fc, kernel.RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{c.budgetOrDefault(60 * time.Minute)},
		Solver:      c.solverCfg(),
		Grounding:   boolPtr(c.grounding),
		Logf:        c.logf,
		Trace:       tracer,
		OnChallenge: func(r kernel.ChallengeReport) {
			mark := "❌"
			if r.Solved {
				mark = "✅"
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
	return 0
}
