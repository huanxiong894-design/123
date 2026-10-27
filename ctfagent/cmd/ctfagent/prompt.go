package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"ctfagent/internal/core"
	"ctfagent/internal/kernel"
	"ctfagent/internal/platform"
)

// cmdPrompt 是"提示词接入"的入口。
//
// 场景：平台不给你 List/Submit 接口，只给你一段题面（网页上贴过来、或会话里发过来），
// 容器地址写在题面里，flag 要人工去网页交。那就把题面喂给它：
//
//	# 1) 直接贴一段文本 + 目标地址
//	ctfagent prompt --text-file q1.txt --id q1 --category web \
//	    --target http://10.0.1.5:8080 --trace q1.trace.jsonl
//
//	# 2) 已经整理成 spec（可以一次跑多题）
//	ctfagent prompt --spec examples/prompt/q1.json
//
//	# 3) 如果平台其实还有 openapi 可交 flag，就顺手接上（提交是真验证的）
//	ctfagent prompt --spec q1.json --submit-tsec \
//	    --base-url https://... --token ...
func cmdPrompt(args []string) int {
	fs := flag.NewFlagSet("prompt", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
	var (
		specPaths = multiFlag{}
		textFile  = fs.String("text-file", "", "题面文本文件（- 表示 stdin）")
		id        = fs.String("id", "q1", "题目 id")
		title     = fs.String("title", "", "题目标题")
		category  = fs.String("category", "", "分类提示（web/pwn/rev/crypto/misc/cloud）")
		targets   = multiFlag{}
		pattern   = fs.String("flag-pattern", "", "flag 正则（留空用默认策略）")
		flagCount = fs.Int("flag-count", 0, "flag 数量（0=未知）")
		container = fs.String("container", "", "平台已经起好的容器 id（给了就直接 docker exec 进去）")
		workdir   = fs.String("workdir", "", "宿主工作目录（默认 ./.ctfagent-work/<id>）")
		submitTS  = fs.Bool("submit-tsec", false, "用 TSecBench openapi 提交（没有判题接口时留空）")
		out       = fs.String("out", "", "把报告写成 JSON")
		conc      = fs.Int("concurrency", 1, "同时进行的题目数")
		onlyIDs   = fs.String("only", "", "只跑这些 id（逗号分隔）")
	)
	fs.Var(&specPaths, "spec", "题目 spec JSON（可重复；也可传目录）")
	fs.Var(&targets, "target", "可达目标地址（可重复）")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	specs, err := buildPromptSpecs(specPaths, *textFile, *id, *title, *category, targets, *pattern, *flagCount, *container, *workdir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 2
	}
	if len(specs) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 需要 --spec 或 --text-file（附 --target）")
		return 2
	}

	base := c.suite
	if base == "" {
		base = ".ctfagent-work"
	}
	ad, err := platform.NewPrompt(base, specs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	if *submitTS {
		if c.baseURL == "" || c.token == "" {
			fmt.Fprintln(os.Stderr, "错误: --submit-tsec 需要 --base-url 与 --token")
			return 2
		}
		tsec := platform.NewTSec(platform.TSecConfig{BaseURL: c.baseURL, Token: c.token, SkipVPNCheck: c.skipVPN})
		ad.SubmitFn = func(ctx context.Context, cid, flag string) (core.SubmitResult, error) {
			return tsec.Submit(ctx, cid, flag)
		}
		fmt.Println("[模式] 有判题接口：flag 会真的提交到平台")
	} else {
		fmt.Println("[模式] 无判题接口：flag 会记下来，运行结束打印给你人工提交")
	}

	tracer, closeTrace, err := newTracer(c.tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	defer closeTrace()

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

	orch := kernel.NewOrchestrator(ad, c.client(), kernel.RunConfig{
		Concurrency: *conc,
		Rounds:      []time.Duration{c.budgetOrDefault(30 * time.Minute)},
		Solver:      c.solverCfg(),
		Grounding:   boolPtr(c.grounding),
		Logf:        c.logf,
		Trace:       tracer,
		OnChallenge: func(r kernel.ChallengeReport) {
			mark := "❌"
			if r.Solved {
				mark = "✅"
				if r.Unverified {
					mark = "📝"
				}
			}
			c.logf("%s %-20s %-12s %d 步 %s", mark, r.ChallengeID, r.Reason, r.Steps, r.Duration.Round(time.Second))
		},
	})
	rep, err := orch.Run(ctx, list)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	fmt.Print(rep.Table())

	if rec := ad.Recorded(); len(rec) > 0 {
		fmt.Println("\n====== 需要人工提交的 flag ======")
		for _, line := range rec {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 {
				fmt.Printf("%-20s %s\n", parts[0], parts[1])
			}
		}
		fmt.Println("（本模式没有判题接口，flag 未经平台验证；交完请回填结果以便复盘）")
	}
	if *out != "" {
		if err := writeJSON(*out, map[string]any{
			"report":   rep,
			"recorded": ad.Recorded(),
			"mode":     "prompt",
		}); err != nil {
			fmt.Fprintln(os.Stderr, "写报告失败:", err)
		} else {
			fmt.Printf("报告已写入 %s\n", *out)
		}
	}
	if rep.Solved > 0 {
		return 0
	}
	return 1
}

// buildPromptSpecs 把"贴过来的题面"整理成 spec。
func buildPromptSpecs(paths multiFlag, textFile, id, title, category string, targets multiFlag, pattern string, flagCount int, container, workdir string) ([]platform.PromptSpec, error) {
	if sf := paths.values(); len(sf) > 0 {
		specs, err := platform.LoadPromptSpecs(sf...)
		if err != nil {
			return nil, err
		}
		// 命令行上的 --target 可以覆盖/补充 spec 里的目标（临时换地址很方便）
		if len(targets) > 0 && len(specs) == 1 {
			specs[0].Targets = targets.values()
		}
		return specs, nil
	}
	if textFile == "" {
		return nil, nil
	}
	var data []byte
	var err error
	if textFile == "-" {
		data, err = readAll(os.Stdin)
	} else {
		data, err = os.ReadFile(textFile)
	}
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, fmt.Errorf("题面为空")
	}
	return []platform.PromptSpec{{
		ID:          id,
		Title:       title,
		Category:    category,
		Prompt:      text,
		Targets:     targets.values(),
		FlagPattern: pattern,
		FlagCount:   flagCount,
		Container:   container,
		WorkDir:     workdir,
	}}, nil
}

// multiFlag 是"可重复出现的参数"（--spec a --spec b）。
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
func (m multiFlag) values() []string    { return []string(m) }

func readAll(f *os.File) ([]byte, error) { return io.ReadAll(f) }

// newTracer 返回一个把事件写成 JSONL 的回调；路径为空时返回 nil（不记录）。
func newTracer(path string) (func(kernel.TraceEvent), func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	var mu sync.Mutex
	enc := json.NewEncoder(f)
	return func(ev kernel.TraceEvent) {
			mu.Lock()
			defer mu.Unlock()
			if err := enc.Encode(ev); err != nil {
				log.Printf("写 trace 失败: %v", err)
			}
		}, func() {
			f.Close()
			log.Printf("trace 已写入 %s", path)
		}, nil
}
