// Command ctfagent 是一个通用的 CTF 自动解题 agent。
//
// 它不绑定任何评测平台：TSecBench、CTFd、本地题库、自建 API 都只是"适配器"。
// 同一套解题内核可以在本地题库上迭代，再拿去平台上测能力。
//
//	ctfagent demo                          # 不用 API key，跑通整条回路
//	ctfagent list   --platform local --suite ./examples/suite
//	ctfagent solve  --platform local --suite ./examples/suite --id warmup
//	ctfagent run    --platform local --suite ./examples/suite --out report.json
//	ctfagent run    --platform tsec --concurrency 3
//	ctfagent doctor
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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
	"ctfagent/internal/sandbox"
)

const version = "0.6.0"

func boolPtr(b bool) *bool { return &b }

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 2 {
		usage()
		return 2
	}
	switch os.Args[1] {
	case "demo":
		return cmdDemo(os.Args[2:])
	case "list":
		return cmdList(os.Args[2:])
	case "solve":
		return cmdSolve(os.Args[2:])
	case "run":
		return cmdRun(os.Args[2:])
	case "prompt":
		return cmdPrompt(os.Args[2:])
	case "drive":
		return cmdDrive(os.Args[2:])
	case "doctor":
		return cmdDoctor(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("ctfagent %s\n", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		usage()
		return 2
	}
}

func usage() {
	fmt.Print(`ctfagent — 通用 CTF 自动解题 agent

用法:
  ctfagent demo     [--model deepseek-chat]            用剧本模型跑通全流程（不花钱）
  ctfagent list     --platform local --suite DIR        列出题目
  ctfagent solve    --platform local --suite DIR --id ID  解一道题
  ctfagent run      --platform local --suite DIR        跑整批
  ctfagent prompt   --spec q1.json | --text-file q.txt  提示词接入（题面是贴过来的）
  ctfagent drive    --platform tsec --only <题号>         外部大脑驱动（无模型 API 时用）
  ctfagent doctor                                       环境自检
  ctfagent version

平台:
  --platform local  --suite DIR                         本地题库（challenge.json + flag.txt）
  --platform tsec   --base-url URL --token TOKEN        TSecBench（也可用环境变量）

模型（OpenAI 兼容端点）:
  --model NAME --llm-url URL --api-key KEY
  或环境变量 CTFAGENT_MODEL / CTFAGENT_LLM_URL / CTFAGENT_API_KEY

示例:
  export CTFAGENT_MODEL=deepseek-chat
  export CTFAGENT_LLM_URL=https://api.deepseek.com/v1
  export CTFAGENT_API_KEY=sk-xxx
  ctfagent run --platform local --suite ./examples/suite --concurrency 2
`)
}

// ---------------------------------------------------------------------------
// 公共：平台与模型
// ---------------------------------------------------------------------------

type commonFlags struct {
	platform string
	suite    string
	baseURL  string
	token    string
	skipVPN  bool

	model     string
	llmURL    string
	apiKey    string
	temp      float64
	maxTokens int
	maxSteps  int
	budget    time.Duration
	prompt    string
	grounding bool
	allowHint bool
	fresh     bool
	tracePath string
	verbose   bool
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.platform, "platform", "local", "平台：local | tsec")
	fs.StringVar(&c.suite, "suite", "", "本地题库目录（platform=local）")
	fs.StringVar(&c.baseURL, "base-url", env("BENCHMARK_BASE_URL", ""), "平台地址（platform=tsec）")
	fs.StringVar(&c.token, "token", env("BENCHMARK_TOKEN", ""), "平台 token（platform=tsec）")
	fs.BoolVar(&c.skipVPN, "skip-vpn", false, "跳过 VPN 预检（仅本地联调）")

	fs.StringVar(&c.model, "model", env("CTFAGENT_MODEL", "deepseek-chat"), "模型名")
	fs.StringVar(&c.llmURL, "llm-url", env("CTFAGENT_LLM_URL", "https://api.deepseek.com/v1"), "模型 OpenAI 兼容端点")
	fs.StringVar(&c.apiKey, "api-key", env("CTFAGENT_API_KEY", ""), "模型 API Key")
	fs.Float64Var(&c.temp, "temperature", 0.3, "采样温度")
	fs.IntVar(&c.maxTokens, "max-tokens", 4096, "单轮回复 token 上限")
	fs.IntVar(&c.maxSteps, "max-steps", 40, "单题最大步数")
	fs.DurationVar(&c.budget, "budget", 0, "单题时间预算（0=用调度默认）")
	fs.StringVar(&c.prompt, "prompt", "", "自定义 system prompt 文件")
	fs.BoolVar(&c.grounding, "grounding", true, "flag 必须逐字出现在工具输出中才允许提交")
	fs.BoolVar(&c.allowHint, "hints", false, "允许向平台取提示（可能扣分）")
	fs.BoolVar(&c.fresh, "fresh", false, "本地题库：清空工作目录后重跑（默认保留上一轮产物）")
	fs.StringVar(&c.tracePath, "trace", "", "把每一步（模型原话/工具/输出）写成 JSONL，便于事后复盘")
	fs.BoolVar(&c.verbose, "v", true, "打印每一步动作")
}

// adapter 按参数构造平台适配器。
func (c *commonFlags) adapter(ctx context.Context) (platform.Adapter, error) {
	switch c.platform {
	case "local", "":
		if c.suite == "" {
			return nil, fmt.Errorf("--platform local 需要 --suite 目录")
		}
		s, err := platform.NewLocalSuite(c.suite)
		if err != nil {
			return nil, err
		}
		s.Fresh = c.fresh
		return s, nil
	case "tsec", "tsecbench":
		if c.baseURL == "" || c.token == "" {
			return nil, fmt.Errorf("--platform tsec 需要 --base-url 与 --token（或 BENCHMARK_BASE_URL / BENCHMARK_TOKEN）")
		}
		a := platform.NewTSec(platform.TSecConfig{BaseURL: c.baseURL, Token: c.token, SkipVPNCheck: c.skipVPN})
		if !c.skipVPN {
			if err := a.CheckVPN(ctx); err != nil {
				return nil, err
			}
		}
		return a, nil
	default:
		return nil, fmt.Errorf("未知平台 %q（支持: local, tsec）", c.platform)
	}
}

// client 按参数构造模型客户端。
func (c *commonFlags) client() llm.Client {
	return llm.NewOpenAI(c.llmURL, c.apiKey)
}

// solverCfg 把公共参数翻译成内核配置。
func (c *commonFlags) solverCfg() kernel.Config {
	cfg := kernel.DefaultConfig()
	cfg.Model = c.model
	cfg.MaxSteps = c.maxSteps
	if c.budget > 0 {
		cfg.Budget = c.budget
	}
	cfg.Temperature = c.temp
	cfg.MaxTokens = c.maxTokens
	cfg.AllowHint = c.allowHint
	if c.prompt != "" {
		if data, err := os.ReadFile(c.prompt); err == nil {
			cfg.SystemPrompt = string(data)
		} else {
			log.Printf("读取提示词失败: %v", err)
		}
	}
	return cfg
}

func (c *commonFlags) logf(format string, args ...any) {
	if c.verbose {
		log.Printf(format, args...)
	}
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
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
	fmt.Printf("%-28s %-10s %-6s %-8s %s\n", "ID", "CATEGORY", "FLAGS", "SCORE", "TITLE/PROMPT")
	for _, ch := range list {
		fmt.Printf("%-28s %-10s %-6d %-8d %s\n",
			trunc(ch.ID, 28), trunc(catOf(ch.Category), 10), ch.FlagCount, ch.MaxScore, trunc(oneLine(ch.Prompt), 50))
	}
	fmt.Printf("\n共 %d 题\n", len(list))
	return 0
}

// ---------------------------------------------------------------------------
// solve（单题）
// ---------------------------------------------------------------------------

func cmdSolve(args []string) int {
	fs := flag.NewFlagSet("solve", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
	id := fs.String("id", "", "题目 id")
	out := fs.String("out", "", "把结果写成 JSON")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Fprintln(os.Stderr, "错误: 需要 --id")
		return 2
	}

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
	var target *core.Challenge
	for i := range list {
		if list[i].ID == *id {
			target = &list[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(os.Stderr, "错误: 找不到题目 %s\n", *id)
		return 1
	}

	tracer, closeTrace, err := newTracer(c.tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	defer closeTrace()
	orch := kernel.NewOrchestrator(ad, c.client(), kernel.RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{c.budgetOrDefault(20 * time.Minute)},
		TotalBudget: 0,
		Solver:      c.solverCfg(),
		Grounding:   boolPtr(c.grounding),
		Logf:        c.logf,
		Trace:       tracer,
	})
	rep, err := orch.Run(ctx, []core.Challenge{*target})
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	fmt.Print(rep.Table())
	if *out != "" {
		_ = writeJSON(*out, rep)
	}
	if rep.Solved > 0 {
		return 0
	}
	return 1
}

// ---------------------------------------------------------------------------
// run（整批）
// ---------------------------------------------------------------------------

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
	conc := fs.Int("concurrency", 2, "同时进行的题目数")
	rounds := fs.String("rounds", "20m", "每轮单题预算，逗号分隔（长度=最大轮数）")
	total := fs.Duration("total-budget", 0, "整场预算（0=不限）")
	out := fs.String("out", "report.json", "报告输出路径")
	only := fs.String("only", "", "只跑这些 id（逗号分隔）")
	_ = fs.Parse(args)

	budgets, err := parseDurations(*rounds)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误: --rounds:", err)
		return 2
	}

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
	if *only != "" {
		want := map[string]bool{}
		for _, id := range strings.Split(*only, ",") {
			want[strings.TrimSpace(id)] = true
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

	tracer, closeTrace, err := newTracer(c.tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	defer closeTrace()
	orch := kernel.NewOrchestrator(ad, c.client(), kernel.RunConfig{
		Concurrency: *conc,
		Rounds:      budgets,
		TotalBudget: *total,
		Solver:      c.solverCfg(),
		Grounding:   boolPtr(c.grounding),
		Logf:        c.logf,
		Trace:       tracer,
		OnChallenge: func(r kernel.ChallengeReport) {
			mark := "❌"
			if r.Solved {
				mark = "✅"
			}
			c.logf("%s %-24s %-8s %d 步 %s", mark, r.ChallengeID, r.Reason, r.Steps, r.Duration.Round(time.Second))
		},
	})
	rep, err := orch.Run(ctx, list)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	fmt.Print(rep.Table())
	if *out != "" {
		if err := writeJSON(*out, rep); err != nil {
			fmt.Fprintln(os.Stderr, "写报告失败:", err)
		} else {
			fmt.Printf("报告已写入 %s\n", *out)
		}
	}
	return 0
}

func (c *commonFlags) budgetOrDefault(d time.Duration) time.Duration {
	if c.budget > 0 {
		return c.budget
	}
	return d
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	var c commonFlags
	c.bind(fs)
	_ = fs.Parse(args)
	ctx := context.Background()
	ok := true

	fmt.Println("== 环境自检 ==")
	// 1. 模型
	if c.apiKey == "" {
		fmt.Println("[!] 未设置模型 API Key（CTFAGENT_API_KEY / --api-key）：只有 demo 能跑")
	} else {
		fmt.Printf("[✓] 模型端点 %s / %s\n", c.llmURL, c.model)
		cl := llm.NewOpenAI(c.llmURL, c.apiKey)
		cl.Retries = 1
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := cl.Chat(tctx, llm.Request{
			Model:     c.model,
			Messages:  []llm.Message{{Role: "user", Content: "回复 ok 两个字母即可。"}},
			MaxTokens: 8,
		})
		cancel()
		if err != nil {
			fmt.Printf("[✗] 模型连通性: %v\n", err)
			ok = false
		} else {
			fmt.Println("[✓] 模型连通性正常")
		}
	}

	// 2. docker（容器类题目需要）
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	if err := sandbox.DockerAvailable(dctx); err != nil {
		fmt.Println("[i] docker 不可用：只能跑本地目录类题目（misc/rev/crypto 足够）")
	} else {
		fmt.Println("[✓] docker 可用")
	}
	dcancel()

	// 3. 平台
	if c.platform == "tsec" {
		if c.baseURL == "" || c.token == "" {
			fmt.Println("[✗] platform=tsec 但缺少 --base-url/--token")
			ok = false
		} else {
			ad := platform.NewTSec(platform.TSecConfig{BaseURL: c.baseURL, Token: c.token, SkipVPNCheck: c.skipVPN})
			if !c.skipVPN {
				if err := ad.CheckVPN(ctx); err != nil {
					fmt.Printf("[✗] VPN 预检: %v\n", err)
					ok = false
				} else {
					fmt.Println("[✓] VPN 预检通过")
				}
			}
			list, err := ad.List(ctx)
			if err != nil {
				fmt.Printf("[✗] 拉取题目: %v\n", err)
				ok = false
			} else {
				fmt.Printf("[✓] 平台题目 %d 道\n", len(list))
			}
		}
	}

	// 4. 本地题库
	if c.platform == "local" && c.suite != "" {
		if ad, err := platform.NewLocalSuite(c.suite); err != nil {
			fmt.Printf("[✗] 本地题库: %v\n", err)
			ok = false
		} else if list, err := ad.List(ctx); err != nil {
			fmt.Printf("[✗] 本地题库: %v\n", err)
			ok = false
		} else {
			fmt.Printf("[✓] 本地题库 %d 题\n", len(list))
		}
	}

	if !ok {
		return 1
	}
	if c.apiKey == "" {
		fmt.Println("\n可以跑 demo。配置 API Key（CTFAGENT_API_KEY）后才能跑真实题库/平台。")
		return 0
	}
	fmt.Println("\n一切就绪。")
	return 0
}

// ---------------------------------------------------------------------------
// demo：不需要 API key，用剧本模型跑通"侦察 → 读 flag → 提交 → 收工"
// ---------------------------------------------------------------------------

func cmdDemo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	verbose := fs.Bool("v", true, "打印每一步")
	_ = fs.Parse(args)

	dir, err := os.MkdirTemp("", "ctfagent-demo-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	chal := filepath.Join(dir, "hello")
	if err := os.MkdirAll(chal, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	const wantFlag = "flag{demo_works_2026}"
	// flag.txt 是"判题答案"，不会进工作目录；工作目录里放的是题面给的文件。
	if err := os.WriteFile(filepath.Join(chal, "flag.txt"), []byte(wantFlag+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(chal, "secret.txt"), []byte("恭喜你找到了这个文件。\nflag 就在下面这一行：\n"+wantFlag+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	spec := `{
  "id": "demo-hello",
  "title": "演示题：读文件",
  "category": "misc",
  "prompt": "工作目录下有一个 secret.txt，读出里面的内容并提交其中的 flag。",
  "flag_count": 1,
  "flag_pattern": "flag\\{[^}]+\\}"
}`
	if err := os.WriteFile(filepath.Join(chal, "challenge.json"), []byte(spec), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ad, err := platform.NewLocalSuite(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// 剧本模型：模拟一个"规规矩矩干活"的 agent。
	script := llm.NewScripted(
		llm.Call("sh", `{"command":"ls -la"}`),
		llm.Call("fact", `{"text":"工作目录里存在 secret.txt","evidence":"secret.txt"}`),
		llm.Call("sh", `{"command":"cat secret.txt"}`),
		llm.Call("submit", fmt.Sprintf(`{"flag":%q,"evidence":%q}`, wantFlag, wantFlag)),
		llm.Call("finish", `{"status":"solved","summary":"读取 secret.txt 并提交成功"}`),
	)
	script.OnCall = func(turn int, _ llm.Request) {
		if *verbose {
			log.Printf("[scripted] turn %d", turn)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	orch := kernel.NewOrchestrator(ad, script, kernel.RunConfig{
		Concurrency: 1,
		Rounds:      []time.Duration{2 * time.Minute},
		Solver:      kernel.DefaultConfig(),
		Grounding:   boolPtr(true),
		Logf: func(f string, a ...any) {
			if *verbose {
				log.Printf(f, a...)
			}
		},
	})
	rep, err := orch.Run(ctx, []core.Challenge{{
		ID: "demo-hello", Title: "演示题：读文件", Category: "misc",
		Prompt:    "工作目录下有一个 secret.txt，读出里面的内容并提交其中的 flag。",
		FlagCount: 1,
	}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(rep.Table())
	if rep.Solved == 0 {
		fmt.Fprintln(os.Stderr, "\n演示失败：内核没有解出这道题（这不应该发生，请提 issue）")
		return 1
	}
	fmt.Println("\n演示成功：内核、沙箱、工具、grounding、提交闸门、报告 全都通了。")
	fmt.Println("下一步：配置真实模型后跑自己的题库或 TSecBench。")
	return 0
}

// ---------------------------------------------------------------------------

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func parseDurations(s string) ([]time.Duration, error) {
	var out []time.Duration
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		d, err := time.ParseDuration(p)
		if err != nil {
			return nil, err
		}
		if d <= 0 {
			return nil, fmt.Errorf("%q 必须为正", p)
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少给一个轮次预算")
	}
	return out, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	return s
}

func catOf(c string) string {
	if c == "" {
		return "unknown"
	}
	return c
}
