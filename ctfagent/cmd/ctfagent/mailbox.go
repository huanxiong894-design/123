package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ctfagent/internal/llm"
)

func cmdMailbox(args []string) int {
	if len(args) == 0 {
		mailboxUsage()
		return 2
	}
	switch args[0] {
	case "wait":
		return cmdMailboxWait(args[1:])
	case "reply":
		return cmdMailboxReply(args[1:])
	case "help", "-h", "--help":
		mailboxUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知 mailbox 操作: %s\n", args[0])
		mailboxUsage()
		return 2
	}
}

func mailboxUsage() {
	fmt.Print(`FileChan 邮箱自动化：
  ctfagent mailbox wait  --root RUN_DIR [--timeout 30m]
  ctfagent mailbox reply --request req-NNN.json --input reply.json
  ctfagent mailbox reply --request req-NNN.json --input - < reply.json

wait 会等待最早的未回复请求，并输出已自动脱敏的预览和精确文件路径。
原始 req 文件仅供当前 agent 读取，目录/文件使用 owner-only 权限。
reply 会校验 JSON、工具名和 args 对象，并以原子方式写入 reply 文件。
`)
}

func cmdMailboxWait(args []string) int {
	fs := flag.NewFlagSet("mailbox wait", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	root := fs.String("root", "", "本次 drive 的 run 目录")
	timeout := fs.Duration("timeout", 0, "等待上限（0 表示由 Ctrl-C 结束）")
	poll := fs.Duration("poll", 100*time.Millisecond, "邮箱检查间隔")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*root) == "" {
		fmt.Fprintln(os.Stderr, "错误: mailbox wait 需要 --root")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	summary, err := llm.WaitPending(ctx, *root, *timeout, *poll)
	if err != nil {
		fmt.Fprintln(os.Stderr, "等待失败:", err)
		return 1
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(summary); err != nil {
		fmt.Fprintln(os.Stderr, "输出失败:", err)
		return 1
	}
	return 0
}

func cmdMailboxReply(args []string) int {
	fs := flag.NewFlagSet("mailbox reply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	request := fs.String("request", "", "对应 req-NNN.json 路径")
	input := fs.String("input", "-", "回复 JSON 文件；- 表示 stdin")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*request) == "" {
		fmt.Fprintln(os.Stderr, "错误: mailbox reply 需要 --request")
		return 2
	}
	var reader io.Reader = os.Stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取回复文件失败:", err)
			return 1
		}
		defer f.Close()
		reader = f
	}
	data, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取回复失败:", err)
		return 1
	}
	path, calls, err := llm.WriteMailboxReply(*request, data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "回复未写入:", err)
		return 1
	}
	fmt.Printf("已原子写入 %s（%d 个已校验工具调用）\n", path, calls)
	return 0
}
