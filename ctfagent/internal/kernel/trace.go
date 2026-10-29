package kernel

import "time"

// TraceEvent 是解题过程的可观测事件。
//
// 为什么要有它：跑分之后最常问的两个问题是"这题为什么没解出来"和"它到底在干嘛"。
// 只靠日志（几行摘要）回答不了——需要每一步的模型原话、工具、参数、真实输出。
// 把它写成 JSONL，就可以事后用 jq / 脚本统计：平均步数、重复命令率、无效工具调用率、
// 卡在哪个阶段、token 花在哪。
//
// 注意：trace 里会有题目内容和工具输出（可能含 flag），调试完记得删。
type TraceEvent struct {
	At        time.Time `json:"at"`
	Challenge string    `json:"challenge,omitempty"`
	Kind      string    `json:"kind"` // start | model | tool | nudge | hint | finish | done
	Step      int       `json:"step,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Args      string    `json:"args,omitempty"`
	Output    string    `json:"output,omitempty"`
	Content   string    `json:"content,omitempty"`
	Note      string    `json:"note,omitempty"`
	TokensIn  int       `json:"tokens_in,omitempty"`
	TokensOut int       `json:"tokens_out,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

const traceOutputCap = 16 << 10 // 单条输出最多记 16KB，别把 trace 撑爆

func (h Hooks) trace(ev TraceEvent) {
	if h.Trace == nil {
		return
	}
	ev.At = time.Now()
	h.Trace(ev)
}

func clipTrace(s string) string {
	if len(s) <= traceOutputCap {
		return s
	}
	return s[:traceOutputCap] + "…(truncated)"
}
