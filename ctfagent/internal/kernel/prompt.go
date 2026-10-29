package kernel

import _ "embed"

// DefaultSystemPrompt 是内置的解题人格。用 --prompt 可以换成任意文件，
// 便于针对不同题型/模型做 A/B 对比（这是"通用工具"必须具备的可实验性）。
//
//go:embed prompts/solver.md
var DefaultSystemPrompt string
