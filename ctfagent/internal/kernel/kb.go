package kernel

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"ctfagent/internal/llm"
)

//go:embed prompts/kb/*.md
var kbFS embed.FS

// doKB 检索内置打法笔记。一次调用直接拿到可复制的 payload 清单，
// 省掉模型"凭记忆想 payload"的轮次。
func (t *ToolSet) doKB(tc llm.ToolCall) string {
	var a struct {
		Query string `json:"query"`
		Name  string `json:"name"`
		Max   int    `json:"max_chars"`
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	entries, err := kbFS.ReadDir("prompts/kb")
	if err != nil {
		return "知识库不可用: " + err.Error()
	}
	type note struct {
		name string
		text string
	}
	var notes []note
	for _, e := range entries {
		b, err := kbFS.ReadFile("prompts/kb/" + e.Name())
		if err != nil {
			continue
		}
		notes = append(notes, note{name: strings.TrimSuffix(e.Name(), ".md"), text: string(b)})
	}
	base := strings.ToLower(strings.TrimSuffix(a.Name, ".md"))
	if base != "" {
		for _, n := range notes {
			if n.name == base {
				return fmt.Sprintf("# %s\n%s", n.name, n.text)
			}
		}
	}
	q := strings.ToLower(strings.TrimSpace(a.Query))
	if q == "" {
		var names []string
		for _, n := range notes {
			names = append(names, n.name)
		}
		sort.Strings(names)
		return "可用打法笔记：" + strings.Join(names, ", ") +
			"\n用法：kb(query=\"ssti jinja\") 或 kb(name=\"sqli\")"
	}
	// 关键词打分：标题命中权重最高，其次正文
	type scored struct {
		n note
		s int
	}
	var sc []scored
	terms := strings.Fields(q)
	for _, n := range notes {
		text := strings.ToLower(n.text)
		lowName := strings.ToLower(n.name)
		s := 0
		for _, t := range terms {
			if t == "" {
				continue
			}
			if strings.Contains(lowName, t) {
				s += 10
			}
			s += strings.Count(text, t)
		}
		if s > 0 {
			sc = append(sc, scored{n, s})
		}
	}
	if len(sc) == 0 {
		return "没找到匹配的笔记。可用：" + strings.Join(func() []string {
			var xs []string
			for _, n := range notes {
				xs = append(xs, n.name)
			}
			sort.Strings(xs)
			return xs
		}(), ", ")
	}
	sort.Slice(sc, func(i, j int) bool { return sc[i].s > sc[j].s })
	limit := a.Max
	if limit <= 0 {
		limit = 3000
	}
	var b strings.Builder
	take := 2
	if len(sc) < take {
		take = len(sc)
	}
	for i := 0; i < take; i++ {
		txt := sc[i].n.text
		if len(txt) > limit {
			txt = txt[:limit] + "\n…（截断，用 name 取全文）"
		}
		fmt.Fprintf(&b, "# %s (匹配度 %d)\n%s\n\n", sc[i].n.name, sc[i].s, txt)
	}
	return b.String()
}
