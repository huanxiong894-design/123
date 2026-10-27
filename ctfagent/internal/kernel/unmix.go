package kernel

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"ctfagent/internal/llm"
)

// unmix 是「静态密文 + 已知明文格式」的方向性穷举器。
//
// 适用信号（逆向/固件题里很常见）：
//   - 二进制里有一块 N 字节的高熵常量，但同一个二进制里**找不到**任何解密代码；
//   - 或者校验路径只打印固定占位符，占位符个数恰好等于那块常量的长度；
//   - 结论：那块常量就是凭据本身，只是被「按字节」的可逆混淆过，
//     而混淆的参数（表/轮数/常数）散落在程序其它地方（.data 的小表、立即数）。
//
// 做法不是"猜算法"，而是把**逐字节可逆变换的组合空间**枚举掉：
//
//	原文 = C( rot( blob[i] OP1 key[i%L] , r ) )
//
// 其中 key 取自题目里的小表（任意 1..16 字节窗口循环），OP1 ∈ {xor,add,sub,subr}，
// rot ∈ {不转, rol/ror 1..7}，C ∈ {+c, -c, ^c}（c 用位掩码交集一次算出全部可行值）。
// 判据是「输出全部落在可打印 ASCII」——这条约束极强，真实的错误组合几乎不可能满足。
//
// 这个工具只吃"字节 + 候选表 + 明文格式"，不含任何题目信息；换个二进制照样能用。
type unmixArgs struct {
	Hex       string   `json:"hex"`     // 密文（hex）
	Text      string   `json:"text"`    // 或者直接给文本/转义串（会把 \xNN 解出来）
	File      string   `json:"file"`    // 或者给目标环境里的文件路径 + offset（省一次 read）
	Offset    int      `json:"offset"`  // 配合 file
	Length    int      `json:"length"`  // 配合 file
	Keys      []string `json:"keys"`    // 候选表（每个是 hex 串，可多给几个）
	Periods   []int    `json:"periods"` // 直接指定周期（不给就用 keys 的所有窗口）
	Prefix    string   `json:"prefix"`  // 已知明文前缀（如平台约定的花括号头），命中直接顶到最前
	Top       int      `json:"top"`     // 最多返回多少条，默认 8
	Brute     int      `json:"brute"`   // 0 不裸爆破 / 1 追加 1 字节键 / 2 追加 1~2 字节键
	MaxKeyLen int      `json:"max_key_len"`
}

type bit256 [4]uint64

func (b *bit256) set(i int) { b[i>>6] |= 1 << uint(i&63) }
func (b *bit256) has(i int) bool {
	return b[i>>6]&(1<<uint(i&63)) != 0
}
func (b *bit256) and(o *bit256) {
	for i := 0; i < 4; i++ {
		b[i] &= o[i]
	}
}
func (b *bit256) empty() bool { return b[0]|b[1]|b[2]|b[3] == 0 }

// 三张「可行常数表」：x 是中间值，表里存所有能让结果的第 i 字节可打印的 c。
var (
	unmixXorTab [256]bit256
	unmixAddTab [256]bit256
	unmixSubTab [256]bit256
	unmixInited bool
)

func unmixPrintable(v byte) bool { return v >= 0x20 && v <= 0x7e }

func unmixInitTables() {
	if unmixInited {
		return
	}
	for x := 0; x < 256; x++ {
		var xorT, addT, subT bit256
		for c := 0; c < 256; c++ {
			if unmixPrintable(byte(x ^ c)) {
				xorT.set(c)
			}
			if unmixPrintable(byte(x + c)) {
				addT.set(c)
			}
			if unmixPrintable(byte(x - c)) {
				subT.set(c)
			}
		}
		unmixXorTab[x] = xorT
		unmixAddTab[x] = addT
		unmixSubTab[x] = subT
	}
	unmixInited = true
}

var unmixOps = []struct {
	name string
	fn   func(b, k byte) byte
}{
	{"xor", func(b, k byte) byte { return b ^ k }},
	{"add", func(b, k byte) byte { return b + k }},
	{"sub", func(b, k byte) byte { return b - k }},
	{"subr", func(b, k byte) byte { return k - b }},
}

func unmixRot(v byte, r int) byte {
	if r == 0 {
		return v
	}
	if r > 0 {
		return v<<uint(r) | v>>uint(8-r)
	}
	r = -r
	return v>>uint(r) | v<<uint(8-r)
}

// unmixScore 给候选明文打分：只要能走到这里，可打印性已经满足；
// 剩下的是「像不像凭据」——花括号、常见字符集、已知前缀。
func unmixScore(b []byte, prefix string) int {
	s := 0
	hasL, hasR := false, false
	plausible := true
	for _, c := range b {
		switch {
		case c == '{':
			hasL = true
		case c == '}':
			hasR = true
		}
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
			c != '{' && c != '}' && c != '_' && c != '-' && c != '.' && c != '+' && c != '/' && c != '=' {
			plausible = false
		}
	}
	if hasL && hasR {
		s += 40
	}
	if plausible {
		s += 15
	}
	if prefix != "" && strings.HasPrefix(string(b), prefix) {
		s += 200
	}
	return s
}

type unmixHit struct {
	score int
	model string
	out   []byte
}

func (t *ToolSet) doUnmix(ctx context.Context, tc llm.ToolCall) string {
	var a unmixArgs
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	unmixInitTables()

	// 1. 取密文
	blob, err := unmixBlob(ctx, t, a)
	if err != nil {
		return err.Error()
	}
	if len(blob) == 0 || len(blob) > 4096 {
		return fmt.Sprintf("密文长度不合法：%d 字节（要求 1..4096）", len(blob))
	}

	// 2. 收集候选表
	maxKey := a.MaxKeyLen
	if maxKey <= 0 || maxKey > 32 {
		maxKey = 16
	}
	type keyTab struct {
		desc string
		b    []byte
	}
	seen := map[string]bool{}
	var tabs []keyTab
	addTab := func(desc string, b []byte) {
		if len(b) == 0 || len(b) > maxKey {
			return
		}
		k := string(b)
		if seen[k] {
			return
		}
		seen[k] = true
		tabs = append(tabs, keyTab{desc, b})
	}
	for _, kh := range a.Keys {
		raw, err := unmixDecodeHex(kh)
		if err != nil || len(raw) == 0 {
			continue
		}
		for L := 1; L <= maxKey && L <= len(raw); L++ {
			for off := 0; off+L <= len(raw); off++ {
				addTab(fmt.Sprintf("%d@%d", L, off), raw[off:off+L])
			}
		}
	}
	for _, p := range a.Periods {
		if p <= 0 || p > maxKey {
			continue
		}
		for _, kh := range a.Keys {
			raw, err := unmixDecodeHex(kh)
			if err != nil || len(raw) < p {
				continue
			}
			for off := 0; off+p <= len(raw); off++ {
				addTab(fmt.Sprintf("%d@%d", p, off), raw[off:off+p])
			}
		}
	}
	if len(tabs) == 0 {
		// 没有表 = 只做「单字节平移/旋转」这一类
		addTab("1@0", []byte{0})
	}
	if a.Brute >= 1 {
		for i := 0; i < 256; i++ {
			addTab(fmt.Sprintf("brute1:%02x", i), []byte{byte(i)})
		}
	}
	if a.Brute >= 2 && len(blob) <= 256 {
		for i := 0; i < 256; i++ {
			for j := 0; j < 256; j++ {
				addTab("brute2", []byte{byte(i), byte(j)})
			}
		}
	}
	if len(tabs) > 200000 {
		tabs = tabs[:200000]
	}

	// 3. 枚举
	top := a.Top
	if top <= 0 || top > 64 {
		top = 8
	}
	var hits []unmixHit
	seenOut := map[string]bool{}
	for _, tb := range tabs {
		for _, op := range unmixOps {
			v := make([]byte, len(blob))
			for i, b := range blob {
				v[i] = op.fn(b, tb.b[i%len(tb.b)])
			}
			for r := -7; r <= 7; r++ {
				w := v
				if r != 0 {
					w = make([]byte, len(v))
					for i, b := range v {
						w[i] = unmixRot(b, r)
					}
				}
				for pass := 0; pass < 3; pass++ {
					allow := bit256{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
					for _, b := range w {
						var tab *bit256
						switch pass {
						case 0:
							tab = &unmixAddTab[b]
						case 1:
							tab = &unmixSubTab[b]
						default:
							tab = &unmixXorTab[b]
						}
						allow.and(tab)
						if allow.empty() {
							break
						}
					}
					if allow.empty() {
						continue
					}
					sign := "+"
					if pass == 1 {
						sign = "-"
					} else if pass == 2 {
						sign = "^"
					}
					for c := 0; c < 256; c++ {
						if !allow.has(c) {
							continue
						}
						out := make([]byte, len(w))
						for i, b := range w {
							switch pass {
							case 0:
								out[i] = b + byte(c)
							case 1:
								out[i] = b - byte(c)
							default:
								out[i] = b ^ byte(c)
							}
						}
						key := string(out)
						if seenOut[key] {
							continue
						}
						seenOut[key] = true
						model := fmt.Sprintf("%s(k[%s]=%s)", op.name, tb.desc, hex.EncodeToString(tb.b))
						if r > 0 {
							model += fmt.Sprintf(" rol%d", r)
						} else if r < 0 {
							model += fmt.Sprintf(" ror%d", -r)
						}
						model += fmt.Sprintf(" %s0x%02x", sign, c)
						hits = append(hits, unmixHit{unmixScore(out, a.Prefix), model, out})
					}
				}
			}
		}
	}

	if len(hits) == 0 {
		return fmt.Sprintf("没有候选满足「全部可打印」。密文 %d 字节，试了 %d 张表 × %d 种运算 × 15 种旋转。\n"+
			"下一步：把程序里更多小常量（.data/.rodata 的任意连续窗口、立即数）作为 keys 再跑一次；"+
			"或者确认这段是不是整块别的东西（压缩/打包/哈希），换思路。", len(blob), len(tabs), len(unmixOps))
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return len(hits[i].model) < len(hits[j].model)
	})
	var sb strings.Builder
	fmt.Fprintf(&sb, "密文 %d 字节；表 %d 张；候选 %d 条（按「像凭据」排序，最多显示 %d 条）：\n",
		len(blob), len(tabs), len(hits), top)
	for i, h := range hits {
		if i >= top {
			break
		}
		fmt.Fprintf(&sb, "\n[%02d] score=%d  %s\n     text: %s\n     hex : %s\n",
			i+1, h.score, h.model, unmixSafe(h.out), hex.EncodeToString(h.out))
	}
	if len(hits) > top {
		fmt.Fprintf(&sb, "\n（其余 %d 条省略；prefix= 能直接命中就说明格式对上了）\n", len(hits)-top)
	}
	out := strings.TrimRight(sb.String(), "\n")
	t.scanForFlags(out)
	return out
}

// unmixSafe 把候选转成可放进一条日志的样子（可打印优先，其它用转义）。
func unmixSafe(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
			continue
		}
		fmt.Fprintf(&sb, "\\x%02x", c)
	}
	return sb.String()
}

func unmixDecodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer(" ", "", ":", "", "-", "", "\n", "", "\t", "").Replace(s)
	return hex.DecodeString(s)
}

func unmixBlob(ctx context.Context, t *ToolSet, a unmixArgs) ([]byte, error) {
	switch {
	case strings.TrimSpace(a.Hex) != "":
		return unmixDecodeHex(a.Hex)
	case strings.TrimSpace(a.Text) != "":
		return unmixUnescape(a.Text), nil
	case strings.TrimSpace(a.File) != "":
		out, err := t.rt.ReadFile(ctx, a.File, 8<<20)
		if err != nil {
			return nil, fmt.Errorf("读文件失败：%w", err)
		}
		if a.Offset < 0 || a.Offset > len(out) {
			return nil, fmt.Errorf("offset 越界（文件 %d 字节）", len(out))
		}
		end := len(out)
		if a.Length > 0 && a.Offset+a.Length < end {
			end = a.Offset + a.Length
		}
		return out[a.Offset:end], nil
	}
	return nil, fmt.Errorf("必须给 hex / text / file 之一")
}

// unmixUnescape 处理含 \xNN、\n、\t 的字符串字面量（方便直接贴 objdump 里的转义输出）。
func unmixUnescape(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out = append(out, s[i])
			continue
		}
		switch s[i+1] {
		case 'x', 'X':
			if i+3 < len(s) {
				if v, err := unmixDecodeHex(s[i+2 : i+4]); err == nil {
					out = append(out, v...)
					i += 3
					continue
				}
			}
			out = append(out, s[i])
		case 'n':
			out = append(out, '\n')
			i++
		case 't':
			out = append(out, '\t')
			i++
		case 'r':
			out = append(out, '\r')
			i++
		case '0':
			out = append(out, 0)
			i++
		default:
			out = append(out, s[i])
		}
	}
	return out
}
