package kernel

import (
	"context"

	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// 这一组用例把 F 系列里最省时间的两条判据做成**可复现的合成靶场**：
//
//	① 诱饵引擎：程序字节 + 小表 + 定长高熵块混在同一块数据里，
//	   「引擎」本身不产出任何数据，真凭据就在那块定长常量里。
//	② 定长槽位：写入不补 NUL，列表命令按 %s 打印，越过槽边界读到相邻内存。
//
// 两个靶场都是现造的，不含任何真实题目的字节、路径或答案。

// ---------------------------------------------------------------------------
// ① 诱饵引擎 / 定长高熵块
// ---------------------------------------------------------------------------

// decoyLayout 造一块「像 .data」的数据：一小段"程序"、一张 4 字节表、
// 一段定长高熵密文、一个 NUL、尾部再挂一张 12 字节表。
// 返回整块数据、密文在块内的偏移与长度（模拟反汇编时看到的布局）。
func decoyLayout(cred, key []byte) (blob []byte, off, n int) {
	prog := []byte{0xc2, 0xc1, 0xc0, 0xc7, 0xd2, 0xc6, 0xc5, 0xcb, 0xc3, 0xca}
	tail := []byte{0xc3, 0xc2, 0xc1, 0xc0, 0xc7, 0xc6, 0xc5, 0xc4, 0xcb, 0xca, 0xc9, 0xc8}
	ct := unmixEncode(cred, key, -3, 0xef) // 与真实场景同族：xor 表 → ror3 → 加常数

	blob = append(blob, prog...)
	blob = append(blob, key...)
	blob = append(blob, 0x00, 0x00)
	off = len(blob)
	blob = append(blob, ct...)
	n = len(ct)
	blob = append(blob, 0x00)
	blob = append(blob, tail...)
	return blob, off, n
}

// TestRangeDecoyEngineBlob 模拟「引擎是诱饵」时的取数过程：
// 只有文件里那一块数据，密钥表要从同一块数据的小常量里找。
func TestRangeDecoyEngineBlob(t *testing.T) {
	ts, _, rt := newTestToolSet(t)
	cred := []byte("CRED{d3c0y_3ng1n3_bl0b_pr0b3}")
	key := []byte{0x5b, 0xa7, 0x13, 0xe1}

	blob, off, n := decoyLayout(cred, key)
	if err := rt.WriteFile(context.Background(), "rodata.bin", blob); err != nil {
		t.Fatal(err)
	}
	// 「程序」与两张小表都当作候选密钥表交给工具；密文按 offset/length 取出。
	args := fmt.Sprintf(`{"file":"rodata.bin","offset":%d,"length":%d,"keys":[%q,%q,%q],"prefix":"CRED{"}`,
		off, n,
		hex.EncodeToString(blob[0:10]),     // 假的"程序"
		hex.EncodeToString(blob[10:14]),    // 4 字节表
		hex.EncodeToString(blob[off+n+1:]), // 尾部 12 字节表
	)
	out := call(t, ts, "unmix", args)
	if !strings.Contains(out, string(cred)) {
		t.Fatalf("诱饵布局下没恢复出凭据：\n%s", out)
	}
	// 判定条件必须可回核对：描述里要带上旋转与常数。
	if !strings.Contains(out, "ror3") || !strings.Contains(out, "0xef") {
		t.Fatalf("变换描述不完整，无法回汇编核对：\n%s", out)
	}
	// 关键判据：凭据长度 == 密文长度（"占位符个数 = 答案长度"）。
	if n != len(cred) {
		t.Fatalf("定长块长度 %d 与凭据长度 %d 不一致", n, len(cred))
	}
}

// TestRangeDecoyEngineNoFalsePositive 没有正确的密钥表时，工具必须**明确报告没找到**，
// 而不是硬凑一个"看起来像"的串 —— 这是 it 能不能被信任的关键。
func TestRangeDecoyEngineNoFalsePositive(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	cred := []byte("CRED{n0_k3y_n0_c4nd1d4t3}")
	ct := unmixEncode(cred, []byte{0x11, 0x22}, -2, 0x31)
	out := call(t, ts, "unmix", fmt.Sprintf(`{"hex":%q,"keys":["a1b2c3d4"],"top":5}`, hex.EncodeToString(ct)))
	if strings.Contains(out, string(cred)) {
		t.Fatalf("密钥表不对却给出了凭据：\n%s", out)
	}
	if !strings.Contains(out, "没有候选") {
		t.Fatalf("没有候选时应明确说明，而不是返回可疑结果：\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// ② 定长槽位不补 NUL
// ---------------------------------------------------------------------------

const slotProbeSize = 64

// slotServer 是一个最小化的"记录型行协议服务"：
// 每条记录固定 slotProbeSize 字节，超长写入不补 NUL，LIST 按 C 字符串语义打印。
type slotServer struct {
	ln   net.Listener
	mem  []byte // 槽位数组 + 紧随其后的"别的对象"
	flag string
}

func startSlotServer(t *testing.T) (*slotServer, string, int) {
	t.Helper()
	flag := "CRED{adjacent_object_leaked}"
	mem := make([]byte, slotProbeSize+len(flag)+1)
	copy(mem[slotProbeSize:], flag) // 槽位后面紧挨着"别的对象"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &slotServer{ln: ln, mem: mem, flag: flag}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().(*net.TCPAddr)
	return s, "127.0.0.1", addr.Port
}

func (s *slotServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *slotServer) handle(c net.Conn) {
	defer c.Close()
	fmt.Fprint(c, "Slot Store v1.0\r\n")
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "STORE "):
			data := []byte(line[6:])
			n := copy(s.mem[:slotProbeSize], data)
			if n < slotProbeSize {
				s.mem[n] = 0 // 只有短写入才补 NUL：这就是缺陷
			}
			fmt.Fprintf(c, "[OK] stored %d bytes\r\n", n)
		case line == "LIST":
			end := bytes.IndexByte(s.mem, 0) // 等价于 %s
			if end < 0 {
				end = len(s.mem)
			}
			fmt.Fprintf(c, "[LAST] %s\r\n", string(s.mem[:end]))
		case line == "HELP":
			fmt.Fprint(c, "STORE <data> | LIST | HELP | QUIT\r\n")
		case line == "QUIT":
			return
		default:
			fmt.Fprint(c, "[ERR] unknown command\r\n")
		}
	}
}

// TestRangeFixedSlotOverread 用框架自己的 raw 工具复现「输出比输入长」这一判据：
// 先短写入确认会补 NUL（输出长度 == 输入长度），再用 >= 槽位长度写入触发越界读。
func TestRangeFixedSlotOverread(t *testing.T) {
	_, host, port := startSlotServer(t)
	ts, _, _ := newTestToolSet(t)

	// 第一步：短写入 → 正常（输出止于自己写的内容）
	short := call(t, ts, "raw", fmt.Sprintf(
		`{"host":%q,"port":%d,"payload":"STORE short-probe\r\nLIST\r\nQUIT\r\n","timeout_s":3}`, host, port))
	if !strings.Contains(short, "[LAST] short-probe") {
		t.Fatalf("短写入的正常路径不对：\n%s", short)
	}
	if strings.Contains(short, "adjacent_object") {
		t.Fatalf("短写入不应该泄漏：\n%s", short)
	}

	// 第二步：填满槽位且不含 NUL → 越界读
	long := "STORE " + strings.Repeat("Z", slotProbeSize+6) + "\r\nLIST\r\nQUIT\r\n"
	out := call(t, ts, "raw", fmt.Sprintf(`{"host":%q,"port":%d,"payload":%q,"timeout_s":3}`, host, port, long))
	if !strings.Contains(out, strings.Repeat("Z", slotProbeSize)) {
		t.Fatalf("没有回显出填满的槽位：\n%s", out)
	}
	if !strings.Contains(out, "adjacent_object_leaked") {
		t.Fatalf("没有触发越界读（判据：输出应比输入长）：\n%s", out)
	}
	// 判据本身：泄漏行的长度 > 自己写入的长度（被截到槽位大小）
	last := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "[LAST]") {
			last = ln
		}
	}
	if len(last) <= slotProbeSize {
		t.Fatalf("泄漏行长度 %d 不大于槽位大小 %d：%q", len(last), slotProbeSize, last)
	}
	_ = time.Now
}
