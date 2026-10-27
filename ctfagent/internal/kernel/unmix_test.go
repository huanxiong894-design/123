package kernel

import (
	"context"

	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// unmixEncode 造测试数据用：把明文按「xor 表 → 旋转 r → 平移 c」正向混淆。
// 正确性靠 unmix 自己的反向枚举来验证（这是黑盒对照，不共享实现）。
func unmixEncode(plain, key []byte, rot int, add int) []byte {
	out := make([]byte, len(plain))
	for i, p := range plain {
		// decode: plain = rot(blob^k, rot) + add  =>  blob = rotInv(plain-add) ^ k
		v := p - byte(add)
		v = unmixRot(v, -rot)
		out[i] = v ^ key[i%len(key)]
	}
	return out
}

func unmixHex(b []byte) string { return hex.EncodeToString(b) }

// TestUnmixRecoversTableRotateAdd 锁住最常用的一种组合：
// 「循环表异或 → 右旋 3 → 加常数」必须能被一条调用解出来（这是这类题的主线）。
func TestUnmixRecoversTableRotateAdd(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	plain := []byte("CRED{m4sk3d_by73s_0p_rot4t3}")
	key := []byte{0x8d, 0xde, 0xb9, 0x0f}
	blob := unmixEncode(plain, key, -3, 0xef) // -3 = ror3
	args := fmt.Sprintf(`{"hex":%q,"keys":[%q],"prefix":"CRED{","top":4}`,
		unmixHex(blob), unmixHex(key))
	out := call(t, ts, "unmix", args)
	if !strings.Contains(out, string(plain)) {
		t.Fatalf("没有恢复出明文：\n%s", out)
	}
	if !strings.Contains(out, "ror3") || !strings.Contains(out, "0xef") {
		t.Fatalf("变换描述不对：\n%s", out)
	}
}

// TestUnmixBruteFindsSingleByteKey 没有表可依赖时，brute=1 也要能扫出来。
func TestUnmixBruteFindsSingleByteKey(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	plain := []byte("X{firmw4re_bl0b}")
	blob := unmixEncode(plain, []byte{0x5b}, 2, 0x21)
	args := fmt.Sprintf(`{"hex":%q,"brute":1,"prefix":"X{","top":4}`, unmixHex(blob))
	out := call(t, ts, "unmix", args)
	if !strings.Contains(out, string(plain)) {
		t.Fatalf("单字节键没扫出来：\n%s", out)
	}
}

// TestUnmixReadsFileRange 目标环境里的文件 + offset/length 也要能直接吃。
func TestUnmixReadsFileRange(t *testing.T) {
	ts, _, rt := newTestToolSet(t)
	plain := []byte("Y{off5e7_1n_f1l3}")
	key := []byte{0x33, 0x91}
	blob := unmixEncode(plain, key, -5, 0x7)
	pad := []byte{0xaa, 0xbb, 0xcc}
	all := append(append(append([]byte{}, pad...), blob...), 0x00, 0x11)
	if err := rt.WriteFile(context.Background(), "blob.bin", all); err != nil {
		t.Fatal(err)
	}
	args := fmt.Sprintf(`{"file":"blob.bin","offset":3,"length":%d,"keys":[%q],"prefix":"Y{"}`,
		len(blob), unmixHex(key))
	out := call(t, ts, "unmix", args)
	if !strings.Contains(out, string(plain)) {
		t.Fatalf("文件片段没解出来：\n%s", out)
	}
}

// TestUnmixDeclared 工具必须在 Definitions 里（模型才看得见）。
func TestUnmixDeclared(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	for _, d := range ts.Definitions() {
		if d.Name == "unmix" {
			if !strings.Contains(d.Description, "printable") {
				t.Fatalf("描述缺少判定条件：%s", d.Description)
			}
			return
		}
	}
	t.Fatal("unmix 没注册进工具表")
}
