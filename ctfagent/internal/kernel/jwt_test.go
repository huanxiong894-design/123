package kernel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// callJWT 走真实的工具分发路径，避免测试与实现脱节。
func callJWT(t *testing.T, ts *ToolSet, args map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return call(t, ts, "jwt", string(raw))
}

func TestJWTDeclared(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	found := false
	for _, d := range ts.Definitions() {
		if d.Name == "jwt" {
			found = true
			if !strings.Contains(d.Description, "decode") || !strings.Contains(d.Description, "jwks") {
				t.Errorf("jwt 工具描述缺少关键动作说明：%s", d.Description)
			}
		}
	}
	if !found {
		t.Fatal("Definitions 里没有 jwt 工具")
	}
}

func TestJWTSignThenDecode(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	out := callJWT(t, ts, map[string]any{
		"action":  "sign",
		"payload": `{"sub":"u1","role":"admin"}`,
		"secret":  "s3cr3t",
		"kid":     "k1",
		"jku":     "/files/shared/jwks.json",
	})
	tok := extractKV(out, "token=")
	if tok == "" {
		t.Fatalf("sign 没给出 token：\n%s", out)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token 段数不对：%q", tok)
	}
	// 自校验签名：HMAC-SHA256(secret, header.payload)
	m := hmac.New(sha256.New, []byte("s3cr3t"))
	m.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if parts[2] != want {
		t.Fatalf("签名不匹配 want=%s got=%s", want, parts[2])
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hdr), `"kid":"k1"`) || !strings.Contains(string(hdr), `"jku":"/files/shared/jwks.json"`) {
		t.Fatalf("header 没带上 kid/jku：%s", hdr)
	}

	dec := callJWT(t, ts, map[string]any{"action": "decode", "token": tok})
	if !strings.Contains(dec, `"role":"admin"`) {
		t.Errorf("decode 没解出 payload：\n%s", dec)
	}
	if !strings.Contains(dec, "值得动的字段") {
		t.Errorf("decode 应提示可疑 claim：\n%s", dec)
	}
}

func TestJWTNoneVariant(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	out := callJWT(t, ts, map[string]any{"action": "none", "payload": `{"sub":"x"}`})
	tok := extractKV(out, "token=")
	if !strings.HasSuffix(tok, ".") {
		t.Fatalf("alg=none 的 token 必须以点结尾：%q", tok)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hdr), `"alg":"none"`) {
		t.Fatalf("header 里没有 alg=none：%s", hdr)
	}
	if !strings.Contains(out, "token_alt=") {
		t.Error("应同时给出两段式变体")
	}
}

func TestJWTJWKS(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	out := callJWT(t, ts, map[string]any{"action": "jwks", "secret": "abc123", "kid": "mykey"})
	raw := extractKV(out, "jwks=")
	if raw == "" {
		t.Fatalf("jwks 没输出：\n%s", out)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			K   string `json:"k"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("jwks 不是合法 JSON：%v\n%s", err, raw)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].Kty != "oct" || doc.Keys[0].Kid != "mykey" {
		t.Fatalf("jwks 结构不对：%s", raw)
	}
	k, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].K)
	if err != nil || string(k) != "abc123" {
		t.Fatalf("k 字段不是密钥的 base64url：%v %q", err, k)
	}
}

func TestJWTBadInput(t *testing.T) {
	ts, _, _ := newTestToolSet(t)
	if out := callJWT(t, ts, map[string]any{"action": "sign", "payload": `{}`}); !strings.Contains(out, "secret") {
		t.Errorf("缺 secret 应明确提示：%s", out)
	}
	if out := callJWT(t, ts, map[string]any{"action": "sign", "payload": `{"a":1}`, "secret": "k", "alg": "RS256"}); !strings.Contains(out, "HS256") {
		t.Errorf("不支持的算法应提示支持范围：%s", out)
	}
	if out := callJWT(t, ts, map[string]any{"action": "decode", "token": "not-a-jwt"}); !strings.Contains(out, "不是 JWT") {
		t.Errorf("非法 token 应给出可读错误：%s", out)
	}
}

// extractKV 从"key=value\n" 形式的输出里取值。
func extractKV(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
