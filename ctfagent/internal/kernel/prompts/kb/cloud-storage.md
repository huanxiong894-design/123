# 云存储与凭证代理

对象存储（S3 / Azure Blob / GCS / MinIO / 自研网关）的题，八成落在两个地方：
**凭证的权限范围**，和**代理把用户输入拼进后端 URL 的方式**。

## 0. 先画地图

| 你看到的 | 大概率是什么 | 第一件事 |
|---|---|---|
| `?comp=list`、`<ListBucketResult>` | S3 / MinIO / Azurite | 匿名能不能列 |
| 域名形如 `bucket.host` | virtual-hosted 风格 | 换成 path 风格 `host/bucket` 再试 |
| `?sv=&se=&sp=&sig=` | Azure SAS | 逐字段读权限语义（见 §2） |
| `X-Amz-Credential=`、`X-Amz-Signature=` | SigV4 预签名 URL | 解出 `X-Amz-*`，看 scope 是否被限制 |
| `/api/sas/generate`、`/sts/exchange`、`/sign` | **自研凭证门户** | 先看它给的范围，再看它怎么拼 URL（见 §4） |

## 1. 匿名 / 路径风格 / 计费账号

```
GET /<bucket>?list-type=2                     # 列对象（path-style）
GET /<bucket>/<key>                           # 读对象
GET /?comp=list&restype=container             # Azure：列容器
GET /<container>?restype=container&comp=list  # Azure：列对象
```

- 403 与 404 的含义因实现而异：**先测一个确定不存在的容器名**，把「无权限」和「不存在」分开。
- 有的实现把 `AllAccessDisabled` / `AccessDenied` / `NoSuchBucket` 混用，别只凭一个错误码下结论。
- 拿到 `ListBucketResult` 就等于拿到全量 key —— 很多题的 flag 就在一个不起眼的对象里，**先列再猜**。

## 2. Azure SAS：把 `sp` / `srt` / `sr` 读明白

SAS 是「自带的临时凭证」，权限全写在 URL 里：

| 字段 | 含义 | 危险值 |
|---|---|---|
| `sp` | 权限位 | `rwdlac` = 读/写/删/**列**/追加/创建；只要有 `w`/`d`/`c` 就能改数据 |
| `srt` | 资源类型 | `sco` = service + container + object（**整个账号**）；`c` = 单容器；`o` = 单对象 |
| `sr` | 具体资源 | `b`=blob, `c`=container；缺省往往意味着作用于更上层 |
| `ss` | 服务 | `b`=blob, `f`=file, `q`=queue, `t`=table |
| `st` / `se` | 生效/过期 | `se` 很长 = 泄露后能长期用 |
| `si` / `sip` | 策略 id / IP 限制 | 为空 = 不绑定来源 |
| `sig` | HMAC 签名 | 见 §3 |

**判断口径**：题目里出现「生成临时访问凭证」的门户，第一件事就是把它发出来的 SAS 解码，
看 `srt` 和 `sp` 是不是比你"申请"的那个对象**大一圈**。这就是最常见的越权。

三种 SAS 别混：
- **Account SAS** —— string-to-sign 是 `account\nsp\nss\nsrt\nst\nse\nsip\nspr\nsv\nses\n`，**不绑定路径**，
  拿它可以访问账号下任意容器。
- **Service SAS** —— 绑定到某个容器/对象，签名里含资源路径，换容器就失效。
- **User delegation SAS** —— 用 Entra ID 凭证签的，`skoid` 等字段可见。

## 3. 默认 / 开发凭据

模拟环境和真实事故里都极常见：

| 服务 | 默认账号 | 备注 |
|---|---|---|
| Azurite（Azure 存储模拟器） | `devstoreaccount1` + 一把**公开的**固定 key | key 在官方文档里，等于人人可签名 |
| MinIO | `minioadmin:minioadmin` | 也常被写成环境变量泄露 |
| 本地 S3 兼容网关 | `test/test`、`accesskey/secretkey` | 从 `/api/config`、前端 JS、compose 文件里找 |

用公开默认 key **自己签一个 SAS/预签名 URL**，是合法且高频的路径：
它能绕开"门户签出来的凭证不能用了"这种死局。

```
# Account SAS（sv 用目标实现支持的最新版本，太新的版本可能不被模拟器支持）
string_to_sign = f"{account}\n{sp}\n{ss}\n{srt}\n{st}\n{se}\n{sip}\n{spr}\n{sv}\n{ses}\n"
sig = base64(hmac_sha256(base64decode(key), string_to_sign))
```

签名对不对，用**错误类型**验证：签名错 → `AuthenticationFailed` / `AuthorizationFailure`；
签名对但对象不存在 → `BlobNotFound` / `NoSuchKey`。**两者能区分，就等于你有了一个可用的 oracle。**

## 4. 代理 / 网关类端点：三处注入点

这是这类题最容易卡住的地方。一个"帮我取对象"的代理，实现通常等价于：

```python
url = f"{BACKEND}/{container}/{blob}?{request.args['sas']}"   # 注意最后这段
```

只要用户可控的字符串进了这个 f-string，就有**三个**注入位置：

| # | 位置 | 例子 | 结果 |
|---|---|---|---|
| 1 | **path 段** | `container=foo?restype=container&comp=list` | 通常被框架/编码吃掉 → `AuthorizationFailure` |
| 2 | **query 名** | `?restype=container&comp=list&sas=...` | 如果代理透传 query，可能生效 |
| 3 | **query 值** | `sas=restype=container&comp=list&<真实凭证>` | **很多实现栽在这里** |

第 3 种的原理：`?{sas}` 是把 **`sas` 参数的值当作整段 query string** 拼进去的。
所以给 `sas` 的值前面加 `restype=container&comp=list&`，拼出来就是

```
.../<container>/<blob>?restype=container&comp=list&se=...&sig=...
```

后端看到的是一个**合法的列举请求**，而签名照样有效（Account SAS 不绑定路径）。

> **经验法则**：path 段注入失败 **不等于** 没有注入点。
> 一定要再试一次「把参数注进那个看起来只是数据的字段」（`sas` / `token` / `sig` / `key` / `url`）。

用 `http` 工具构造，比手工拼 URL 可靠：

```json
{"url":"http://t/api/sas/x/%2e%2e",
 "inject":{"param":"sas","value":"restype=container&comp=list&sig=ab%2Bcd%3D"}}
```

`value` 的写法约定：**它就是后端将要原样解析的那段 query**。
工具只把 `&` `+` `#` 空格转义成 `%26 %2B %23 %20`（否则会被当成分隔符/空格），
**`%2B` `%3D` 这类已经编码的写法原样保留** —— 所以签名里的 `+` `/` `=` 记得先写成 `%2B` `%2F` `%3D`。
返回值第一行会回显实际发出的 URL，**先看这一行**再分析响应：拼接错了响应会骗你。

### 路径穿越配合列举

要让列举落到正确的位置，通常还需要退回账号根：

```
/api/sas/x/%2e%2e                       → /<account>/x/../        → /<account>/         （列容器）
/api/sas/<c>/%2e%2e%2f<c>               → /<account>/<c>/../<c>   → /<account>/<c>/     （列对象）
```

- **必须 URL 编码**成 `%2e%2e`。裸 `..` 会被 Flask/Werkzeug（以及多数框架）在路由层规范化掉，直接 404。
- 想让 `%2f` 不被当成路径分隔符，就得让它和 `%2e%2e` 在**同一个编码段**里。
- Go 的 `net/http` 会保留 `RawPath`，所以发 `%2e%2e` 不会被客户端再规范化一次；curl 反而需要 `--path-as-is`。

### 想清楚"注入成功长什么样"

| 观察 | 说明 |
|---|---|
| `BlobNotFound` | 凭证有效，对象名不对 → 该去找列举 |
| `AuthorizationFailure` | 签名无效 / 被参数污染 |
| 返回 `ListBucketResult` / `<EnumerationResults>` | **成了**，直接读 key 列表 |
| 400 + 空 body | 后端认为 URL 畸形（多半是注入被编码了） |

## 5. JWT → 云凭证：联邦交换

`/sts/exchange`、`/api/federation`、`AssumeRoleWithWebIdentity` 这类接口，把 OIDC/JWT 换成对象存储的 AK/SK。
常见的三类问题：

1. **信任任意 `jku` / `x5u`**：JWT header 里指定密钥集 URL，服务端去拉。
   - 该 URL 往往只校验**前缀**（`/files/`、`/uploads/`），于是你上传自己的 JWKS 就能自签。
   - 上传点通常是"公开分享"功能；桶可匿名列举时，先从桶里翻出接入说明（组名、前缀要求）。
2. **算法混淆**：`alg: none`、`HS256` 用公钥当 HMAC 密钥、`kty` 校验缺失。
   JWKS 里放 **`kty: "oct"`** 的对称密钥，很多实现会直接拿 `k` 当 HMAC secret —— 这一步能过掉"unsupported key type"。
3. **claims 提权**：`role` / `groups` / `policy` 直接决定返回的凭证 scope。
   组名从桶里的说明文档、前端 JS、`/api/dashboard` 的公告里找，**别硬猜**。

拿到 AK/SK 后，别忘了看它能不能访问**比预期更多的桶**（Terraform state、runbook 里常留 root 凭证）。

## 6. 常见误判

- `OutOfRangeInput` / `InvalidContainerName`：容器名 **<3 或 >63 字符**，这是**参数错误不是"存在"**。
  用短名（`hr`、`s3`）枚举容器会得到假阳性。
- 公开容器（设置了 anonymous read）上的 SAS 请求可能返回 `AuthorizationFailure` 而不是 `BlobNotFound` ——
  同一把凭证在不同容器上表现不一致时，先怀疑"这个容器有独立的访问策略分支"。
- 模拟器对 `sv`（API 版本）敏感：门户签出来的 `sv` 太新时，签名可能与模拟器算的对不上，
  表现为"服务自己签的凭证自己用不了"。此时正确动作是**用默认 key 自签**，不是继续调门户参数。
- 服务吞吐常常只有个位数 req/s。**穷举对象名是下策**：先找列举点，再谈字典。
