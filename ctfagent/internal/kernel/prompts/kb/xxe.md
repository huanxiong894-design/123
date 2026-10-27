# XXE / XML 解析器

## 探测

先确认"这块 XML 真的被解析了"，再看它能不能读外部资源：

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]>
<r>&xxe;</r>
```

- 回显点在**任意一个被渲染的字段**（`<title>`、`<name>`、错误信息）都行；
- 不回显时用**报错/布尔**：引用不存在的文件 vs 存在的文件，错误信息不同；
- 解析器不同、边界不同：`libxml2`（PHP/Python `lxml`）默认**读本地文件**、默认**不出网**；
  Java 的 `DocumentBuilderFactory` 默认更宽松（旧版本还能读 `http://`）。

## 常见入口

`?endpoint=import`、`/api/import`、SOAP、SVG 上传、DOCX/XLSX（zip 里的 XML）、RSS/OPML 导入、SAML。

## 绕过"字符串黑名单"（最常见的 WAF 形态）

WAF 通常只对**原始字节**做 `<!DOCTYPE` / `<!ENTITY` / `SYSTEM` / `file://` 之类的子串匹配。可选顺序：

1. **换编码整篇投递**：UTF-16LE 带 BOM（`FF FE`）或 UTF-16BE（`FE FF`）。
   原始字节里不含任何 ASCII 明文，但解析器按 BOM 解码后照常解析 —— 这一招命中率最高。
2. **换 XML 版本/声明方式**：省略 `<?xml?>`、用单引号、用 `&#x53;YSTEM`（字符引用）拼关键字。
3. **换参数实体**：`<!ENTITY % p SYSTEM "...">%p;` 放在内部子集之外（外部 DTD）。
4. **换协议写外部实体**：`php://filter/convert.base64-encode/resource=...`（PHP 后端），
   或 `file:///` 换 `file:/`、`file://localhost/`。

> 判据：把同一份 payload 用「明文 / UTF-16 / 参数实体」三种形态各发一次，
> 只有一种过不去，说明拦的是**形态**而不是**能力**。

## 拿到 XXE 之后（得分点往往不在这条链的终点）

1. 读**源码/配置**：`/var/www/html/...`、`app/config/settings.py`、`.env`、`application.yml`
   → 里面常直接写着 `ADMIN_API_KEY` / `SECRET_KEY` 这类能打开下一道门的钥匙；
2. 用拿到的 Key 走**管理员视图/内部接口**（自定义头 `X-Admin-Key`、`X-API-Key`）；
3. 读答案文件本身；
4. PHP 后端可以 `php://filter` 把 PHP 源文件 base64 出来（避免被当代码执行）。

## 坑点

- **实体要在文档里被真正引用**才会展开（`&xxe;` 必须出现在会被渲染的节点里）。
- 上传型入口（SVG/DOCX）要保证**主格式合法**：zip 结构/CRC 错一位，上传就会被拒。
- 有的实现只做「解析」不做「展开」（`LIBXML_NOENT` 未开），此时换 `php://`/`file://` 参数实体再试一次。
- XXE 与 SSRF 同源：能读文件通常也能打内网（`http://` 外部实体），禁出网时只走本地文件。
