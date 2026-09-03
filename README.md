# chrome-devtools-auto-allow

用 Frida hook 正在运行的 Google Chrome，让「要允许远程调试吗？」许可弹窗**在出现之前就被自动允许**——`chrome-devtools-mcp --autoConnect` 等工具连接时不再弹窗、不再抢窗口焦点。

## 原理

Chrome 144+ 的 ad-hoc 远程调试（`chrome://inspect/#remote-debugging` 开启）工作在 approval mode：每个新连接都会走

```
content → ChromeDevToolsManagerDelegate::AcceptDebugging(AcceptCallback)
        → DevToolsConnectionDialog::Show(browser, callback)   // 弹窗
        → 用户点「允许」→ callback(kAllow) → 连接放行
```

本工具把 `AcceptDebugging` 整个替换掉：取出传入的 `base::OnceCallback`（BindState 的 invoke 函数存在 `+8`），以 `kAllow=1` 直接调用 Chrome 自己的包装 lambda——UMA 埋点（`DevTools.RemoteDebugging.ConnectionPermission=kAllowed`）保留，回调链完整，弹窗永远不会被创建。

## 文件

- `find_offsets.py` — 在 stripped 的 `/opt/google/chrome/chrome` 里定位两个目标函数。锚点：直方图名字符串 `"DevTools.RemoteDebugging.ConnectionPermission"` 的 `lea rip` 交叉引用 → wrapper lambda；再筛 `lea rsi/rdx`（BindOnce functor 实参，`lea rcx` 是 CFI 校验）→ `AcceptDebugging`。结果按 build id 缓存在 `offsets.json`，Chrome 升级后自动重算（<1s）。
- `auto_allow.py` — 找到浏览器主进程（无 `--type=` 且父进程不是 chrome），Frida attach 并 `Interceptor.replace`。Ctrl-C 退出即恢复 Chrome 原始行为。

## 用法

```bash
cd ~/Documents/chrome-devtools-auto-allow
uv run auto_allow.py        # 挂上 hook，Ctrl-C 摘除
uv run find_offsets.py      # 仅查看/刷新偏移
```

环境：uv 管理（Python 3.12；依赖 frida、numpy、capstone、pyelftools）。

## 注意

- 需要能 ptrace Chrome：本机 `kernel.yama.ptrace_scope=0` 且 SELinux enforcing 下 unconfined 域可附加；若失败检查这两项。
- hook 期间 Chrome 的所有远程调试连接都会被无条件允许——这只该在受信环境使用。
- Chrome 自动升级后无需手动做什么，下次运行 `auto_allow.py` 会自动重新解析偏移。
