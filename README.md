# chrome-devtools-auto-allow

用 Frida hook 正在运行的 Google Chrome，让「要允许远程调试吗？」许可弹窗**在出现之前就被自动允许**——`chrome-devtools-mcp --autoConnect` 等工具连接时不再弹窗、不再抢窗口焦点。

支持平台：**Linux (x86-64)** 与 **macOS (arm64, Apple Silicon)**。

## 原理

Chrome 144+ 的 ad-hoc 远程调试（`chrome://inspect/#remote-debugging` 开启）工作在 approval mode：每个新连接都会走

```
content → ChromeDevToolsManagerDelegate::AcceptDebugging(AcceptCallback)
        → DevToolsConnectionDialog::Show(browser, callback)   // 弹窗
        → 用户点「允许」→ callback(kAllow) → 连接放行
```

本工具把 `AcceptDebugging` 整个替换掉：取出传入的 `base::OnceCallback`（BindState 的 invoke 函数存在 `+8`），以 `kAllow=1` 直接调用 Chrome 自己的包装 lambda——UMA 埋点（`DevTools.RemoteDebugging.ConnectionPermission=kAllowed`）保留，回调链完整，弹窗永远不会被创建。

## 文件

- `find_offsets.py` — 在 stripped 的 Chrome 二进制里定位两个目标函数，结果按 build id / UUID 缓存在 `offsets.json`，Chrome 升级后自动重算。
  - **Linux**：`/opt/google/chrome/chrome`（ELF）。锚点：直方图名字符串的 `lea rip` 交叉引用 → wrapper lambda；再筛 `lea rsi/rdx`（BindOnce functor 实参，`lea rcx` 是 CFI 校验）→ `AcceptDebugging`。函数边界：int3。
  - **macOS**：`Google Chrome Framework.framework`（Mach-O arm64 slice）。锚点相同，编码不同：字符串经 `adrp+add` 引用 → thunk；thunk 在 `AcceptDebugging` 内联的 BindOnce 构造里经单条 `adr` 物化 → 容器函数即 `AcceptDebugging`（虚函数，vtable `+0xb8`，尾调 `DevToolsConnectionDialog::Show`）。函数边界：`brk` 填充。
- `auto_allow.py` — 找到浏览器主进程（无 `--type=` 且父进程不是 chrome），Frida attach 并 `Interceptor.replace`。Ctrl-C 退出即恢复 Chrome 原始行为。

## 用法

```bash
cd ~/Documents/chrome-devtools-auto-allow
uv run auto_allow.py        # 挂上 hook，Ctrl-C 摘除
uv run find_offsets.py      # 仅查看/刷新偏移
```

环境：uv 管理（Python 3.12；依赖 frida、numpy、capstone、pyelftools）。

## macOS 额外设置（一次性）

macOS 上普通用户拿不到 Chrome（hardened runtime，无 `get-task-allow`）的 `task_for_pid`，Frida attach 会超时。两种解法，任选其一：

1. **给 Python 解释器调试 entitlement（推荐，无需 sudo）**：

   ```bash
   PYBIN=$(readlink -f .venv/bin/python)
   cp "$PYBIN" "$PYBIN.orig"          # 留底
   cat > /tmp/ent.plist <<'EOF'
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0"><dict>
       <key>com.apple.security.cs.debugger</key><true/>
   </dict></plist>
   EOF
   codesign -s - --entitlements /tmp/ent.plist -f "$PYBIN"
   ```

   uv 重装/升级该 Python 后需重做一次。

2. **直接用 sudo 运行**：`sudo uv run auto_allow.py`。

## 注意

- Linux 需要能 ptrace Chrome：本机 `kernel.yama.ptrace_scope=0` 且 SELinux enforcing 下 unconfined 域可附加；若失败检查这两项。
- hook 期间 Chrome 的所有远程调试连接都会被无条件允许——这只该在受信环境使用。
- Chrome 自动升级后无需手动做什么，下次运行 `auto_allow.py` 会自动重新解析偏移。
- 目前 macOS 仅覆盖了 arm64 slice（Apple Silicon）；Intel Mac（框架的 x86_64 slice）未实现。
