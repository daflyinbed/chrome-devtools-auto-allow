#!/usr/bin/env python3
"""Auto-allow Chrome's "Allow remote debugging?" consent dialog.

Hooks ChromeDevToolsManagerDelegate::AcceptDebugging in the running browser
process. Instead of showing the consent dialog, the connection callback is
immediately invoked with kAllow through Chrome's own wrapper lambda (so the
UMA histogram still records "allowed" and the callback chain stays intact).

Usage:
    uv run auto_allow.py            # hook until Ctrl-C
    uv run auto_allow.py --status   # just show resolved offsets and exit

Chrome updates change the binary, so offsets are recomputed automatically via
find_offsets.py whenever the build id changes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import frida

HERE = Path(__file__).parent
OFFSETS_FILE = HERE / "offsets.json"

HOOK_JS = """
'use strict';

const BASE = Process.getModuleByName('chrome').base;
const ACCEPT_DEBUGGING = BASE.add(OFFSET_ACCEPT_DEBUGGING);
const ALLOW_VALUE = %ALLOW_VALUE%;

const orig = new NativeFunction(ACCEPT_DEBUGGING, 'void', ['pointer', 'pointer']);
const invokeCache = new Map();

function isExecutable(p) {
  try {
    const r = Process.findRangeByAddress(p);
    return r !== null && r.protection.indexOf('x') !== -1;
  } catch (e) {
    return false;
  }
}

// AcceptCallback is a base::OnceCallback: { BindStateBase* bind_state_ }.
// Depending on how the ABI got specialized it reaches us either as a pointer
// to that 8-byte object or directly as the bind-state pointer. The bind state
// stores its invoke function at +8.
function unwrap(cb) {
  const candidates = [];
  try { candidates.push(cb.readPointer()); } catch (e) {}
  candidates.push(cb);
  for (const bs of candidates) {
    try {
      const invoke = bs.add(8).readPointer();
      if (isExecutable(invoke)) return bs;
    } catch (e) {}
  }
  return null;
}

function invokeWith(bs, value) {
  let fn = invokeCache.get(bs);
  const invoke = bs.add(8).readPointer();
  fn = new NativeFunction(invoke, 'void', ['pointer', 'int']);
  invokeCache.set(bs, fn);
  fn(bs, value);
}

Interceptor.replace(ACCEPT_DEBUGGING, new NativeCallback(function (self, cb) {
  const bs = unwrap(cb);
  if (bs === null) {
    send('[auto-allow] could not unwrap callback, falling back to dialog');
    orig(self, cb);
    return;
  }
  invokeWith(bs, ALLOW_VALUE);
  send('[auto-allow] connection allowed (no dialog)');
}, 'void', ['pointer', 'pointer']));

send('[auto-allow] hooked AcceptDebugging @ ' + ACCEPT_DEBUGGING +
     ' (base ' + BASE + ')');
"""


def load_offsets() -> dict:
    if OFFSETS_FILE.exists():
        data = json.loads(OFFSETS_FILE.read_text())
        build_id = subprocess.run(
            ["readelf", "-n", str(Path("/opt/google/chrome/chrome"))],
            capture_output=True, text=True,
        ).stdout
        # cheap check: reuse cache when the build id line matches
        import re
        m = re.search(r"[0-9a-f]{40}", build_id)
        if m and data.get("build_id") == m.group(0):
            return data["offsets"]
    print("[*] offsets missing/stale, resolving...")
    import find_offsets

    if find_offsets.main() != 0:
        sys.exit("offset resolution failed")
    return json.loads(OFFSETS_FILE.read_text())["offsets"]


def browser_pids() -> list[int]:
    """Main browser processes: chrome without --type= whose parent is not
    chrome itself (zygotes/renderers are sandboxed children with --type=)."""
    info = {}
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            exe = proc / "exe"
            if not exe.exists() or exe.resolve().name != "chrome":
                continue
            cmd = (proc / "cmdline").read_bytes().split(b"\0")
            status = (proc / "status").read_text()
            ppid = int(next(l for l in status.splitlines() if l.startswith("PPid:")).split()[1])
            info[int(proc.name)] = (ppid, any(a.startswith(b"--type=") for a in cmd))
        except (OSError, PermissionError, StopIteration):
            continue
    return [
        pid
        for pid, (ppid, has_type) in info.items()
        if not has_type and ppid not in info
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--status", action="store_true", help="print offsets and exit")
    args = ap.parse_args()

    offsets = load_offsets()
    print(f"[*] offsets: {json.dumps(offsets)}")
    if args.status:
        return 0

    pids = browser_pids()
    if not pids:
        sys.exit("no running Chrome browser process found")
    print(f"[*] browser process(es): {pids}")

    js = HOOK_JS.replace("%ALLOW_VALUE%", str(offsets.get("allow_value", 1)))
    js = js.replace("OFFSET_ACCEPT_DEBUGGING", str(offsets["accept_debugging"]))

    sessions = []
    for pid in pids:
        try:
            session = frida.attach(pid)
        except Exception as e:
            print(f"[!] attach {pid} failed: {e}")
            continue
        script = session.create_script(js)
        script.on("message", lambda msg, _pid=pid: print(f"[chrome:{_pid}] {msg.get('payload', msg)}"))
        script.load()
        sessions.append(session)
        print(f"[+] hooked pid {pid}")

    if not sessions:
        sys.exit("could not hook any Chrome process")

    print("[*] running - Ctrl-C to unhook and exit")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] detaching (stock behavior restored)")
    for s in sessions:
        try:
            s.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
