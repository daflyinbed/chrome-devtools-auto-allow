#!/usr/bin/env python3
"""Locate hook targets inside the stripped Google Chrome binary.

Targets (auto-allow the remote-debugging consent without showing it):
  accept_debugging = ChromeDevToolsManagerDelegate::AcceptDebugging(AcceptCallback)
      -> replaced by the Frida hook
  lambda_invoke    = the BindOnce wrapper lambda it creates (records the UMA
      histogram, then runs the inner callback with the result)
      -> invoked directly with kAllow=1

Anchors: the lambda references the literal histogram name
"DevTools.RemoteDebugging.ConnectionPermission"; function starts are found via
int3 (0xcc) padding because this build has no endbr64/CET.
"""

from __future__ import annotations

import json
import mmap
import sys
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

CHROME_BIN = Path("/opt/google/chrome/chrome")
CACHE_FILE = Path(__file__).parent / "offsets.json"
HISTOGRAM = b"DevTools.RemoteDebugging.ConnectionPermission\x00"


class ElfMap:
    def __init__(self, path: Path):
        self._f = open(path, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.elf = ELFFile(self._f)
        self.segments = [
            (s["p_vaddr"], s["p_filesz"], s["p_offset"], s["p_flags"])
            for s in self.elf.iter_segments()
            if s["p_type"] == "PT_LOAD"
        ]
        self.build_id = "unknown"
        for sec in self.elf.iter_sections():
            if sec.name == ".note.gnu.build-id":
                self.build_id = sec.data()[-20:].hex()

    def off2vaddr(self, off: int) -> int:
        for vaddr, filesz, offset, _ in self.segments:
            if offset <= off < offset + filesz:
                return vaddr + (off - offset)
        raise ValueError(f"offset {off:#x} not in any PT_LOAD")

    def exec_seg(self) -> tuple[int, np.ndarray]:
        vaddr, filesz, offset, flags = max(
            (s for s in self.segments if s[3] & 0x1), key=lambda s: s[1]
        )
        return vaddr, np.frombuffer(self._mm, dtype=np.uint8, count=filesz, offset=offset)

    def read(self, va: int, n: int) -> bytes:
        for vaddr, filesz, offset, _ in self.segments:
            if vaddr <= va < vaddr + filesz:
                off = offset + (va - vaddr)
                return self._mm[off : off + n]
        raise ValueError(f"vaddr {va:#x} not mapped")


def find_lea_rip_xrefs(base_va: int, buf: np.ndarray, target_va: int) -> list[int]:
    """Positions of `lea r64, [rip+disp32]` whose effective address == target_va."""
    if len(buf) < 7:
        return []
    cand = np.nonzero(
        (buf[:-6] == 0x48) & (buf[1:-5] == 0x8D) & ((buf[2:-4] & 0xC7) == 0x05)
    )[0]
    if len(cand) == 0:
        return []
    disp = (
        buf[cand + 3].astype(np.int32)
        | (buf[cand + 4].astype(np.int32) << 8)
        | (buf[cand + 5].astype(np.int32) << 16)
        | (buf[cand + 6].astype(np.int32) << 24)
    )
    eff = base_va + cand + 7 + disp
    return [int(cand[i]) for i in np.nonzero(eff == target_va)[0]]


def find_func_start(seg_va: int, seg: np.ndarray, pos: int, max_back: int = 0x1000) -> int:
    """Walk back from pos to the nearest int3-padded function boundary."""
    for i in range(pos - 1, max(0, pos - max_back), -1):
        if seg[i] == 0xCC and seg[i + 1] != 0xCC:
            return seg_va + i + 1
    raise RuntimeError(f"no function start found before {seg_va + pos:#x}")


def disasm(elf: ElfMap, start_va: int, n: int, stop_at_ret=True) -> list:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out = []
    for insn in md.disasm(elf.read(start_va, n), start_va):
        out.append(insn)
        if stop_at_ret and insn.mnemonic == "ret":
            break
    return out


def dump(title: str, insns: list) -> None:
    print(f"--- {title} ---")
    for i in insns:
        print(f"  {i.address:#12x}: {i.mnemonic} {i.op_str}")


def main() -> int:
    elf = ElfMap(CHROME_BIN)
    print(f"chrome: {CHROME_BIN}\nbuild id: {elf.build_id}")

    if CACHE_FILE.exists():
        cached = json.loads(CACHE_FILE.read_text())
        if cached.get("build_id") == elf.build_id:
            print(f"\ncached offsets still valid:\n{json.dumps(cached['offsets'], indent=2)}")
            return 0

    str_off = elf._mm.find(HISTOGRAM)
    if str_off < 0:
        print("FATAL: histogram string not found", file=sys.stderr)
        return 1
    str_va = elf.off2vaddr(str_off)
    print(f"histogram string @ {str_va:#x}")

    text_va, text = elf.exec_seg()
    sites = find_lea_rip_xrefs(text_va, text, str_va)
    site_vas = [text_va + p for p in sites]
    print(f"lea xrefs to string: {[hex(v) for v in site_vas]}")
    if not site_vas:
        print("FATAL: no code references the histogram string", file=sys.stderr)
        return 1

    lambda_va = find_func_start(text_va, text, sites[0])
    insns = disasm(elf, lambda_va, 0x80)
    dump("wrapper lambda (candidate)", insns[:24])
    ops = [(i.mnemonic, i.op_str.replace(" ", "")) for i in insns[:24]]
    ok = (
        any(m == "mov" and o.endswith(",esi") for m, o in ops)  # save result arg
        and any(m == "cmp" and o.endswith(",1") for m, o in ops)  # == kAllow
        and any(m == "mov" and "+0x28]" in o for m, o in ops)  # move-out inner cb
    )
    print(f"lambda verified @ {lambda_va:#x}: {ok}")
    if not ok:
        print("WARN: lambda shape mismatch, inspect the disasm above")

    a_sites = find_lea_rip_xrefs(text_va, text, lambda_va)
    if not a_sites:
        print("FATAL: nothing references the lambda (AcceptDebugging not found)", file=sys.stderr)
        return 1
    # Xrefs come in two flavours: the BindOnce functor passed as an argument
    # (lea rsi/rdi/rdx, [rip+L]) and CFI checks (lea rcx, [rip+L]). Only the
    # former lives inside AcceptDebugging.
    accept_va = None
    for p in a_sites:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        insn = next(md.disasm(bytes(text[p : p + 16]), text_va + p))
        if insn.mnemonic == "lea" and not insn.op_str.startswith("rcx"):
            accept_va = find_func_start(text_va, text, p)
            break
    if accept_va is None:
        print("FATAL: no functor-argument xref to lambda found", file=sys.stderr)
        return 1
    dump("ChromeDevToolsManagerDelegate::AcceptDebugging (candidate)", disasm(elf, accept_va, 0x200))

    offsets = {
        "accept_debugging": accept_va,
        "lambda_invoke": lambda_va,
        "allow_value": 1,
    }
    CACHE_FILE.write_text(json.dumps({"build_id": elf.build_id, "offsets": offsets}, indent=2))
    print(f"offsets cached -> {CACHE_FILE}\n{json.dumps(offsets, indent=2)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
