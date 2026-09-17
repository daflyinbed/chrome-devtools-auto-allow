#!/usr/bin/env python3
"""Locate hook targets inside the stripped Google Chrome binary.

Targets (auto-allow the remote-debugging consent without showing it):
  accept_debugging = ChromeDevToolsManagerDelegate::AcceptDebugging(AcceptCallback)
      -> replaced by the Frida hook
  lambda_invoke    = the BindOnce thunk it stores in the wrapped callback's bind
      state (records the UMA histogram, then runs the inner callback)
      -> invoked directly with kAllow=1

Linux/x86-64 chain: the histogram name string
"DevTools.RemoteDebugging.ConnectionPermission" is referenced by the thunk via
`lea rip`; function starts are found via int3 padding; AcceptDebugging is the
function that references the thunk (its body constructs the BindOnce inline).

macOS/arm64 chain: same anchors, different encodings. The thunk references the
string via `adrp+add`; function bodies are delimited by `brk` filler; the thunk
address is materialized inside AcceptDebugging with a single `adr` (Mach-O lld
relaxes adrp+add -> adr for nearby targets), which is stored at bind state +8.
"""

from __future__ import annotations

import json
import mmap
import struct
import sys
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

CACHE_FILE = Path(__file__).parent / "offsets.json"
HISTOGRAM = b"DevTools.RemoteDebugging.ConnectionPermission\x00"

IS_DARWIN = sys.platform == "darwin"
CHROME_BIN = Path(
    "/Applications/Google Chrome.app/Contents/Frameworks/"
    "Google Chrome Framework.framework/Versions/Current/Google Chrome Framework"
    if IS_DARWIN
    else "/opt/google/chrome/chrome"
)


def current_build_id() -> str | None:
    """Build identifier of the current Chrome binary (fast, cache check)."""
    try:
        if IS_DARWIN:
            return MachOMap(CHROME_BIN, parse_segs=False).build_id
        import re
        import subprocess

        out = subprocess.run(
            ["readelf", "-n", str(CHROME_BIN)], capture_output=True, text=True
        ).stdout
        m = re.search(r"[0-9a-f]{40}", out)
        return m.group(0) if m else None
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Linux / ELF
# ---------------------------------------------------------------------------


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
        self.text_base = min(v for v, *_ in self.segments)

    def off2vaddr(self, off: int) -> int:
        for vaddr, filesz, offset, _ in self.segments:
            if offset <= off < offset + filesz:
                return vaddr + (off - offset)
        raise ValueError(f"offset {off:#x} not in any PT_LOAD")

    def exec_seg(self) -> tuple[int, np.ndarray]:
        vaddr, filesz, offset, flags = max(
            (s for s in self.segments if s[3] & 0x1), key=lambda s: s[1]
        )
        return vaddr, np.frombuffer(
            self._mm, dtype=np.uint8, count=filesz, offset=offset
        )

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


def find_func_start_x86(
    seg_va: int, seg: np.ndarray, pos: int, max_back: int = 0x1000
) -> int:
    """Walk back from pos to the nearest int3-padded function boundary."""
    for i in range(pos - 1, max(0, pos - max_back), -1):
        if seg[i] == 0xCC and seg[i + 1] != 0xCC:
            return seg_va + i + 1
    raise RuntimeError(f"no function start found before {seg_va + pos:#x}")


def disasm_x86(elf: ElfMap, start_va: int, n: int, stop_at_ret=True) -> list:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out = []
    for insn in md.disasm(elf.read(start_va, n), start_va):
        out.append(insn)
        if stop_at_ret and insn.mnemonic == "ret":
            break
    return out


def main_linux() -> int:
    elf = ElfMap(CHROME_BIN)
    print(f"chrome: {CHROME_BIN}\nbuild id: {elf.build_id}")

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

    lambda_va = find_func_start_x86(text_va, text, sites[0])
    insns = disasm_x86(elf, lambda_va, 0x80)
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
        print(
            "FATAL: nothing references the lambda (AcceptDebugging not found)",
            file=sys.stderr,
        )
        return 1
    # Xrefs come in two flavours: the BindOnce functor passed as an argument
    # (lea rsi/rdi/rdx, [rip+L]) and CFI checks (lea rcx, [rip+L]). Only the
    # former lives inside AcceptDebugging.
    accept_va = None
    for p in a_sites:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        insn = next(md.disasm(bytes(text[p : p + 16]), text_va + p))
        if insn.mnemonic == "lea" and not insn.op_str.startswith("rcx"):
            accept_va = find_func_start_x86(text_va, text, p)
            break
    if accept_va is None:
        print("FATAL: no functor-argument xref to lambda found", file=sys.stderr)
        return 1
    dump(
        "ChromeDevToolsManagerDelegate::AcceptDebugging (candidate)",
        disasm_x86(elf, accept_va, 0x200),
    )

    return write_cache(
        elf.build_id, accept_va - elf.text_base, lambda_va - elf.text_base
    )


# ---------------------------------------------------------------------------
# macOS / Mach-O (arm64 slice)
# ---------------------------------------------------------------------------

FAT_MAGIC = 0xCAFEBABE
MACHO64_MAGIC = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B


class MachOMap:
    """View of the host-arch slice of a (possibly fat) Mach-O image."""

    def __init__(self, path: Path, parse_segs: bool = True):
        self._f = open(path, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        mm = self._mm
        magic = struct.unpack(">I", mm[0:4])[0]
        self.slice_off = 0
        if magic == FAT_MAGIC:
            n_arches = struct.unpack(">I", mm[4:8])[0]
            for i in range(n_arches):
                cputype, _, off, size, _ = struct.unpack(
                    ">IIIII", mm[8 + i * 20 : 8 + i * 20 + 20]
                )
                if cputype == CPU_TYPE_ARM64:
                    self.slice_off, self.slice_size = off, size
                    break
            else:
                raise ValueError("no arm64 slice in fat binary")
        o = self.slice_off
        if struct.unpack("<I", mm[o : o + 4])[0] != MACHO64_MAGIC:
            raise ValueError("not a Mach-O 64 binary")
        self.build_id = "unknown"
        ncmds, sizeofcmds = struct.unpack("<II", mm[o + 16 : o + 24])
        self.segments: list[
            tuple[int, int, int, int]
        ] = []  # vmaddr, filesize, absoff, initprot
        self.sections: dict[str, tuple[int, int]] = {}  # name -> (addr, size)
        p = o + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", mm[p : p + 8])
            if not parse_segs and cmd != LC_UUID:
                p += cmdsize
                continue
            if cmd == LC_UUID:
                self.build_id = mm[p + 8 : p + 24].hex()
            elif cmd == LC_SEGMENT_64:
                vmaddr, _, fileoff, filesize, _, initprot, nsects, _ = struct.unpack(
                    "<QQQQIIII", mm[p + 24 : p + 72]
                )
                self.segments.append((vmaddr, filesize, o + fileoff, initprot))
                sp = p + 72
                for _ in range(nsects):
                    name = mm[sp : sp + 16].rstrip(b"\0").decode()
                    addr, size = struct.unpack("<QQ", mm[sp + 32 : sp + 48])
                    self.sections[name] = (addr, size)
                    sp += 80
            p += cmdsize
        self.text_base = self.segments[0][0] if self.segments else 0

    def _v2o(self, va: int) -> int:
        for vaddr, filesz, absoff, _ in self.segments:
            if vaddr <= va < vaddr + filesz:
                return absoff + (va - vaddr)
        raise ValueError(f"vaddr {va:#x} not mapped")

    def read(self, va: int, n: int) -> bytes:
        off = self._v2o(va)
        return self._mm[off : off + n]

    def find(self, needle: bytes) -> int:
        off = self._mm.find(needle, self.slice_off, self.slice_off + self.slice_size)
        if off < 0:
            return -1
        for vaddr, filesz, absoff, _ in self.segments:
            if absoff <= off < absoff + filesz:
                return vaddr + (off - absoff)
        raise ValueError("string found outside mapped segments")

    def text_words(self) -> tuple[int, np.ndarray]:
        addr, size = self.sections["__text"]
        va = addr
        off = self._v2o(addr)
        return va, np.frombuffer(self._mm, dtype="<u4", count=size // 4, offset=off)


class Arm64Scan:
    """Vectorised searches over the arm64 __text of a MachOMap."""

    def __init__(self, img: MachOMap):
        self.img = img
        self.text_va, words = img.text_words()
        self.buf = words
        w = words.astype(np.int64)
        pc = self.text_va + np.arange(len(words), dtype=np.int64) * 4
        self.pc = pc
        imm = ((w >> 3) & 0x1FFFFC) | ((w >> 29) & 3)  # adrp/adr immhi:immlo
        self.imm21 = np.where(imm >= (1 << 20), imm - (1 << 21), imm)
        self.is_adrp = (words & 0x9F000000) == 0x90000000
        self.is_adr = (words & 0x9F000000) == 0x10000000

    def find_imm_refs(self, target: int) -> list[int]:
        """VAs of instructions materialising `target` (adr, or adrp+add)."""
        refs = []
        adr_hit = np.nonzero(self.is_adr & (self.pc + self.imm21 == target))[0]
        refs += [int(self.pc[i]) for i in adr_hit]
        page = self.pc & ~0xFFF
        cand = np.nonzero(
            self.is_adrp & (page + (self.imm21 << 12) == (target & ~0xFFF))
        )[0]
        lo = target & 0xFFF
        for i in cand:
            rd = int(self.buf[i]) & 31
            for j in range(i + 1, min(i + 6, len(self.buf))):
                a = int(self.buf[j])
                if (a & 0xFF000000) == 0x91000000 and ((a >> 5) & 31) == rd:
                    if ((a >> 10) & 0xFFF) == lo and not ((a >> 22) & 1):
                        refs.append(int(self.pc[i]))
                    break
        return sorted(refs)

    def func_starts_before(
        self, va: int, max_back: int = 0x400, limit: int = 6
    ) -> list[int]:
        """Candidate function entries below va: word after each `brk` filler."""
        words = (min(va - self.text_va, max_back)) // 4
        if words <= 0:
            return []
        w = self.buf[(va - self.text_va) // 4 - words : (va - self.text_va) // 4]
        brks = np.nonzero((w & 0xFFE0001F) == 0xD4200000)[0]
        starts = [va - words * 4 + (int(k) + 1) * 4 for k in brks][-limit:]
        return [s for s in reversed(starts) if s < va]

    def disasm(self, va: int, nbytes: int):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        return list(md.disasm(self.img.read(va, nbytes), va))

    def resolve_entry(self, xref_va: int, check_insns: int = 3) -> int:
        """Nearest plausible function entry above xref_va (validates a prologue)."""
        for start in self.func_starts_before(xref_va):
            insns = self.disasm(start, check_insns * 4)
            if len(insns) == check_insns and self._looks_like_prologue(insns[0]):
                return start
        raise RuntimeError(f"no function entry found before {xref_va:#x}")

    @staticmethod
    def _looks_like_prologue(insn) -> bool:
        m, o = insn.mnemonic, insn.op_str
        return (
            m == "stp"
            or m == "sub"
            and o.startswith("sp, sp,")
            or m == "str"
            and "x29" in o
            or m in ("pacibsp", "paciasp", "bti")
        )


def main_darwin() -> int:
    img = MachOMap(CHROME_BIN)
    print(f"chrome framework: {CHROME_BIN}\nuuid: {img.build_id}")

    str_va = img.find(HISTOGRAM)
    if str_va < 0:
        print("FATAL: histogram string not found", file=sys.stderr)
        return 1
    print(f"histogram string @ {str_va:#x}")

    scan = Arm64Scan(img)
    sites = scan.find_imm_refs(str_va)
    print(f"adrp+add xrefs to string: {[hex(v) for v in sites]}")
    if not sites:
        print("FATAL: no code references the histogram string", file=sys.stderr)
        return 1

    lambda_va = scan.resolve_entry(sites[0])
    insns = scan.disasm(lambda_va, 0x80)
    dump("wrapper lambda / invoke thunk (candidate)", insns[:24])
    ops = [(i.mnemonic, i.op_str.replace(" ", "")) for i in insns[:24]]
    ok = (
        any(
            m == "cmp" and o.endswith(",#1") and w in o for m, o in ops for w in ("w1",)
        )
        and any(m == "ldr" and "[x0,#0x28]" in o for m, o in ops)  # move-out inner cb
        and any(m == "blr" for m, o in ops)  # runs the inner callback
    )
    print(f"lambda verified @ {lambda_va:#x}: {ok}")
    if not ok:
        print("WARN: lambda shape mismatch, inspect the disasm above")

    bind_sites = scan.find_imm_refs(lambda_va)
    print(f"adr/adrp+add xrefs to thunk: {[hex(v) for v in bind_sites]}")
    if not bind_sites:
        print(
            "FATAL: nothing materialises the thunk (AcceptDebugging not found)",
            file=sys.stderr,
        )
        return 1
    accept_va = scan.resolve_entry(bind_sites[0])
    dump(
        "ChromeDevToolsManagerDelegate::AcceptDebugging (candidate)",
        scan.disasm(accept_va, 0x70),
    )

    return write_cache(
        img.build_id, accept_va - img.text_base, lambda_va - img.text_base
    )


# ---------------------------------------------------------------------------


def dump(title: str, insns: list) -> None:
    print(f"--- {title} ---")
    for i in insns:
        print(f"  {i.address:#12x}: {i.mnemonic} {i.op_str}")


def write_cache(build_id: str, accept_off: int, lambda_off: int) -> int:
    offsets = {
        "accept_debugging": accept_off,
        "lambda_invoke": lambda_off,
        "allow_value": 1,
    }
    CACHE_FILE.write_text(
        json.dumps({"build_id": build_id, "offsets": offsets}, indent=2)
    )
    print(f"offsets cached -> {CACHE_FILE}\n{json.dumps(offsets, indent=2)}")
    return 0


def main() -> int:
    if IS_DARWIN:
        return main_darwin()
    return main_linux()


if __name__ == "__main__":
    sys.exit(main())
