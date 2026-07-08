"""Ground-truth dispatch finder (pefile + capstone) to validate disasm.cpp.

Locates MajorFunction[IRP_MJ_DEVICE_CONTROL] the same way our C++ does, then
disassembles the handler and dumps the instructions that carry IOCTL-looking
immediates or call imports -- so we can see what disasm.cpp *should* report.
"""
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, x86

MAJOR_BASE, PTR, DEVCTL = 0x70, 8, 0x0E

pe = pefile.PE(sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData,
         s.PointerToRawData, s.Characteristics) for s in pe.sections]


def sec_of(rva):
    for va, vs, rs, ptr, ch in secs:
        if va <= rva < va + max(vs, rs):
            return va, vs, rs, ptr, ch
    return None


def is_exec(rva):
    s = sec_of(rva)
    return s is not None and (s[4] & 0x20000000)


def read(rva, n):
    s = sec_of(rva)
    if not s:
        return b""
    va, vs, rs, ptr, ch = s
    off = ptr + (rva - va)
    return pe.__data__[off:off + n]


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# --- locate handler: lea reg,[rip+x] ; mov [reg+0xE0], reg ---
handler = None
for va, vs, rs, ptr, ch in secs:
    if not (ch & 0x20000000):
        continue
    code = pe.__data__[ptr:ptr + rs]
    leas = {}
    for insn in md.disasm(code, base + va):
        if insn.id == x86.X86_INS_LEA:
            o0, o1 = insn.operands
            if o1.type == x86.X86_OP_MEM and o1.mem.base == x86.X86_REG_RIP:
                tgt = insn.address + insn.size + o1.mem.disp - base
                if is_exec(tgt):
                    leas[o0.reg] = tgt
        elif insn.id == x86.X86_INS_MOV:
            o0, o1 = insn.operands
            if (o0.type == x86.X86_OP_MEM and o1.type == x86.X86_OP_REG
                    and o0.mem.base not in (0, x86.X86_REG_RIP)):
                disp = o0.mem.disp
                if (disp >= MAJOR_BASE and (disp - MAJOR_BASE) % PTR == 0
                        and (disp - MAJOR_BASE) // PTR == DEVCTL
                        and o1.reg in leas):
                    handler = leas[o1.reg]

print(f"image_base=0x{base:x}  entry=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
print(f"DEVICE_CONTROL handler RVA = "
      f"{'0x%08x' % handler if handler else 'NOT FOUND'}")
if not handler:
    sys.exit(0)

# --- dump the handler: IOCTL-ish immediates and call targets ---
code = read(handler, 0x1200)
print(f"\n-- first ~60 notable insns from handler 0x{handler:08x} --")
n = 0
for insn in md.disasm(code, base + handler):
    txt = f"{insn.mnemonic} {insn.op_str}"
    interesting = False
    for op in insn.operands:
        if op.type == x86.X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            dt = v >> 16
            if (dt == 0x22 or dt >= 0x8000) and v != 0xFFFFFFFF:
                method = v & 3
                print(f"  0x{insn.address-base:08x}: {txt:40s} "
                      f"IMM=0x{v:08x} method={method}"
                      f"{'  <-- METHOD_NEITHER' if method == 3 else ''}")
                interesting = True
    if insn.id in (x86.X86_INS_CALL, x86.X86_INS_JMP):
        print(f"  0x{insn.address-base:08x}: {txt}")
        interesting = True
    n += 1
    if n > 400 or insn.id == x86.X86_INS_RET:
        break
