"""Find every call site that references a given imported API, across the
whole driver, using pefile+capstone. Tells us whether a dangerous primitive
is called only during driver init (less interesting) or from many places
including the dispatch path (more interesting)."""
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, x86

path, target_name = sys.argv[1], sys.argv[2]
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase

# find the IAT slot RVA for the target import
target_rva = None
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else None
        if name == target_name:
            target_rva = imp.address - base
            print(f"found import {entry.dll.decode()}!{name} at IAT RVA 0x{target_rva:x}")
if target_rva is None:
    print("import not found")
    sys.exit(1)

secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData, s.Characteristics)
        for s in pe.sections]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

sites = []
for va, vs, rs, ptr, ch in secs:
    if not (ch & 0x20000000):
        continue
    code = pe.__data__[ptr:ptr + rs]
    for insn in md.disasm(code, base + va):
        if insn.id in (x86.X86_INS_CALL, x86.X86_INS_JMP):
            for op in insn.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    tgt = insn.address + insn.size + op.mem.disp - base
                    if tgt == target_rva:
                        sites.append(insn.address - base)

print(f"call sites referencing {target_name}: {len(sites)}")
for s in sites:
    print(f"  0x{s:08x}")
