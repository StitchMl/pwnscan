from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .model import BinaryInfo


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class _ElfSection:
    name: str
    kind: int
    flags: int
    va: int
    offset: int
    size: int
    link: int
    item_size: int


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
INTERESTING_APIS = (
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "fscanf", "read", "recv", "memcpy", "printf", "fprintf", "syslog",
    "system", "popen", "execve", "mprotect", "VirtualProtect", "WinExec",
    "CreateProcess", "LoadLibrary", "GetProcAddress",
    "malloc", "calloc", "realloc", "free", "operator new", "operator delete",
)


def extract_strings(data: bytes, minimum: int = 4, limit: int = 4000) -> List[str]:
    pattern = ASCII_RE if minimum == 4 else re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    values = {match.group().decode("ascii", "replace") for match in pattern.finditer(data)}
    return sorted(values, key=lambda value: (value.lower(), value))[:limit]


def _u(data: bytes, offset: int, fmt: str, endian: str = "<") -> int:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ParseError("truncated binary structure")
    return int(struct.unpack_from(endian + fmt, data, offset)[0])


def _c_string(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", "replace")


def _interesting_names(strings: Sequence[str]) -> List[str]:
    found = set()
    for value in strings:
        tail = value.rsplit("/", 1)[-1]
        for api in INTERESTING_APIS:
            if tail == api or tail.startswith((api + "@", "_" + api)):
                found.add(api)
    return sorted(found, key=str.lower)


def parse_binary(data: bytes) -> BinaryInfo:
    if data.startswith(b"\x7fELF"):
        return parse_elf(data)
    if data.startswith(b"MZ"):
        return parse_pe(data)
    if len(data) >= 4 and data[:4] in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    }:
        return parse_macho(data)
    if len(data) >= 8 and data[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        endian = ">" if data[:4] == b"\xca\xfe\xba\xbe" else "<"
        arch_count = _u(data, 4, "I", endian)
        if 1 <= arch_count <= 32 and len(data) >= 8 + arch_count * 20:
            raise ParseError("universal/fat Mach-O is not supported; extract a thin slice")
    raise ParseError("unsupported file format; expected ELF, PE, or Mach-O")


ELF_MACHINES = {3: "x86", 8: "mips", 20: "ppc", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}


def _elf_program_headers(data: bytes, bits: int, endian_char: str, phoff: int, phentsize: int, phnum: int) -> Tuple[Optional[bool], bool, bool, bool, bool, bool]:
    nx: Optional[bool] = None
    relro = False
    bind_now = False
    dynamic = False
    has_interp = False
    is_pie_flag = False
    min_phentsize = 56 if bits == 64 else 32
    for index in range(min(phnum, 4096)):
        off = phoff + index * phentsize
        if phentsize < min_phentsize or off + phentsize > len(data):
            break
        p_type = _u(data, off, "I", endian_char)
        p_flags = _u(data, off + (4 if bits == 64 else 24), "I", endian_char)
        if p_type == 0x6474E551:
            nx = not bool(p_flags & 1)
        elif p_type == 0x6474E552:
            relro = True
        elif p_type == 2:
            dynamic = True
            dyn_off = _u(data, off + (8 if bits == 64 else 4), "Q" if bits == 64 else "I", endian_char)
            dyn_size = _u(data, off + (32 if bits == 64 else 16), "Q" if bits == 64 else "I", endian_char)
            dyn_bind_now, pie_flag = _elf_dynamic_flags(data, bits, endian_char, dyn_off, dyn_size)
            bind_now = bind_now or dyn_bind_now
            is_pie_flag = is_pie_flag or pie_flag
        elif p_type == 3:
            has_interp = True
    return nx, relro, bind_now, dynamic, has_interp, is_pie_flag


def _elf_dynamic_flags(data: bytes, bits: int, endian_char: str, dyn_off: int, dyn_size: int) -> Tuple[bool, bool]:
    bind_now = False
    is_pie_flag = False
    stride = 16 if bits == 64 else 8
    if dyn_off <= 0 or dyn_size <= 0:
        return bind_now, is_pie_flag
    for dyn_at in range(dyn_off, min(len(data), dyn_off + dyn_size), stride):
        if dyn_at + stride > len(data):
            break
        tag = _u(data, dyn_at, "Q" if bits == 64 else "I", endian_char)
        value = _u(data, dyn_at + stride // 2, "Q" if bits == 64 else "I", endian_char)
        if tag == 0:
            break
        bind_now = bind_now or tag == 24 or (tag == 30 and bool(value & 8)) or (tag == 0x6FFFFFFB and bool(value & 1))
        is_pie_flag = is_pie_flag or (tag == 0x6FFFFFFB and bool(value & 0x08000000))
    return bind_now, is_pie_flag


def parse_elf(data: bytes) -> BinaryInfo:
    if len(data) < 0x34:
        raise ParseError("truncated ELF header")
    elf_class = data[4]
    bits = {1: 32, 2: 64}.get(elf_class)
    if bits is None:
        raise ParseError("invalid ELF class")
    endian_char = {1: "<", 2: ">"}.get(data[5])
    if endian_char is None:
        raise ParseError("invalid ELF byte order")
    endian = "little" if endian_char == "<" else "big"
    machine = _u(data, 18, "H", endian_char)
    e_type = _u(data, 16, "H", endian_char)
    if bits == 64:
        if len(data) < 0x40:
            raise ParseError("truncated ELF64 header")
        entry = _u(data, 24, "Q", endian_char)
        phoff = _u(data, 32, "Q", endian_char)
        shoff = _u(data, 40, "Q", endian_char)
        phentsize, phnum = _u(data, 54, "H", endian_char), _u(data, 56, "H", endian_char)
        shentsize, shnum, shstrndx = (_u(data, 58, "H", endian_char), _u(data, 60, "H", endian_char), _u(data, 62, "H", endian_char))
    else:
        entry = _u(data, 24, "I", endian_char)
        phoff = _u(data, 28, "I", endian_char)
        shoff = _u(data, 32, "I", endian_char)
        phentsize, phnum = _u(data, 42, "H", endian_char), _u(data, 44, "H", endian_char)
        shentsize, shnum, shstrndx = (_u(data, 46, "H", endian_char), _u(data, 48, "H", endian_char), _u(data, 50, "H", endian_char))

    nx, relro, bind_now, dynamic, has_interp, is_pie_flag = _elf_program_headers(data, bits, endian_char, phoff, phentsize, phnum)
    sections = _elf_sections(data, bits, endian_char, shoff, shentsize, shnum, shstrndx)
    symbols, symbol_addresses, undefined_symbols, has_symtab = _elf_symbols(data, bits, endian_char, sections)
    values = extract_strings(data)
    parsed_imports = sorted({name for name in undefined_symbols if name in INTERESTING_APIS}, key=str.lower)
    string_hints = sorted(set(_interesting_names(values)) - set(parsed_imports), key=str.lower)
    imports = sorted(set(parsed_imports) | set(string_hints), key=str.lower)
    stack_canary = (
        any(name in {"__stack_chk_fail", "__stack_chk_guard"} or name.startswith("__stack_chk_fail@") for name in symbols)
        or (not has_symtab and b"__stack_chk_fail" in data)
    )
    pie = e_type == 3 and (has_interp or is_pie_flag)
    relro_state = "full" if relro and bind_now else ("partial" if relro else "none")
    architecture = ELF_MACHINES.get(machine, "machine-%d" % machine)
    plt_addresses = _elf_plt_addresses(data, bits, endian_char, sections, architecture)
    return BinaryInfo(
        format="ELF", bits=bits, endian=endian,
        architecture=architecture,
        entrypoint=entry, imports=imports, symbols=symbols, strings=values,
        mitigations={"nx": nx, "pie": pie, "stack_canary": stack_canary, "relro": relro, "aslr": e_type == 3},
        metadata={
            "elf_type": e_type, "elf_role": "pie" if pie else ("shared_object" if e_type == 3 else "executable"),
            "dynamic": dynamic, "relro": relro_state, "sections": sorted({section.name for section in sections}),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "symbol_addresses": symbol_addresses,
            "plt_addresses": plt_addresses,
            **_elf_exploit_metadata(data, bits, sections, architecture),
        },
    )


def _elf_sections(data: bytes, bits: int, endian: str, shoff: int, entsize: int, count: int, names_index: int) -> List[_ElfSection]:
    raw = []
    minimum = 64 if bits == 64 else 40
    if shoff == 0 or count == 0 or entsize < minimum or count > 65535:
        return []
    for index in range(count):
        off = shoff + index * entsize
        if off + minimum > len(data):
            break
        if bits == 64:
            name, kind, flags = _u(data, off, "I", endian), _u(data, off + 4, "I", endian), _u(data, off + 8, "Q", endian)
            va, file_off, size, link, item_size = (
                _u(data, off + 16, "Q", endian), _u(data, off + 24, "Q", endian),
                _u(data, off + 32, "Q", endian), _u(data, off + 40, "I", endian), _u(data, off + 56, "Q", endian),
            )
        else:
            name, kind, flags = _u(data, off, "I", endian), _u(data, off + 4, "I", endian), _u(data, off + 8, "I", endian)
            va, file_off, size, link, item_size = (
                _u(data, off + 12, "I", endian), _u(data, off + 16, "I", endian),
                _u(data, off + 20, "I", endian), _u(data, off + 24, "I", endian), _u(data, off + 36, "I", endian),
            )
        raw.append((name, kind, flags, va, file_off, size, link, item_size))
    names = b""
    if 0 <= names_index < len(raw) and raw[names_index][1] != 8:
        _, _, _, _, name_off, name_size, _, _ = raw[names_index]
        names = data[name_off:min(len(data), name_off + name_size)]
    result: List[_ElfSection] = []
    for index, (name_at, kind, flags, va, file_off, size, link, item_size) in enumerate(raw):
        section_name = _c_string(names, name_at) if name_at < len(names) else "section_%d" % index
        if not section_name and index > 0:
            section_name = "section_%d" % index
        result.append(_ElfSection(section_name, kind, flags, va, file_off, size, link, item_size))
    return result


def _elf_symbols(data: bytes, bits: int, endian: str, sections: Sequence[_ElfSection]) -> Tuple[List[str], Dict[str, int], List[str], bool]:
    result = set()
    addresses: Dict[str, int] = {}
    undefined = set()
    has_symtab = False
    for section in sections:
        if section.kind not in {2, 11}:
            continue
        has_symtab = True
        if section.link >= len(sections):
            continue
        strtab = sections[section.link]
        if strtab.kind == 8:
            continue
        strings = data[strtab.offset:min(len(data), strtab.offset + strtab.size)]
        default_size = 24 if bits == 64 else 16
        stride = section.item_size or default_size
        if stride < default_size:
            continue
        for at in range(section.offset, min(len(data), section.offset + section.size), stride):
            if at + default_size > len(data):
                break
            name_at = _u(data, at, "I", endian)
            name = _c_string(strings, name_at)
            if name:
                result.add(name)
                value = _u(data, at + (8 if bits == 64 else 4), "Q" if bits == 64 else "I", endian)
                section_index = _u(data, at + (6 if bits == 64 else 14), "H", endian)
                if value and section_index != 0 and (name not in addresses or value < addresses[name]):
                    addresses[name] = value
                if section_index == 0:
                    undefined.add(name)
    return (
        sorted(result, key=lambda value: (value.lower(), value)),
        {name: addresses[name] for name in sorted(addresses, key=str.lower)},
        sorted(undefined, key=str.lower),
        has_symtab,
    )


def _elf_plt_addresses(data: bytes, bits: int, endian: str, sections: Sequence[_ElfSection], architecture: str) -> Dict[str, str]:
    if architecture not in {"x86", "x86_64"}:
        return {}
    by_name = {section.name: section for section in sections}
    rel_section = by_name.get(".rela.plt") or by_name.get(".rel.plt")
    if rel_section is None or rel_section.kind not in {4, 9} or rel_section.link >= len(sections):
        return {}
    dynsym = sections[rel_section.link]
    if dynsym.kind not in {2, 11} or dynsym.link >= len(sections):
        return {}
    dynstr = sections[dynsym.link]
    if dynstr.kind == 8:
        return {}
    plt_sec = by_name.get(".plt.sec")
    plt_base = plt_sec or by_name.get(".plt")
    if plt_base is None or plt_base.va == 0:
        return {}
    plt_stride = plt_base.item_size or 16
    first_index = 0 if plt_sec is not None else 1
    is_rela = rel_section.kind == 4
    rel_stride = rel_section.item_size or ((24 if is_rela else 16) if bits == 64 else (12 if is_rela else 8))
    sym_stride = dynsym.item_size or (24 if bits == 64 else 16)
    if rel_stride < (16 if bits == 64 else 8) or sym_stride < (24 if bits == 64 else 16):
        return {}
    strings = data[dynstr.offset:min(len(data), dynstr.offset + dynstr.size)]
    count = min(rel_section.size // rel_stride, 65535)
    result: Dict[str, str] = {}
    for index in range(count):
        rel_at = rel_section.offset + index * rel_stride
        if rel_at + rel_stride > len(data):
            break
        r_info = _u(data, rel_at + (8 if bits == 64 else 4), "Q" if bits == 64 else "I", endian)
        sym_index = (r_info >> 32) if bits == 64 else (r_info >> 8)
        sym_at = dynsym.offset + sym_index * sym_stride
        if sym_at + 4 > min(len(data), dynsym.offset + dynsym.size):
            continue
        name = _c_string(strings, _u(data, sym_at, "I", endian))
        if not name:
            continue
        stub_va = plt_base.va + (index + first_index) * plt_stride
        if plt_base.size and stub_va >= plt_base.va + plt_base.size:
            break
        result["0x%x" % stub_va] = name
    return result


def _elf_exploit_metadata(data: bytes, bits: int, sections: Sequence[_ElfSection], architecture: str) -> Dict[str, object]:
    """Extract address-bearing facts from sections without executing the target."""
    patterns: Dict[str, bytes] = {}
    if architecture in {"x86", "x86_64"}:
        patterns = {"ret": b"\xc3", "leave_ret": b"\xc9\xc3", "jmp_rsp": b"\xff\xe4", "syscall_ret": b"\x0f\x05\xc3"}
        if bits == 64:
            patterns.update({"pop_rdi_ret": b"\x5f\xc3", "pop_rsi_ret": b"\x5e\xc3", "pop_rdx_ret": b"\x5a\xc3"})
    gadgets: Dict[str, List[int]] = {name: [] for name in patterns}
    useful: Dict[str, List[int]] = {"/bin/sh": []}
    rwx: List[str] = []
    for section in sections:
        if section.flags & 1 and section.flags & 4:
            rwx.append(section.name)
        if section.kind == 8:
            continue
        blob = data[section.offset:min(len(data), section.offset + section.size)]
        if section.flags & 4 and patterns:
            for label, needle in patterns.items():
                start = 0
                while len(gadgets[label]) < 8:
                    found = blob.find(needle, start)
                    if found < 0:
                        break
                    gadgets[label].append(section.va + found)
                    start = found + 1
        if section.flags & 2 or section.va:
            start = 0
            while len(useful["/bin/sh"]) < 4:
                found = blob.find(b"/bin/sh\0", start)
                if found < 0:
                    break
                useful["/bin/sh"].append(section.va + found)
                start = found + 1
    return {
        "rwx_sections": sorted(set(rwx), key=str.lower),
        "gadgets": {name: values for name, values in sorted(gadgets.items()) if values},
        "useful_strings": {name: values for name, values in sorted(useful.items()) if values},
    }


PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0xAA64: "aarch64"}


def _pe_rva_to_offset(data: bytes, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int, rva: int) -> Optional[int]:
    for _, va, _, raw, rs, _ in sections:
        if rs > 0 and va <= rva < va + rs:
            result = raw + (rva - va)
            return result if result < len(data) else None
    if rva < first_section_va and rva < len(data):
        return rva
    return None


def _pe_imports(data: bytes, bits: int, import_rva: int, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int) -> Set[str]:
    imports: Set[str] = set()
    descriptor = _pe_rva_to_offset(data, sections, first_section_va, import_rva) if import_rva else None
    stride = 8 if bits == 64 else 4
    ordinal_mask = 1 << (bits - 1)
    for _ in range(4096):
        if descriptor is None or descriptor + 20 > len(data):
            break
        original, _, _, name_rva, thunk = struct.unpack_from("<IIIII", data, descriptor)
        if not any((original, name_rva, thunk)):
            break
        descriptor += 20
        ilt_rva = original or thunk
        if not ilt_rva:
            continue
        thunk_off = _pe_rva_to_offset(data, sections, first_section_va, ilt_rva)
        if thunk_off is None:
            continue
        for item in range(4096):
            at = thunk_off + item * stride
            if at + stride > len(data):
                break
            value = _u(data, at, "Q" if bits == 64 else "I")
            if value == 0:
                break
            if not value & ordinal_mask:
                name_off = _pe_rva_to_offset(data, sections, first_section_va, value & 0x7FFFFFFF)
                if name_off is not None:
                    name = _c_string(data, name_off + 2)
                    if name:
                        imports.add(name)
    return imports


def _pe_exports(data: bytes, image_base: int, export_rva: int, export_size: int, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int) -> Tuple[Set[str], Dict[str, int]]:
    exported: Set[str] = set()
    addresses: Dict[str, int] = {}
    exp_off = _pe_rva_to_offset(data, sections, first_section_va, export_rva) if export_rva else None
    if exp_off is None or exp_off + 40 > len(data):
        return exported, addresses
    num_funcs = _u(data, exp_off + 20, "I")
    num_names = _u(data, exp_off + 24, "I")
    funcs_off = _pe_rva_to_offset(data, sections, first_section_va, _u(data, exp_off + 28, "I"))
    names_off = _pe_rva_to_offset(data, sections, first_section_va, _u(data, exp_off + 32, "I"))
    ords_off = _pe_rva_to_offset(data, sections, first_section_va, _u(data, exp_off + 36, "I"))
    if funcs_off is None or names_off is None or ords_off is None:
        return exported, addresses
    for index in range(min(num_names, 65535)):
        if names_off + index * 4 + 4 > len(data) or ords_off + index * 2 + 2 > len(data):
            break
        name_rva = _u(data, names_off + index * 4, "I")
        name_off = _pe_rva_to_offset(data, sections, first_section_va, name_rva)
        name = _c_string(data, name_off) if name_off is not None else ""
        if not name:
            continue
        exported.add(name)
        ord_idx = _u(data, ords_off + index * 2, "H")
        if ord_idx < num_funcs and funcs_off + ord_idx * 4 + 4 <= len(data):
            func_rva = _u(data, funcs_off + ord_idx * 4, "I")
            is_forwarder = export_size > 0 and export_rva <= func_rva < export_rva + export_size
            if func_rva and not is_forwarder:
                addresses[name] = image_base + func_rva
    return exported, addresses


def parse_pe(data: bytes) -> BinaryInfo:
    if len(data) < 0x40:
        raise ParseError("truncated DOS header")
    pe_at = _u(data, 0x3C, "I")
    if pe_at + 24 > len(data) or data[pe_at:pe_at + 4] != b"PE\0\0":
        raise ParseError("invalid PE signature")
    machine = _u(data, pe_at + 4, "H")
    sections_count = _u(data, pe_at + 6, "H")
    optional_size = _u(data, pe_at + 20, "H")
    characteristics = _u(data, pe_at + 22, "H")
    opt = pe_at + 24
    if opt + 2 > len(data) or optional_size < 32 or opt + optional_size > len(data):
        raise ParseError("truncated PE optional header")
    magic = _u(data, opt, "H")
    if magic == 0x20B:
        bits, image_base_off, data_dir_off = 64, 24, 112
        image_base = _u(data, opt + image_base_off, "Q")
    elif magic == 0x10B:
        bits, image_base_off, data_dir_off = 32, 28, 96
        image_base = _u(data, opt + image_base_off, "I")
    else:
        raise ParseError("unsupported PE optional header")
    entry_rva = _u(data, opt + 16, "I")
    dll_chars = _u(data, opt + 70, "H") if optional_size >= 72 else None
    section_at = opt + optional_size
    sections = []
    for index in range(min(sections_count, 4096)):
        at = section_at + index * 40
        if at + 40 > len(data):
            break
        name = data[at:at + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_at = _u(data, at + 8, "I"), _u(data, at + 12, "I")
        raw_size, raw_at = _u(data, at + 16, "I"), _u(data, at + 20, "I")
        flags = _u(data, at + 36, "I")
        sections.append((name, virtual_at, virtual_size, raw_at, raw_size, flags))

    first_section_va = min((va for _, va, *_ in sections if va > 0), default=len(data))
    imports = _pe_imports(data, bits, _u(data, opt + data_dir_off + 8, "I"), sections, first_section_va) if data_dir_off + 16 <= optional_size else set()
    exported_symbols, symbol_addresses = (
        _pe_exports(data, image_base, _u(data, opt + data_dir_off, "I"), _u(data, opt + data_dir_off + 4, "I"), sections, first_section_va)
        if data_dir_off + 8 <= optional_size
        else (set(), {})
    )

    parsed_imports = sorted(imports, key=str.lower)
    values = extract_strings(data)
    string_hints = sorted(set(_interesting_names(values)) - set(parsed_imports), key=str.lower)
    imports.update(string_hints)
    nx = bool(dll_chars & 0x0100) if dll_chars is not None else None
    aslr = bool(dll_chars & 0x0040) if dll_chars is not None else None
    cfg = bool(dll_chars & 0x4000) if dll_chars is not None else None
    writable_executable = any((flags & 0x80000000) and (flags & 0x20000000) for *_, flags in sections)
    return BinaryInfo(
        format="PE", bits=bits, endian="little", architecture=PE_MACHINES.get(machine, "machine-%d" % machine),
        entrypoint=image_base + entry_rva if entry_rva else None, image_base=image_base,
        imports=sorted(imports, key=str.lower),
        symbols=sorted(exported_symbols, key=lambda value: (value.lower(), value)),
        strings=values,
        mitigations={"nx": nx, "aslr": aslr, "cfg": cfg, "stack_canary": None, "writable_executable": writable_executable},
        metadata={
            "dll": bool(characteristics & 0x2000), "sections": sorted(section[0] for section in sections),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "symbol_addresses": {name: symbol_addresses[name] for name in sorted(symbol_addresses, key=str.lower)},
            "rwx_sections": sorted(section[0] for section in sections if (section[5] & 0x80000000) and (section[5] & 0x20000000)),
        },
    )


MACH_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "aarch64"}


def _macho_symtab(data: bytes, bits: int, endian: str, at: int) -> Tuple[Set[str], Set[str], Dict[str, int]]:
    symbols: Set[str] = set()
    undefined: Set[str] = set()
    addresses: Dict[str, int] = {}
    symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, at + 8)
    str_end = min(len(data), stroff + strsize)
    nlist_size = 16 if bits == 64 else 12
    if stroff >= len(data) or symoff >= len(data):
        return symbols, undefined, addresses
    for index in range(min(nsyms, 65535)):
        sym_at = symoff + index * nlist_size
        if sym_at + nlist_size > len(data):
            break
        n_strx = _u(data, sym_at, "I", endian)
        n_type = data[sym_at + 4]
        n_sect = data[sym_at + 5]
        n_value = _u(data, sym_at + 8, "Q" if bits == 64 else "I", endian)
        if n_type & 0xE0 or stroff + n_strx >= str_end:
            continue
        raw_name = _c_string(data, stroff + n_strx)
        if not raw_name:
            continue
        clean_name = raw_name[1:] if raw_name.startswith("_") else raw_name
        symbols.add(clean_name)
        if (n_type & 0x0E) == 0x0 and (n_type & 0x01) and n_sect == 0:
            undefined.add(clean_name)
        elif (n_type & 0x0E) == 0x0E and n_value and (clean_name not in addresses or n_value < addresses[clean_name]):
            addresses[clean_name] = n_value
    return symbols, undefined, addresses


def parse_macho(data: bytes) -> BinaryInfo:
    magic = data[:4]
    endian = ">" if magic in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"} else "<"
    bits = 64 if magic in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"} else 32
    header_size = 32 if bits == 64 else 28
    if len(data) < header_size:
        raise ParseError("truncated Mach-O header")
    cpu = _u(data, 4, "I", endian)
    file_type = _u(data, 12, "I", endian)
    commands = _u(data, 16, "I", endian)
    flags = _u(data, 24, "I", endian)
    at = header_size
    entry_offset: Optional[int] = None
    text_vmaddr: Optional[int] = None
    dylibs = []
    executable_stack = False
    rwx_sections = set()
    symbols = set()
    undefined_symbols = set()
    symbol_addresses: Dict[str, int] = {}
    has_symtab = False
    for _ in range(min(commands, 65535)):
        if at + 8 > len(data):
            break
        command, size = _u(data, at, "I", endian), _u(data, at + 4, "I", endian)
        if size < 8 or at + size > len(data):
            break
        if command == 0x80000028 and size >= 24:
            entry_offset = _u(data, at + 8, "Q", endian)
        elif command in {0xC, 0x18, 0x1F, 0x8000001F, 0x80000018} and size >= 24:
            name_at = _u(data, at + 8, "I", endian)
            name = _c_string(data, at + name_at)
            if name:
                dylibs.append(name)
        elif command in {0x1, 0x19} and size >= (72 if command == 0x19 else 56):
            segname = data[at + 8:at + 24].split(b"\0", 1)[0].decode("ascii", "replace")
            vmaddr = _u(data, at + 24, "Q" if command == 0x19 else "I", endian)
            initprot = _u(data, at + (60 if command == 0x19 else 44), "I", endian)
            if segname == "__TEXT":
                text_vmaddr = vmaddr
            if segname == "__UNIXSTACK" and (initprot & 4):
                executable_stack = True
            if (initprot & 0x6) == 0x6:
                rwx_sections.add(segname or "segment")
        elif command == 0x2 and size >= 24:
            has_symtab = True
            syms, undef, addrs = _macho_symtab(data, bits, endian, at)
            symbols.update(syms)
            undefined_symbols.update(undef)
            symbol_addresses.update(addrs)
        at += size
    entry = (text_vmaddr + entry_offset) if (entry_offset is not None and text_vmaddr is not None) else entry_offset
    values = extract_strings(data)
    parsed_imports = sorted({name for name in undefined_symbols if name in INTERESTING_APIS}, key=str.lower)
    string_hints = sorted(set(_interesting_names(values)) - set(parsed_imports), key=str.lower)
    imports = sorted(set(parsed_imports) | set(string_hints), key=str.lower)
    pie = bool(flags & 0x200000)
    stack_canary = (
        any(name in {"__stack_chk_fail", "__stack_chk_guard"} for name in symbols)
        or (not has_symtab and b"___stack_chk_fail" in data)
    )
    if executable_stack:
        rwx_sections.add("__UNIXSTACK")
    return BinaryInfo(
        format="Mach-O", bits=bits, endian="big" if endian == ">" else "little",
        architecture=MACH_CPU.get(cpu, "cpu-%d" % cpu), entrypoint=entry,
        imports=imports,
        symbols=sorted(symbols, key=lambda value: (value.lower(), value)),
        strings=values,
        mitigations={"nx": not executable_stack, "pie": pie, "aslr": pie, "stack_canary": stack_canary},
        metadata={
            "file_type": file_type, "dylibs": sorted(set(dylibs), key=str.lower),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "symbol_addresses": {name: symbol_addresses[name] for name in sorted(symbol_addresses, key=str.lower)},
            "rwx_sections": sorted(rwx_sections, key=str.lower),
        },
    )
