from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
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


BIN_SH = "/bin/sh"
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
INTERESTING_APIS = (
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "fscanf", "read", "recv", "memcpy", "printf", "fprintf", "syslog",
    "system", "popen", "execve", "execv", "execvp", "execvpe", "execl",
    "execlp", "execle", "posix_spawn", "posix_spawnp", "wordexp",
    "mprotect", "VirtualProtect", "WinExec",
    "CreateProcess", "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "dlopen", "dlsym",
    "prctl", "seccomp", "seccomp_init", "seccomp_rule_add",
    "malloc", "calloc", "realloc", "free", "operator new", "operator delete",
)
FORTIFY_APIS = frozenset({
    "__memcpy_chk", "__memmove_chk", "__memset_chk", "__strcpy_chk",
    "__stpcpy_chk", "__strncpy_chk", "__strcat_chk", "__strncat_chk",
    "__sprintf_chk", "__vsprintf_chk", "__snprintf_chk", "__vsnprintf_chk",
    "__printf_chk", "__fprintf_chk", "__dprintf_chk", "__vprintf_chk",
    "__vfprintf_chk", "__fgets_chk", "__gets_chk", "__read_chk",
    "__recv_chk", "__recvfrom_chk",
})
FORTIFIABLE_APIS = frozenset({
    "memcpy", "memmove", "memset", "strcpy", "stpcpy", "strncpy",
    "strcat", "strncat", "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "printf", "fprintf", "dprintf", "vprintf", "vfprintf", "fgets",
    "gets", "read", "recv", "recvfrom",
})


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


def _elf_dynamic_segment(data: bytes, bits: int, endian_char: str, off: int) -> Tuple[bool, bool]:
    wide = bits == 64
    fmt = "Q" if wide else "I"
    dyn_off = _u(data, off + (8 if wide else 4), fmt, endian_char)
    dyn_size = _u(data, off + (32 if wide else 16), fmt, endian_char)
    return _elf_dynamic_flags(data, bits, endian_char, dyn_off, dyn_size)


def _elf_program_headers(data: bytes, bits: int, endian_char: str, phoff: int, phentsize: int, phnum: int) -> Tuple[Optional[bool], bool, bool, bool, bool, bool]:
    nx: Optional[bool] = None
    relro = False
    bind_now = False
    dynamic = False
    has_interp = False
    is_pie_flag = False
    wide = bits == 64
    min_phentsize = 56 if wide else 32
    flags_at = 4 if wide else 24
    for index in range(min(phnum, 4096)):
        off = phoff + index * phentsize
        if phentsize < min_phentsize or off + phentsize > len(data):
            break
        p_type = _u(data, off, "I", endian_char)
        p_flags = _u(data, off + flags_at, "I", endian_char)
        if p_type == 0x6474E551:
            nx = not bool(p_flags & 1)
        elif p_type == 0x6474E552:
            relro = True
        elif p_type == 2:
            dynamic = True
            dyn_bind_now, pie_flag = _elf_dynamic_segment(data, bits, endian_char, off)
            bind_now |= dyn_bind_now
            is_pie_flag |= pie_flag
        elif p_type == 3:
            has_interp = True
    return nx, relro, bind_now, dynamic, has_interp, is_pie_flag


def _dynamic_bind_now(tag: int, value: int) -> bool:
    if tag == 24:
        return True
    if tag == 30:
        return bool(value & 8)
    return tag == 0x6FFFFFFB and bool(value & 1)


def _elf_dynamic_flags(data: bytes, bits: int, endian_char: str, dyn_off: int, dyn_size: int) -> Tuple[bool, bool]:
    bind_now = False
    is_pie_flag = False
    stride = 16 if bits == 64 else 8
    if dyn_off <= 0 or dyn_size <= 0:
        return bind_now, is_pie_flag
    fmt = "Q" if bits == 64 else "I"
    for dyn_at in range(dyn_off, min(len(data), dyn_off + dyn_size), stride):
        if dyn_at + stride > len(data):
            break
        tag = _u(data, dyn_at, fmt, endian_char)
        value = _u(data, dyn_at + stride // 2, fmt, endian_char)
        if tag == 0:
            break
        bind_now = bind_now or _dynamic_bind_now(tag, value)
        is_pie_flag = is_pie_flag or (tag == 0x6FFFFFFB and bool(value & 0x08000000))
    return bind_now, is_pie_flag


def _elf_header_fields(data: bytes, bits: int, endian_char: str) -> Tuple[int, ...]:
    if bits == 64:
        if len(data) < 0x40:
            raise ParseError("truncated ELF64 header")
        wide, offsets = "Q", (24, 32, 40)
        small = (54, 56, 58, 60, 62)
    else:
        wide, offsets = "I", (24, 28, 32)
        small = (42, 44, 46, 48, 50)
    return tuple(_u(data, at, wide, endian_char) for at in offsets) + tuple(_u(data, at, "H", endian_char) for at in small)


def _elf_stack_canary(data: bytes, symbols: Sequence[str], has_symtab: bool) -> Optional[bool]:
    if any(name in {"__stack_chk_fail", "__stack_chk_guard"} or name.startswith("__stack_chk_fail@") for name in symbols):
        return True
    if has_symtab:
        return False
    if b"__stack_chk_fail" in data:
        return True
    # Stripped binary without the canary symbol: presence is unknown, not absent.
    return None


def _elf_fortify(fortified_imports: Sequence[str], undefined_symbols: Sequence[str], has_symtab: bool) -> Optional[bool]:
    if fortified_imports:
        return True
    if has_symtab and any(name in FORTIFIABLE_APIS for name in undefined_symbols):
        return False
    return None


def _split_imports(undefined_symbols: Sequence[str], values: Sequence[str]) -> Tuple[List[str], List[str], List[str]]:
    parsed_imports = sorted({name for name in undefined_symbols if name in INTERESTING_APIS}, key=str.lower)
    string_hints = sorted(set(_interesting_names(values)) - set(parsed_imports), key=str.lower)
    imports = sorted(set(parsed_imports) | set(string_hints), key=str.lower)
    return parsed_imports, string_hints, imports


def _elf_relro_state(relro: bool, bind_now: bool) -> str:
    if relro and bind_now:
        return "full"
    return "partial" if relro else "none"


def _elf_role(e_type: int, pie: bool) -> str:
    if pie:
        return "pie"
    return "shared_object" if e_type == 3 else "executable"


def parse_elf(data: bytes) -> BinaryInfo:
    if len(data) < 0x34:
        raise ParseError("truncated ELF header")
    bits = {1: 32, 2: 64}.get(data[4])
    if bits is None:
        raise ParseError("invalid ELF class")
    endian_char = {1: "<", 2: ">"}.get(data[5])
    if endian_char is None:
        raise ParseError("invalid ELF byte order")
    endian = "little" if endian_char == "<" else "big"
    machine = _u(data, 18, "H", endian_char)
    e_type = _u(data, 16, "H", endian_char)
    entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx = _elf_header_fields(data, bits, endian_char)

    nx, relro, bind_now, dynamic, has_interp, is_pie_flag = _elf_program_headers(data, bits, endian_char, phoff, phentsize, phnum)
    sections = _elf_sections(data, bits, endian_char, shoff, shentsize, shnum, shstrndx)
    symbols, symbol_addresses, undefined_symbols, has_symtab = _elf_symbols(data, bits, endian_char, sections)
    values = extract_strings(data)
    parsed_imports, string_hints, imports = _split_imports(undefined_symbols, values)
    fortified_imports = sorted({name for name in undefined_symbols if name in FORTIFY_APIS}, key=str.lower)
    stack_canary = _elf_stack_canary(data, symbols, has_symtab)
    fortify = _elf_fortify(fortified_imports, undefined_symbols, has_symtab)
    pie = e_type == 3 and (has_interp or is_pie_flag)
    relro_state = _elf_relro_state(relro, bind_now)
    architecture = ELF_MACHINES.get(machine, "machine-%d" % machine)
    plt_addresses = _elf_plt_addresses(data, bits, endian_char, sections, architecture)
    return BinaryInfo(
        format="ELF", bits=bits, endian=endian,
        architecture=architecture,
        entrypoint=entry, imports=imports, symbols=symbols, strings=values,
        mitigations={"nx": nx, "pie": pie, "stack_canary": stack_canary, "relro": relro, "aslr": e_type == 3, "fortify": fortify},
        metadata={
            "elf_type": e_type, "elf_role": _elf_role(e_type, pie),
            "dynamic": dynamic, "relro": relro_state, "sections": sorted({section.name for section in sections}),
            "parsed_imports": parsed_imports, "fortified_imports": fortified_imports, "string_import_hints": string_hints,
            "symbol_addresses": symbol_addresses,
            "plt_addresses": plt_addresses,
            "string_addresses": _elf_string_addresses(data, sections),
            **_elf_exploit_metadata(data, bits, sections, architecture),
        },
    )


def _elf_raw_section(data: bytes, bits: int, endian: str, off: int) -> Tuple[int, ...]:
    if bits == 64:
        return (
            _u(data, off, "I", endian), _u(data, off + 4, "I", endian), _u(data, off + 8, "Q", endian),
            _u(data, off + 16, "Q", endian), _u(data, off + 24, "Q", endian),
            _u(data, off + 32, "Q", endian), _u(data, off + 40, "I", endian), _u(data, off + 56, "Q", endian),
        )
    return (
        _u(data, off, "I", endian), _u(data, off + 4, "I", endian), _u(data, off + 8, "I", endian),
        _u(data, off + 12, "I", endian), _u(data, off + 16, "I", endian),
        _u(data, off + 20, "I", endian), _u(data, off + 24, "I", endian), _u(data, off + 36, "I", endian),
    )


def _elf_section_names(data: bytes, raw: Sequence[Tuple[int, ...]], names_index: int) -> bytes:
    if 0 <= names_index < len(raw) and raw[names_index][1] != 8:
        name_off, name_size = raw[names_index][4], raw[names_index][5]
        return data[name_off:min(len(data), name_off + name_size)]
    return b""


def _elf_sections(data: bytes, bits: int, endian: str, shoff: int, entsize: int, count: int, names_index: int) -> List[_ElfSection]:
    raw = []
    minimum = 64 if bits == 64 else 40
    if shoff == 0 or count == 0 or entsize < minimum or count > 65535:
        return []
    for index in range(count):
        off = shoff + index * entsize
        if off + minimum > len(data):
            break
        raw.append(_elf_raw_section(data, bits, endian, off))
    names = _elf_section_names(data, raw, names_index)
    result: List[_ElfSection] = []
    for index, (name_at, kind, flags, va, file_off, size, link, item_size) in enumerate(raw):
        section_name = _c_string(names, name_at) if name_at < len(names) else "section_%d" % index
        if not section_name and index > 0:
            section_name = "section_%d" % index
        result.append(_ElfSection(section_name, kind, flags, va, file_off, size, link, item_size))
    return result


def _elf_symbol_table(data: bytes, bits: int, endian: str, section: _ElfSection, strings: bytes) -> List[Tuple[str, int, int]]:
    wide = bits == 64
    default_size = 24 if wide else 16
    stride = section.item_size or default_size
    if stride < default_size:
        return []
    value_at = 8 if wide else 4
    index_at = 6 if wide else 14
    value_fmt = "Q" if wide else "I"
    entries: List[Tuple[str, int, int]] = []
    for at in range(section.offset, min(len(data), section.offset + section.size), stride):
        if at + default_size > len(data):
            break
        name = _c_string(strings, _u(data, at, "I", endian))
        if name:
            entries.append((name, _u(data, at + value_at, value_fmt, endian), _u(data, at + index_at, "H", endian)))
    return entries


def _merge_symbol_entries(entries: Sequence[Tuple[str, int, int]], result: Set[str], addresses: Dict[str, int], undefined: Set[str]) -> None:
    for name, value, section_index in entries:
        result.add(name)
        if value and section_index != 0 and (name not in addresses or value < addresses[name]):
            addresses[name] = value
        if section_index == 0:
            undefined.add(name)


def _elf_symbols(data: bytes, bits: int, endian: str, sections: Sequence[_ElfSection]) -> Tuple[List[str], Dict[str, int], List[str], bool]:
    result: Set[str] = set()
    addresses: Dict[str, int] = {}
    undefined: Set[str] = set()
    has_symtab = False
    for section in sections:
        if section.kind not in {2, 11}:
            continue
        has_symtab = True
        strtab = sections[section.link] if section.link < len(sections) else None
        if strtab is None or strtab.kind == 8:
            continue
        strings = data[strtab.offset:min(len(data), strtab.offset + strtab.size)]
        _merge_symbol_entries(_elf_symbol_table(data, bits, endian, section, strings), result, addresses, undefined)
    return (
        sorted(result, key=lambda value: (value.lower(), value)),
        {name: addresses[name] for name in sorted(addresses, key=str.lower)},
        sorted(undefined, key=str.lower),
        has_symtab,
    )


def _elf_plt_tables(sections: Sequence[_ElfSection]) -> Optional[Tuple[_ElfSection, _ElfSection, _ElfSection]]:
    by_name = {section.name: section for section in sections}
    rel_section = by_name.get(".rela.plt") or by_name.get(".rel.plt")
    if rel_section is None or rel_section.kind not in {4, 9} or rel_section.link >= len(sections):
        return None
    dynsym = sections[rel_section.link]
    if dynsym.kind not in {2, 11} or dynsym.link >= len(sections):
        return None
    dynstr = sections[dynsym.link]
    if dynstr.kind == 8:
        return None
    return rel_section, dynsym, dynstr


def _elf_plt_strides(bits: int, rel_section: _ElfSection, dynsym: _ElfSection) -> Optional[Tuple[int, int]]:
    is_rela = rel_section.kind == 4
    if bits == 64:
        default_rel, min_rel, default_sym = (24 if is_rela else 16), 16, 24
    else:
        default_rel, min_rel, default_sym = (12 if is_rela else 8), 8, 16
    rel_stride = rel_section.item_size or default_rel
    sym_stride = dynsym.item_size or default_sym
    if rel_stride < min_rel or sym_stride < default_sym:
        return None
    return rel_stride, sym_stride


def _elf_plt_base(sections: Sequence[_ElfSection]) -> Optional[Tuple[_ElfSection, int]]:
    by_name = {section.name: section for section in sections}
    plt_sec = by_name.get(".plt.sec")
    plt_base = plt_sec or by_name.get(".plt")
    if plt_base is None or plt_base.va == 0:
        return None
    return plt_base, (0 if plt_sec is not None else 1)


def _elf_plt_name(data: bytes, endian: str, dynsym: _ElfSection, strings: bytes, sym_at: int) -> str:
    if sym_at + 4 > min(len(data), dynsym.offset + dynsym.size):
        return ""
    return _c_string(strings, _u(data, sym_at, "I", endian))


def _elf_plt_addresses(data: bytes, bits: int, endian: str, sections: Sequence[_ElfSection], architecture: str) -> Dict[str, str]:
    if architecture not in {"x86", "x86_64", "arm", "aarch64"}:
        return {}
    tables = _elf_plt_tables(sections)
    if tables is None:
        return {}
    rel_section, dynsym, dynstr = tables
    plt = _elf_plt_base(sections)
    if plt is None:
        return {}
    plt_base, first_index = plt
    default_stride = {"arm": 12, "aarch64": 16}.get(architecture, 16)
    plt_stride = plt_base.item_size or default_stride
    strides = _elf_plt_strides(bits, rel_section, dynsym)
    if strides is None:
        return {}
    rel_stride, sym_stride = strides
    strings = data[dynstr.offset:min(len(data), dynstr.offset + dynstr.size)]
    count = min(rel_section.size // rel_stride, 65535)
    info_fmt, info_at, sym_shift = ("Q", 8, 32) if bits == 64 else ("I", 4, 8)
    result: Dict[str, str] = {}
    for index in range(count):
        rel_at = rel_section.offset + index * rel_stride
        if rel_at + rel_stride > len(data):
            break
        r_info = _u(data, rel_at + info_at, info_fmt, endian)
        name = _elf_plt_name(data, endian, dynsym, strings, dynsym.offset + (r_info >> sym_shift) * sym_stride)
        if not name:
            continue
        stub_va = plt_base.va + (index + first_index) * plt_stride
        if plt_base.size and stub_va >= plt_base.va + plt_base.size:
            break
        result["0x%x" % stub_va] = name
    return result


def _collect_matches(blob: bytes, needle: bytes, base: int, found: List[int], limit: int) -> None:
    start = 0
    while len(found) < limit:
        at = blob.find(needle, start)
        if at < 0:
            break
        found.append(base + at)
        start = at + 1


def _gadget_patterns(bits: int, architecture: str) -> Dict[str, bytes]:
    if architecture in {"x86", "x86_64"}:
        patterns = {"ret": b"\xc3", "leave_ret": b"\xc9\xc3", "jmp_rsp": b"\xff\xe4", "syscall_ret": b"\x0f\x05\xc3"}
        if bits == 64:
            patterns.update({"pop_rdi_ret": b"\x5f\xc3", "pop_rsi_ret": b"\x5e\xc3", "pop_rdx_ret": b"\x5a\xc3"})
        return patterns
    if architecture == "aarch64":
        # Raw byte sequences; validate against instruction boundaries in a disassembler.
        return {"ret": b"\xc0\x03\x5f\xd6", "br_x0": b"\x00\x00\x1f\xd6", "blr_x1": b"\x20\x00\x3f\xd6"}
    if architecture == "arm":
        return {"bx_lr": b"\x1e\xff\x2f\xe1"}
    return {}


def _scan_section(data: bytes, section: _ElfSection, patterns: Dict[str, bytes], gadgets: Dict[str, List[int]], useful: Dict[str, List[int]]) -> None:
    blob = data[section.offset:min(len(data), section.offset + section.size)]
    if section.flags & 4:
        for label, needle in patterns.items():
            _collect_matches(blob, needle, section.va, gadgets[label], 8)
    if section.flags & 2 or section.va:
        _collect_matches(blob, BIN_SH.encode("ascii") + b"\0", section.va, useful[BIN_SH], 4)


def _elf_string_addresses(data: bytes, sections: Sequence[_ElfSection], limit: int = 200000) -> Dict[str, List[int]]:
    """Map each printable string to its virtual addresses, for address-based lookups.

    Uses a 2-character minimum so short format strings like "%d" are included;
    lookups are by exact address, so extra entries cannot cause false matches.
    Non-executable sections are scanned first so a large .text cannot starve
    .rodata of the global entry budget (format strings live there).
    """
    pattern = re.compile(rb"[\x20-\x7e]{2,}")
    result: Dict[str, List[int]] = {}
    total = 0
    ordered = sorted(sections, key=lambda section: 1 if section.flags & 4 else 0)
    for section in ordered:
        if section.kind == 8 or not section.va:
            continue
        blob = data[section.offset:min(len(data), section.offset + section.size)]
        for match in pattern.finditer(blob):
            if total >= limit:
                break
            result.setdefault(match.group().decode("ascii", "replace"), []).append(section.va + match.start())
            total += 1
        if total >= limit:
            break
    return {key: sorted(set(values)) for key, values in sorted(result.items())}


def _elf_exploit_metadata(data: bytes, bits: int, sections: Sequence[_ElfSection], architecture: str) -> Dict[str, object]:
    """Extract address-bearing facts from sections without executing the target."""
    patterns = _gadget_patterns(bits, architecture)
    gadgets: Dict[str, List[int]] = {name: [] for name in patterns}
    useful: Dict[str, List[int]] = {BIN_SH: []}
    rwx: List[str] = []
    for section in sections:
        if section.flags & 1 and section.flags & 4:
            rwx.append(section.name)
        if section.kind != 8:
            _scan_section(data, section, patterns, gadgets, useful)
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


def _pe_thunk_names(data: bytes, bits: int, thunk_off: int, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int) -> Set[str]:
    names: Set[str] = set()
    stride = 8 if bits == 64 else 4
    ordinal_mask = 1 << (bits - 1)
    fmt = "Q" if bits == 64 else "I"
    for item in range(4096):
        at = thunk_off + item * stride
        if at + stride > len(data):
            break
        value = _u(data, at, fmt)
        if value == 0:
            break
        if value & ordinal_mask:
            continue
        name_off = _pe_rva_to_offset(data, sections, first_section_va, value & 0x7FFFFFFF)
        name = _c_string(data, name_off + 2) if name_off is not None else ""
        if name:
            names.add(name)
    return names


def _pe_imports(data: bytes, bits: int, import_rva: int, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int) -> Set[str]:
    imports: Set[str] = set()
    descriptor = _pe_rva_to_offset(data, sections, first_section_va, import_rva) if import_rva else None
    for _ in range(4096):
        if descriptor is None or descriptor + 20 > len(data):
            break
        original, _, _, name_rva, thunk = struct.unpack_from("<IIIII", data, descriptor)
        if not any((original, name_rva, thunk)):
            break
        descriptor += 20
        ilt_rva = original or thunk
        thunk_off = _pe_rva_to_offset(data, sections, first_section_va, ilt_rva) if ilt_rva else None
        if thunk_off is not None:
            imports |= _pe_thunk_names(data, bits, thunk_off, sections, first_section_va)
    return imports


def _pe_export_tables(data: bytes, export_rva: int, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int) -> Optional[Tuple[int, int, int, int, int]]:
    exp_off = _pe_rva_to_offset(data, sections, first_section_va, export_rva) if export_rva else None
    if exp_off is None or exp_off + 40 > len(data):
        return None
    num_funcs = _u(data, exp_off + 20, "I")
    num_names = _u(data, exp_off + 24, "I")
    funcs_off, names_off, ords_off = (
        _pe_rva_to_offset(data, sections, first_section_va, _u(data, exp_off + at, "I")) for at in (28, 32, 36)
    )
    if funcs_off is None or names_off is None or ords_off is None:
        return None
    return num_funcs, num_names, funcs_off, names_off, ords_off


def _pe_export_rva(data: bytes, funcs_off: int, ord_idx: int, num_funcs: int, export_rva: int, export_size: int) -> Optional[int]:
    if ord_idx >= num_funcs or funcs_off + ord_idx * 4 + 4 > len(data):
        return None
    func_rva = _u(data, funcs_off + ord_idx * 4, "I")
    is_forwarder = export_size > 0 and export_rva <= func_rva < export_rva + export_size
    return None if (not func_rva or is_forwarder) else func_rva


def _pe_exports(data: bytes, image_base: int, export_rva: int, export_size: int, sections: Sequence[Tuple[str, int, int, int, int, int]], first_section_va: int) -> Tuple[Set[str], Dict[str, int]]:
    exported: Set[str] = set()
    addresses: Dict[str, int] = {}
    tables = _pe_export_tables(data, export_rva, sections, first_section_va)
    if tables is None:
        return exported, addresses
    num_funcs, num_names, funcs_off, names_off, ords_off = tables
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
        func_rva = _pe_export_rva(data, funcs_off, ord_idx, num_funcs, export_rva, export_size)
        if func_rva is not None:
            addresses[name] = image_base + func_rva
    return exported, addresses


def _pe_optional_header(data: bytes, opt: int) -> Tuple[int, int, int]:
    magic = _u(data, opt, "H")
    if magic == 0x20B:
        return 64, _u(data, opt + 24, "Q"), 112
    if magic == 0x10B:
        return 32, _u(data, opt + 28, "I"), 96
    raise ParseError("unsupported PE optional header")


def _pe_sections(data: bytes, section_at: int, sections_count: int) -> List[Tuple[str, int, int, int, int, int]]:
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
    return sections


def _pe_flag(dll_chars: Optional[int], mask: int) -> Optional[bool]:
    return None if dll_chars is None else bool(dll_chars & mask)


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
    bits, image_base, data_dir_off = _pe_optional_header(data, opt)
    entry_rva = _u(data, opt + 16, "I")
    dll_chars = _u(data, opt + 70, "H") if optional_size >= 72 else None
    sections = _pe_sections(data, opt + optional_size, sections_count)

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
    writable_executable = any((flags & 0x80000000) and (flags & 0x20000000) for *_, flags in sections)
    return BinaryInfo(
        format="PE", bits=bits, endian="little", architecture=PE_MACHINES.get(machine, "machine-%d" % machine),
        entrypoint=image_base + entry_rva if entry_rva else None, image_base=image_base,
        imports=sorted(imports, key=str.lower),
        symbols=sorted(exported_symbols, key=lambda value: (value.lower(), value)),
        strings=values,
        mitigations={"nx": _pe_flag(dll_chars, 0x0100), "aslr": _pe_flag(dll_chars, 0x0040), "cfg": _pe_flag(dll_chars, 0x4000), "stack_canary": None, "writable_executable": writable_executable},
        metadata={
            "dll": bool(characteristics & 0x2000), "sections": sorted(section[0] for section in sections),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "symbol_addresses": {name: symbol_addresses[name] for name in sorted(symbol_addresses, key=str.lower)},
            "rwx_sections": sorted(section[0] for section in sections if (section[5] & 0x80000000) and (section[5] & 0x20000000)),
        },
    )


MACH_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "aarch64"}


def _macho_record_symbol(name: str, n_type: int, n_sect: int, n_value: int, undefined: Set[str], addresses: Dict[str, int]) -> None:
    if (n_type & 0x0E) == 0x0 and (n_type & 0x01) and n_sect == 0:
        undefined.add(name)
    elif (n_type & 0x0E) == 0x0E and n_value and (name not in addresses or n_value < addresses[name]):
        addresses[name] = n_value


def _macho_symtab(data: bytes, bits: int, endian: str, at: int) -> Tuple[Set[str], Set[str], Dict[str, int], List[str]]:
    symbols: Set[str] = set()
    undefined: Set[str] = set()
    undefined_ordered: List[str] = []
    addresses: Dict[str, int] = {}
    symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, at + 8)
    str_end = min(len(data), stroff + strsize)
    nlist_size = 16 if bits == 64 else 12
    if stroff >= len(data) or symoff >= len(data):
        return symbols, undefined, addresses, undefined_ordered
    value_fmt = "Q" if bits == 64 else "I"
    for index in range(min(nsyms, 65535)):
        sym_at = symoff + index * nlist_size
        if sym_at + nlist_size > len(data):
            break
        n_strx = _u(data, sym_at, "I", endian)
        n_type = data[sym_at + 4]
        n_sect = data[sym_at + 5]
        n_value = _u(data, sym_at + 8, value_fmt, endian)
        if n_type & 0xE0 or stroff + n_strx >= str_end:
            continue
        raw_name = _c_string(data, stroff + n_strx)
        if not raw_name:
            continue
        clean_name = raw_name[1:] if raw_name.startswith("_") else raw_name
        symbols.add(clean_name)
        if (n_type & 0x0E) == 0x0 and (n_type & 0x01) and n_sect == 0 and clean_name not in undefined:
            undefined_ordered.append(clean_name)
        _macho_record_symbol(clean_name, n_type, n_sect, n_value, undefined, addresses)
    return symbols, undefined, addresses, undefined_ordered


@dataclass
class _MachoScan:
    entry_offset: Optional[int] = None
    text_vmaddr: Optional[int] = None
    dylibs: List[str] = field(default_factory=list)
    executable_stack: bool = False
    rwx_sections: Set[str] = field(default_factory=set)
    symbols: Set[str] = field(default_factory=set)
    undefined_symbols: Set[str] = field(default_factory=set)
    undefined_ordered: List[str] = field(default_factory=list)
    symbol_addresses: Dict[str, int] = field(default_factory=dict)
    stub_sections: List[Tuple[int, int, int]] = field(default_factory=list)  # (va, size, stub_size)
    has_symtab: bool = False


S_SYMBOL_STUBS = 0x08


def _macho_segment_sections(data: bytes, endian: str, at: int, wide: bool, scan: _MachoScan) -> None:
    nsects_at = at + (64 if wide else 48)
    sect_at = at + (72 if wide else 56)
    sect_size = 80 if wide else 68
    if nsects_at + 4 > len(data):
        return
    nsects = _u(data, nsects_at, "I", endian)
    addr_fmt = "Q" if wide else "I"
    for index in range(min(nsects, 255)):
        base = sect_at + index * sect_size
        if base + sect_size > len(data):
            break
        sectname = data[base:base + 16].split(b"\0", 1)[0].decode("ascii", "replace")
        addr = _u(data, base + 32, addr_fmt, endian)
        size = _u(data, base + (40 if wide else 36), addr_fmt, endian)
        flags = _u(data, base + (64 if wide else 56), "I", endian)
        reserved2 = _u(data, base + (72 if wide else 60), "I", endian)
        if sectname == "__stubs" and (flags & 0xFF) == S_SYMBOL_STUBS and reserved2 > 0:
            scan.stub_sections.append((addr, size, reserved2))


def _macho_segment(data: bytes, endian: str, at: int, command: int, scan: _MachoScan) -> None:
    wide = command == 0x19
    segname = data[at + 8:at + 24].split(b"\0", 1)[0].decode("ascii", "replace")
    vmaddr = _u(data, at + 24, "Q" if wide else "I", endian)
    initprot = _u(data, at + (60 if wide else 44), "I", endian)
    if segname == "__TEXT":
        scan.text_vmaddr = vmaddr
    if segname == "__UNIXSTACK" and (initprot & 4):
        scan.executable_stack = True
    if (initprot & 0x6) == 0x6:
        scan.rwx_sections.add(segname or "segment")
    _macho_segment_sections(data, endian, at, wide, scan)


def _macho_command(data: bytes, bits: int, endian: str, at: int, command: int, size: int, scan: _MachoScan) -> None:
    if command == 0x80000028 and size >= 24:
        scan.entry_offset = _u(data, at + 8, "Q", endian)
    elif command in {0xC, 0x18, 0x1F, 0x8000001F, 0x80000018} and size >= 24:
        name = _c_string(data, at + _u(data, at + 8, "I", endian))
        if name:
            scan.dylibs.append(name)
    elif command in {0x1, 0x19} and size >= (72 if command == 0x19 else 56):
        _macho_segment(data, endian, at, command, scan)
    elif command == 0x2 and size >= 24:
        scan.has_symtab = True
        syms, undef, addrs, undef_ordered = _macho_symtab(data, bits, endian, at)
        scan.symbols.update(syms)
        scan.undefined_symbols.update(undef)
        scan.undefined_ordered.extend(undef_ordered)
        scan.symbol_addresses.update(addrs)


def _macho_scan_commands(data: bytes, bits: int, endian: str, at: int, commands: int) -> _MachoScan:
    scan = _MachoScan()
    for _ in range(min(commands, 65535)):
        if at + 8 > len(data):
            break
        command, size = _u(data, at, "I", endian), _u(data, at + 4, "I", endian)
        if size < 8 or at + size > len(data):
            break
        _macho_command(data, bits, endian, at, command, size, scan)
        at += size
    return scan


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
    scan = _macho_scan_commands(data, bits, endian, header_size, commands)
    if scan.text_vmaddr is not None and scan.entry_offset is not None:
        entry: Optional[int] = scan.text_vmaddr + scan.entry_offset
    else:
        entry = scan.entry_offset
    values = extract_strings(data)
    parsed_imports, string_hints, imports = _split_imports(sorted(scan.undefined_symbols), values)
    pie = bool(flags & 0x200000)
    if any(name in {"__stack_chk_fail", "__stack_chk_guard"} for name in scan.symbols):
        stack_canary: Optional[bool] = True
    elif scan.has_symtab:
        stack_canary = False
    elif b"___stack_chk_fail" in data:
        stack_canary = True
    else:
        # Stripped binary without the canary symbol: presence is unknown, not absent.
        stack_canary = None
    rwx_sections = set(scan.rwx_sections)
    if scan.executable_stack:
        rwx_sections.add("__UNIXSTACK")
    symbol_addresses = scan.symbol_addresses
    # Heuristic stub map: the i-th __stubs entry binds the i-th undefined symbol
    # (dyld orders them correspondingly); used to resolve Ghidra auto-labels.
    plt_addresses: Dict[str, str] = {}
    for stub_va, stub_total, stub_size in scan.stub_sections:
        for index, name in enumerate(scan.undefined_ordered):
            stub_addr = stub_va + index * stub_size
            if stub_total and stub_addr >= stub_va + stub_total:
                break
            plt_addresses["0x%x" % stub_addr] = name
    return BinaryInfo(
        format="Mach-O", bits=bits, endian="big" if endian == ">" else "little",
        architecture=MACH_CPU.get(cpu, "cpu-%d" % cpu), entrypoint=entry,
        imports=imports,
        symbols=sorted(scan.symbols, key=lambda value: (value.lower(), value)),
        strings=values,
        mitigations={"nx": not scan.executable_stack, "pie": pie, "aslr": pie, "stack_canary": stack_canary},
        metadata={
            "file_type": file_type, "dylibs": sorted(set(scan.dylibs), key=str.lower),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "symbol_addresses": {name: symbol_addresses[name] for name in sorted(symbol_addresses, key=str.lower)},
            "rwx_sections": sorted(rwx_sections, key=str.lower),
            "plt_addresses": {key: plt_addresses[key] for key in sorted(plt_addresses, key=lambda value: int(value, 16))},
        },
    )
