from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import BinaryInfo


class ParseError(ValueError):
    pass


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
INTERESTING_APIS = (
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "fscanf", "read", "recv", "memcpy", "printf", "fprintf", "syslog",
    "system", "popen", "execve", "mprotect", "VirtualProtect", "WinExec",
    "CreateProcess", "LoadLibrary", "GetProcAddress",
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
            if tail == api or tail.startswith(api + "@") or tail.startswith("_" + api):
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
    raise ParseError("unsupported file format; expected ELF, PE, or Mach-O")


ELF_MACHINES = {3: "x86", 8: "mips", 20: "ppc", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}


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

    nx: Optional[bool] = None
    relro = False
    bind_now = False
    dynamic = False
    has_interp = False
    for index in range(min(phnum, 4096)):
        off = phoff + index * phentsize
        if off + phentsize > len(data) or phentsize == 0:
            break
        p_type = _u(data, off, "I", endian_char)
        if bits == 64:
            p_flags = _u(data, off + 4, "I", endian_char)
        else:
            p_flags = _u(data, off + 24, "I", endian_char)
        if p_type == 0x6474E551:
            nx = not bool(p_flags & 1)
        elif p_type == 0x6474E552:
            relro = True
        elif p_type == 2:
            dynamic = True
            dyn_off = _u(data, off + (8 if bits == 64 else 4), "Q" if bits == 64 else "I", endian_char)
            dyn_size = _u(data, off + (32 if bits == 64 else 16), "Q" if bits == 64 else "I", endian_char)
            stride = 16 if bits == 64 else 8
            for dyn_at in range(dyn_off, min(len(data), dyn_off + dyn_size), stride):
                if dyn_at + stride > len(data):
                    break
                tag = _u(data, dyn_at, "Q" if bits == 64 else "I", endian_char)
                value = _u(data, dyn_at + stride // 2, "Q" if bits == 64 else "I", endian_char)
                if tag == 0:
                    break
                bind_now = bind_now or tag == 24 or (tag == 30 and bool(value & 8)) or (tag == 0x6FFFFFFB and bool(value & 1))
        elif p_type == 3:
            has_interp = True

    sections = _elf_sections(data, bits, endian_char, shoff, shentsize, shnum, shstrndx)
    symbols, symbol_addresses, undefined_symbols = _elf_symbols(data, bits, endian_char, sections)
    values = extract_strings(data)
    parsed_imports = sorted({name for name in undefined_symbols if name in INTERESTING_APIS}, key=str.lower)
    string_hints = sorted(set(_interesting_names(values)) - set(parsed_imports), key=str.lower)
    imports = sorted(set(parsed_imports) | set(string_hints), key=str.lower)
    stack_canary = any(name in {"__stack_chk_fail", "__stack_chk_guard"} for name in symbols) or b"__stack_chk_fail" in data
    pie = e_type == 3 and has_interp
    relro_state = "full" if relro and bind_now else ("partial" if relro else "none")
    return BinaryInfo(
        format="ELF", bits=bits, endian=endian,
        architecture=ELF_MACHINES.get(machine, "machine-%d" % machine),
        entrypoint=entry, imports=imports, symbols=symbols, strings=values,
        mitigations={"nx": nx, "pie": pie, "stack_canary": stack_canary, "relro": relro, "aslr": e_type == 3},
        metadata={
            "elf_type": e_type, "elf_role": "pie" if pie else ("shared_object" if e_type == 3 else "executable"),
            "dynamic": dynamic, "relro": relro_state, "sections": sorted(sections),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "symbol_addresses": symbol_addresses,
            **_elf_exploit_metadata(data, bits, endian_char, sections, ELF_MACHINES.get(machine, "")),
        },
    )


def _elf_sections(data: bytes, bits: int, endian: str, shoff: int, entsize: int, count: int, names_index: int) -> Dict[str, Tuple[int, int, int, int]]:
    raw = []
    minimum = 64 if bits == 64 else 40
    if entsize < minimum or count > 65535:
        return {}
    for index in range(count):
        off = shoff + index * entsize
        if off + minimum > len(data):
            return {}
        if bits == 64:
            name, kind = _u(data, off, "I", endian), _u(data, off + 4, "I", endian)
            file_off, size, link, item_size = _u(data, off + 24, "Q", endian), _u(data, off + 32, "Q", endian), _u(data, off + 40, "I", endian), _u(data, off + 56, "Q", endian)
        else:
            name, kind = _u(data, off, "I", endian), _u(data, off + 4, "I", endian)
            file_off, size, link, item_size = _u(data, off + 16, "I", endian), _u(data, off + 20, "I", endian), _u(data, off + 24, "I", endian), _u(data, off + 36, "I", endian)
        raw.append((name, kind, file_off, size, link, item_size))
    if names_index >= len(raw):
        return {}
    _, _, name_off, name_size, _, _ = raw[names_index]
    names = data[name_off:name_off + name_size]
    result = {}
    for index, (name_at, kind, file_off, size, link, item_size) in enumerate(raw):
        section_name = _c_string(names, name_at) if name_at < len(names) else "section_%d" % index
        result[section_name] = (kind, file_off, size, link << 32 | item_size)
    return result


def _elf_symbols(data: bytes, bits: int, endian: str, sections: Dict[str, Tuple[int, int, int, int]]) -> Tuple[List[str], Dict[str, int], List[str]]:
    result = set()
    addresses: Dict[str, int] = {}
    undefined = set()
    section_list = list(sections.items())
    for _, (kind, offset, size, packed) in section_list:
        if kind not in {2, 11}:
            continue
        link, item_size = packed >> 32, packed & 0xFFFFFFFF
        if link >= len(section_list):
            continue
        _, (_, str_off, str_size, _) = section_list[link]
        strings = data[str_off:str_off + str_size]
        default_size = 24 if bits == 64 else 16
        stride = item_size or default_size
        if stride < default_size:
            continue
        for at in range(offset, min(len(data), offset + size), stride):
            if at + default_size > len(data):
                break
            name_at = _u(data, at, "I", endian)
            name = _c_string(strings, name_at)
            if name:
                result.add(name)
                value = _u(data, at + (8 if bits == 64 else 4), "Q" if bits == 64 else "I", endian)
                section_index = _u(data, at + (6 if bits == 64 else 14), "H", endian)
                if value and (name not in addresses or value < addresses[name]):
                    addresses[name] = value
                if section_index == 0:
                    undefined.add(name)
    return (
        sorted(result, key=lambda value: (value.lower(), value)),
        {name: addresses[name] for name in sorted(addresses, key=str.lower)},
        sorted(undefined, key=str.lower),
    )


def _elf_exploit_metadata(data: bytes, bits: int, endian: str, sections: Dict[str, Tuple[int, int, int, int]], architecture: str) -> Dict[str, object]:
    """Extract address-bearing facts from sections without executing the target."""
    result: Dict[str, object] = {"rwx_sections": [], "gadgets": {}, "useful_strings": {}}
    if architecture not in {"x86", "x86_64"}:
        return result
    patterns = {"ret": b"\xc3", "leave_ret": b"\xc9\xc3", "jmp_rsp": b"\xff\xe4", "syscall_ret": b"\x0f\x05\xc3"}
    if bits == 64:
        patterns.update({"pop_rdi_ret": b"\x5f\xc3", "pop_rsi_ret": b"\x5e\xc3", "pop_rdx_ret": b"\x5a\xc3"})
    gadgets: Dict[str, List[int]] = {name: [] for name in patterns}
    useful: Dict[str, List[int]] = {"/bin/sh": []}
    rwx: List[str] = []
    if bits == 64:
        shoff, entsize, count = _u(data, 40, "Q", endian), _u(data, 58, "H", endian), _u(data, 60, "H", endian)
    else:
        shoff, entsize, count = _u(data, 32, "I", endian), _u(data, 46, "H", endian), _u(data, 48, "H", endian)
    indexed = list(sections.items())
    for index in range(min(count, len(indexed))):
        at = shoff + index * entsize
        minimum = 64 if bits == 64 else 40
        if entsize < minimum or at + minimum > len(data):
            break
        if bits == 64:
            flags, va, file_at, size = (_u(data, at + 8, "Q", endian), _u(data, at + 16, "Q", endian), _u(data, at + 24, "Q", endian), _u(data, at + 32, "Q", endian))
        else:
            flags, va, file_at, size = (_u(data, at + 8, "I", endian), _u(data, at + 12, "I", endian), _u(data, at + 16, "I", endian), _u(data, at + 20, "I", endian))
        name = indexed[index][0]
        blob = data[file_at:min(len(data), file_at + size)]
        if flags & 1 and flags & 4:
            rwx.append(name)
        if flags & 4:
            for label, needle in patterns.items():
                start = 0
                while len(gadgets[label]) < 8:
                    found = blob.find(needle, start)
                    if found < 0:
                        break
                    gadgets[label].append(va + found)
                    start = found + 1
        start = 0
        while len(useful["/bin/sh"]) < 4:
            found = blob.find(b"/bin/sh\0", start)
            if found < 0:
                break
            useful["/bin/sh"].append(va + found)
            start = found + 1
    result["rwx_sections"] = sorted(rwx, key=str.lower)
    result["gadgets"] = {name: values for name, values in sorted(gadgets.items()) if values}
    result["useful_strings"] = {name: values for name, values in sorted(useful.items()) if values}
    return result


PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0xAA64: "aarch64"}


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
    magic = _u(data, opt, "H")
    if magic == 0x20B:
        bits, image_base_off, data_dir_off = 64, 24, 112
        image_base = _u(data, opt + image_base_off, "Q")
    elif magic == 0x10B:
        bits, image_base_off, data_dir_off = 32, 28, 96
        image_base = _u(data, opt + image_base_off, "I")
    else:
        raise ParseError("unsupported PE optional header")
    if opt + optional_size > len(data):
        raise ParseError("truncated PE optional header")
    entry_rva = _u(data, opt + 16, "I")
    dll_chars = _u(data, opt + 70, "H")
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

    def rva_to_offset(rva: int) -> Optional[int]:
        for _, va, vs, raw, rs, _ in sections:
            if va <= rva < va + max(vs, rs):
                result = raw + (rva - va)
                return result if result < len(data) else None
        return rva if rva < len(data) else None

    imports = set()
    if data_dir_off + 16 <= optional_size:
        import_rva = _u(data, opt + data_dir_off + 8, "I")
        descriptor = rva_to_offset(import_rva) if import_rva else None
        for _ in range(4096):
            if descriptor is None or descriptor + 20 > len(data):
                break
            original, _, _, name_rva, thunk = struct.unpack_from("<IIIII", data, descriptor)
            if not any((original, name_rva, thunk)):
                break
            thunk_off = rva_to_offset(original or thunk)
            stride = 8 if bits == 64 else 4
            ordinal_mask = 1 << (bits - 1)
            for item in range(4096):
                at = (thunk_off or 0) + item * stride
                if thunk_off is None or at + stride > len(data):
                    break
                value = _u(data, at, "Q" if bits == 64 else "I")
                if value == 0:
                    break
                if not value & ordinal_mask:
                    name_off = rva_to_offset(value)
                    name = _c_string(data, (name_off or -2) + 2)
                    if name:
                        imports.add(name)
            descriptor += 20
    parsed_imports = sorted(imports, key=str.lower)
    values = extract_strings(data)
    string_hints = sorted(set(_interesting_names(values)) - set(parsed_imports), key=str.lower)
    imports.update(string_hints)
    nx = bool(dll_chars & 0x0100)
    aslr = bool(dll_chars & 0x0040)
    cfg = bool(dll_chars & 0x4000)
    writable_executable = any((flags & 0x80000000) and (flags & 0x20000000) for *_, flags in sections)
    return BinaryInfo(
        format="PE", bits=bits, endian="little", architecture=PE_MACHINES.get(machine, "machine-%d" % machine),
        entrypoint=image_base + entry_rva, image_base=image_base,
        imports=sorted(imports, key=str.lower), symbols=[], strings=values,
        mitigations={"nx": nx, "aslr": aslr, "cfg": cfg, "stack_canary": None, "writable_executable": writable_executable},
        metadata={
            "dll": bool(characteristics & 0x2000), "sections": sorted(section[0] for section in sections),
            "parsed_imports": parsed_imports, "string_import_hints": string_hints,
            "rwx_sections": sorted(section[0] for section in sections if (section[5] & 0x80000000) and (section[5] & 0x20000000)),
        },
    )


MACH_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "aarch64"}


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
    entry = None
    dylibs = []
    executable_stack = False
    for _ in range(min(commands, 65535)):
        if at + 8 > len(data):
            break
        command, size = _u(data, at, "I", endian), _u(data, at + 4, "I", endian)
        if size < 8 or at + size > len(data):
            break
        if command == 0x80000028 and size >= 24:
            entry = _u(data, at + 8, "Q", endian)
        elif command in {0xC, 0x18, 0x1F, 0x8000001F, 0x80000018} and size >= 24:
            name_at = _u(data, at + 8, "I", endian)
            name = _c_string(data, at + name_at)
            if name:
                dylibs.append(name)
        elif command in {0x1, 0x19}:
            name = data[at + 8:at + 24].split(b"\0", 1)[0]
            if name == b"__UNIXSTACK":
                flags_at = at + (56 if bits == 64 else 48)
                if flags_at + 4 <= at + size:
                    executable_stack = bool(_u(data, flags_at, "I", endian) & 4)
        at += size
    values = extract_strings(data)
    imports = _interesting_names(values)
    pie = bool(flags & 0x200000)
    return BinaryInfo(
        format="Mach-O", bits=bits, endian="big" if endian == ">" else "little",
        architecture=MACH_CPU.get(cpu, "cpu-%d" % cpu), entrypoint=entry,
        imports=imports, symbols=[], strings=values,
        mitigations={"nx": not executable_stack, "pie": pie, "aslr": pie, "stack_canary": b"___stack_chk_fail" in data},
        metadata={
            "file_type": file_type, "dylibs": sorted(set(dylibs), key=str.lower),
            "parsed_imports": [], "string_import_hints": imports,
            "rwx_sections": ["__UNIXSTACK"] if executable_stack else [],
        },
    )
