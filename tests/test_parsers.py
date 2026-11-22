import struct

import pytest

from pwnscan.parsers import ParseError, parse_binary


def minimal_elf64(extra=b""):
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 0, 0, 0, 64, 0, 0, 64, 0, 0)
    return bytes(data) + extra


def minimal_pe64(extra=b""):
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 0, 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<H", data, opt + 70, 0x0140)
    return bytes(data) + extra


def minimal_macho64(extra=b""):
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0x200000, 0)
    return header + extra


def structured_elf64():
    data = bytearray(0x340)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 0, 0x200, 0, 64, 0, 0, 64, 5, 4)
    data[0x100:0x108] = b"\x5f\xc3\x90\xc9\xc3\x90\x90\xc3"
    data[0x120:0x12a] = b"\0win\0gets\0"
    struct.pack_into("<IBBHQQ", data, 0x158, 1, 0x12, 0, 1, 0x401000, 8)
    struct.pack_into("<IBBHQQ", data, 0x170, 5, 0x12, 0, 0, 0, 0)
    names = b"\0.text\0.strtab\0.symtab\0.shstrtab\0"
    data[0x190:0x190 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x240, 1, 1, 6, 0x401000, 0x100, 8, 0, 0, 16, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x280, 7, 3, 0, 0, 0x120, 10, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x2c0, 15, 2, 0, 0, 0x140, 72, 2, 1, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 0x300, 23, 3, 0, 0, 0x190, len(names), 0, 0, 1, 0)
    return bytes(data)


@pytest.mark.parametrize(
    "payload,expected",
    [(minimal_elf64(), "ELF"), (minimal_pe64(), "PE"), (minimal_macho64(), "Mach-O")],
)
def test_detects_supported_formats(payload, expected):
    assert parse_binary(payload).format == expected


def test_elf_metadata_and_strings_are_stable():
    info = parse_binary(minimal_elf64(b"gets\0win\0FLAG{demo}\0"))
    assert info.bits == 64
    assert info.architecture == "x86_64"
    assert info.entrypoint == 0x401000
    assert info.imports == ["gets"]
    assert info.strings == sorted(info.strings, key=lambda value: (value.lower(), value))


def test_pe_mitigations():
    info = parse_binary(minimal_pe64(b"strcpy\0"))
    assert info.entrypoint == 0x140001000
    assert info.mitigations["nx"] is True
    assert info.mitigations["aslr"] is True
    assert "strcpy" in info.imports


def test_macho_metadata():
    info = parse_binary(minimal_macho64(b"_printf\0%x %n\0"))
    assert info.architecture == "x86_64"
    assert info.mitigations["pie"] is True
    assert info.imports == ["printf"]


def test_rejects_unknown_and_truncated_files():
    with pytest.raises(ParseError):
        parse_binary(b"text")
    with pytest.raises(ParseError):
        parse_binary(b"\x7fELF")


def test_elf_structural_symbols_imports_and_gadgets():
    info = parse_binary(structured_elf64())
    assert info.metadata["parsed_imports"] == ["gets"]
    assert info.metadata["string_import_hints"] == []
    assert info.metadata["symbol_addresses"] == {"win": 0x401000}
    assert info.metadata["gadgets"]["pop_rdi_ret"] == [0x401000]
    assert info.metadata["gadgets"]["leave_ret"] == [0x401003]


def test_elf_shared_object_is_not_mislabeled_pie():
    payload = bytearray(minimal_elf64())
    struct.pack_into("<H", payload, 16, 3)
    info = parse_binary(bytes(payload))
    assert info.metadata["elf_role"] == "shared_object"
    assert info.mitigations["pie"] is False
    assert info.mitigations["aslr"] is True


def test_elf_static_pie_detected_via_df_1_pie():
    data = bytearray(0x200)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 62, 1, 0x1000, 0x40, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 0x40, 2, 6, 0x100, 0x100, 0x100, 32, 32, 8)
    struct.pack_into("<QQ", data, 0x100, 0x6FFFFFFB, 0x08000000)
    struct.pack_into("<QQ", data, 0x110, 0, 0)
    info = parse_binary(bytes(data))
    assert info.metadata["elf_role"] == "pie"
    assert info.mitigations["pie"] is True


def test_elf_duplicate_section_names_nobits_and_canary_false_positive():
    # Sections: 0=null, 1=.dup, 2=.dup (SHT_NOBITS overlapping .rodata), 3=.rodata, 4=.strtab, 5=.symtab, 6=.shstrtab
    data = bytearray(0x400)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 0, 0x200, 0, 64, 0, 0, 64, 7, 6)
    data[0x100:0x11a] = b"/bin/sh\0__stack_chk_fail\0"
    data[0x120:0x12a] = b"\0win\0gets\0"
    struct.pack_into("<IBBHQQ", data, 0x158, 1, 0x12, 0, 1, 0x401000, 8)
    struct.pack_into("<IBBHQQ", data, 0x170, 5, 0x12, 0, 0, 0, 0)
    names = b"\0.dup\0.rodata\0.strtab\0.symtab\0.shstrtab\0"
    data[0x190:0x190 + len(names)] = names
    # 0: null
    # 1: .dup (PROGBITS)
    struct.pack_into("<IIQQQQIIQQ", data, 0x240, 1, 1, 2, 0x402000, 0x188, 4, 0, 0, 1, 0)
    # 2: .dup (NOBITS .bss-like, offset points at /bin/sh in .rodata but must be ignored)
    struct.pack_into("<IIQQQQIIQQ", data, 0x280, 1, 8, 3, 0x403000, 0x100, 32, 0, 0, 1, 0)
    # 3: .rodata
    struct.pack_into("<IIQQQQIIQQ", data, 0x2C0, 6, 1, 2, 0x402000, 0x100, 0x1a, 0, 0, 1, 0)
    # 4: .strtab
    struct.pack_into("<IIQQQQIIQQ", data, 0x300, 14, 3, 0, 0, 0x120, 10, 0, 0, 1, 0)
    # 5: .symtab (sh_link=4)
    struct.pack_into("<IIQQQQIIQQ", data, 0x340, 22, 2, 0, 0, 0x140, 72, 4, 1, 8, 24)
    # 6: .shstrtab
    struct.pack_into("<IIQQQQIIQQ", data, 0x380, 30, 3, 0, 0, 0x190, len(names), 0, 0, 1, 0)
    info = parse_binary(bytes(data))
    assert info.metadata["parsed_imports"] == ["gets"]
    assert info.metadata["symbol_addresses"] == {"win": 0x401000}
    assert info.metadata["useful_strings"] == {"/bin/sh": [0x402000]}
    assert info.mitigations["stack_canary"] is False


def test_elf64_rejects_truncated_header():
    data = bytearray(56)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    with pytest.raises(ParseError, match="truncated ELF64 header"):
        parse_binary(bytes(data))


def test_pe_rejects_short_optional_header_and_handles_missing_dll_chars():
    data = bytearray(minimal_pe64())
    struct.pack_into("<H", data, 0x84 + 16, 16)
    with pytest.raises(ParseError, match="truncated PE optional header"):
        parse_binary(bytes(data))

    short_opt = bytearray(minimal_pe64())
    struct.pack_into("<H", short_opt, 0x84 + 16, 40)
    info = parse_binary(bytes(short_opt))
    assert info.mitigations["nx"] is None
    assert info.mitigations["aslr"] is None
    assert info.mitigations["cfg"] is None


def test_pe_imports_ignore_null_ilt_and_invalid_rvas_and_parses_exports():
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0)  # no entrypoint (e.g. DLL)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<H", data, opt + 70, 0x0140)
    # Export dir at RVA 0x2000 size 0x80; Import dir at RVA 0x2100 size 0x40
    struct.pack_into("<II", data, opt + 112, 0x2000, 0x80)
    struct.pack_into("<II", data, opt + 120, 0x2100, 0x40)
    # Single section .rdata mapped VA=0x2000, size=0x400, raw=0x200
    sec = opt + 0xF0
    data[sec:sec + 8] = b".rdata\0\0"
    struct.pack_into("<IIIIII", data, sec + 8, 0x400, 0x2000, 0x400, 0x200, 0, 0)
    struct.pack_into("<I", data, sec + 36, 0x40000040)

    # Export directory at raw 0x200 (RVA 0x2000): 2 functions, 2 names
    struct.pack_into("<IIHHIIIIIII", data, 0x200, 0, 0, 0, 0, 0, 1, 2, 2, 0x2030, 0x2040, 0x2050)
    struct.pack_into("<II", data, 0x230, 0x1050, 0x2010)  # win=0x1050, fwd inside export dir
    struct.pack_into("<II", data, 0x240, 0x2060, 0x2064)
    struct.pack_into("<HH", data, 0x250, 0, 1)
    data[0x260:0x268] = b"win\0fwd\0"

    # Import descriptors at raw 0x300 (RVA 0x2100):
    # 1) broken descriptor with original=0, thunk=0, name_rva=0x2200 -> must NOT read MZ
    # 2) descriptor with thunk=0x2140 pointing to unmapped RVA 0x999900 and valid gets at 0x2160
    struct.pack_into("<IIIII", data, 0x300, 0, 0, 0, 0x2200, 0)
    struct.pack_into("<IIIII", data, 0x314, 0, 0, 0, 0x2200, 0x2140)
    struct.pack_into("<QQQ", data, 0x340, 0x999900, 0x2160, 0)
    data[0x360:0x367] = b"\0\0gets\0"

    info = parse_binary(bytes(data))
    assert info.entrypoint is None
    assert info.metadata["parsed_imports"] == ["gets"]
    assert "MZ" not in info.imports
    assert info.symbols == ["fwd", "win"]
    assert info.metadata["symbol_addresses"] == {"win": 0x140001050}


def test_macho_symtab_unixstack_initprot_and_fat_rejection():
    # 64-bit Mach-O with __TEXT, __UNIXSTACK (initprot=7), LC_MAIN, LC_SYMTAB
    data = bytearray(0x300)
    # 3 load commands, flags=MH_PIE
    struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, 2, 4, 240, 0x200000, 0)
    at = 32
    # 1: LC_SEGMENT_64 __TEXT vmaddr=0x100000000 initprot=5
    struct.pack_into("<II16sQQQQIIII", data, at, 0x19, 72, b"__TEXT", 0x100000000, 0x1000, 0, 0x300, 5, 5, 0, 0)
    at += 72
    # 2: LC_SEGMENT_64 __UNIXSTACK initprot=7 (RWX)
    struct.pack_into("<II16sQQQQIIII", data, at, 0x19, 72, b"__UNIXSTACK", 0x200000000, 0x1000, 0, 0, 7, 7, 0, 0)
    at += 72
    # 3: LC_MAIN entryoff=0x1200
    struct.pack_into("<IIQQ", data, at, 0x80000028, 24, 0x1200, 0)
    at += 24
    # 4: LC_SYMTAB symoff=0x180, nsyms=2, stroff=0x1c0, strsize=32
    struct.pack_into("<IIIIII", data, at, 0x2, 24, 0x180, 2, 0x1C0, 32)
    data[0x1C0:0x1CF] = b"\0_win\0_gets\0"
    # nlist_64: _win defined (N_SECT=0xE, n_sect=1) at 0x100001300; _gets undefined external (N_UNDF|N_EXT=0x1)
    struct.pack_into("<IBBHQ", data, 0x180, 1, 0x0E, 1, 0, 0x100001300)
    struct.pack_into("<IBBHQ", data, 0x190, 6, 0x01, 0, 0, 0)
    data[0x200:0x212] = b"___stack_chk_fail\0"

    info = parse_binary(bytes(data))
    assert info.entrypoint == 0x100001200
    assert info.mitigations["nx"] is False
    assert info.mitigations["stack_canary"] is False
    assert info.metadata["rwx_sections"] == ["__UNIXSTACK"]
    assert info.metadata["parsed_imports"] == ["gets"]
    assert info.symbols == ["gets", "win"]
    assert info.metadata["symbol_addresses"] == {"win": 0x100001300}

    # 32-bit Mach-O __UNIXSTACK with maxprot=7, initprot=3, nsects=4 (must NOT trigger NX=False)
    macho32 = bytearray(28 + 56)
    struct.pack_into("<IIIIIII", macho32, 0, 0xFEEDFACE, 7, 3, 2, 1, 56, 0)
    struct.pack_into("<II16sIIIIIIII", macho32, 28, 0x1, 56, b"__UNIXSTACK", 0, 0x1000, 0, 0, 7, 3, 4, 0)
    assert parse_binary(bytes(macho32)).mitigations["nx"] is True

    # Fat Mach-O header
    fat = struct.pack(">II", 0xCAFEBABE, 2) + b"\0" * 40
    with pytest.raises(ParseError, match="thin slice"):
        parse_binary(fat)


def test_elf_plt_addresses_resolves_plt_sec_stubs():
    # Sections: 0=null, 1=.dynstr, 2=.dynsym, 3=.rela.plt, 4=.plt.sec, 5=.shstrtab
    data = bytearray(0x400)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 0, 0x200, 0, 64, 0, 0, 64, 6, 5)
    data[0x100:0x109] = b"\0printf\0"
    # .dynsym: entry 0 (null), entry 1 (printf)
    struct.pack_into("<IBBHQQ", data, 0x138, 1, 0x12, 0, 0, 0, 0)
    # .rela.plt: entry 0 -> sym_index=1 (r_info = 1 << 32 | 7)
    struct.pack_into("<QQq", data, 0x160, 0x404018, (1 << 32) | 7, 0)
    names = b"\0.dynstr\0.dynsym\0.rela.plt\0.plt.sec\0.shstrtab\0"
    data[0x190:0x190 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x240, 1, 3, 2, 0, 0x100, 9, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x280, 9, 11, 2, 0, 0x120, 48, 1, 1, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 0x2C0, 17, 4, 2, 0, 0x160, 24, 2, 0, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 0x300, 27, 1, 6, 0x401120, 0x180, 16, 0, 0, 16, 16)
    struct.pack_into("<IIQQQQIIQQ", data, 0x340, 36, 3, 0, 0, 0x190, len(names), 0, 0, 1, 0)

    info = parse_binary(bytes(data))
    assert info.metadata["plt_addresses"] == {"0x401120": "printf"}


def test_elf_fortify_source_detection():
    assert parse_binary(structured_elf64()).mitigations["fortify"] is False

    data = bytearray(0x340)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000, 0, 0x200, 0, 64, 0, 0, 64, 4, 3)
    data[0x100:0x11d] = b"\0__printf_chk\0__memcpy_chk\0"
    struct.pack_into("<IBBHQQ", data, 0x158, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", data, 0x170, 14, 0x12, 0, 0, 0, 0)
    names = b"\0.dynstr\0.dynsym\0.shstrtab\0"
    data[0x190:0x190 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x240, 1, 3, 2, 0, 0x100, 29, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x280, 9, 11, 2, 0, 0x140, 72, 1, 1, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 0x2C0, 17, 3, 0, 0, 0x190, len(names), 0, 0, 1, 0)
    info = parse_binary(bytes(data))
    assert info.mitigations["fortify"] is True
    assert info.metadata["fortified_imports"] == ["__memcpy_chk", "__printf_chk"]


def test_elf32_big_endian_mips_program_headers_and_symbols():
    data = bytearray(0x400)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x01\x02"  # 32-bit, big-endian
    data[6] = 1
    # e_type=3 (ET_DYN), e_machine=8 (mips), entry=0x1000, phoff=0x34, shoff=0x240, phentsize=32, phnum=4, shentsize=40, shnum=4, shstrndx=3
    struct.pack_into(">HHIIIIIHHHHHH", data, 16, 3, 8, 1, 0x1000, 0x34, 0x240, 0, 52, 32, 4, 40, 4, 3)
    # Phdr 0: PT_GNU_STACK (p_flags=7 -> NX=False)
    struct.pack_into(">IIIIIIII", data, 0x34, 0x6474E551, 0, 0, 0, 0, 0, 7, 4)
    # Phdr 1: PT_GNU_RELRO
    struct.pack_into(">IIIIIIII", data, 0x54, 0x6474E552, 0, 0, 0, 0, 0, 4, 4)
    # Phdr 2: PT_INTERP
    struct.pack_into(">IIIIIIII", data, 0x74, 3, 0, 0, 0, 0, 0, 4, 4)
    # Phdr 3: PT_DYNAMIC at 0x100 size 16 -> DT_BIND_NOW (tag=24)
    struct.pack_into(">IIIIIIII", data, 0x94, 2, 0x100, 0x100, 0x100, 16, 16, 6, 4)
    struct.pack_into(">II", data, 0x100, 24, 0)
    struct.pack_into(">II", data, 0x108, 0, 0)

    # .strtab at 0x120, .symtab at 0x140 (Elf32_Sym: 16 bytes)
    data[0x120:0x12c] = b"\0win\0strcpy\0"
    struct.pack_into(">IIIBBH", data, 0x150, 1, 0x1080, 16, 0x12, 0, 1)
    struct.pack_into(">IIIBBH", data, 0x160, 5, 0, 0, 0x12, 0, 0)
    names = b"\0.strtab\0.symtab\0.shstrtab\0"
    data[0x190:0x190 + len(names)] = names
    # Shdr 0 (null), 1 (.strtab), 2 (.symtab), 3 (.shstrtab)
    struct.pack_into(">IIIIIIIIII", data, 0x268, 1, 3, 0, 0, 0x120, 12, 0, 0, 1, 0)
    struct.pack_into(">IIIIIIIIII", data, 0x290, 9, 2, 0, 0, 0x140, 48, 1, 1, 4, 16)
    struct.pack_into(">IIIIIIIIII", data, 0x2B8, 17, 3, 0, 0, 0x190, len(names), 0, 0, 1, 0)

    info = parse_binary(bytes(data))
    assert info.bits == 32
    assert info.endian == "big"
    assert info.architecture == "mips"
    assert info.mitigations["nx"] is False
    assert info.mitigations["pie"] is True
    assert info.metadata["relro"] == "full"
    assert info.metadata["parsed_imports"] == ["strcpy"]
    assert info.metadata["symbol_addresses"] == {"win": 0x1080}


def test_elf32_x86_plt_and_gadgets():
    data = bytearray(0x400)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x01\x01"  # 32-bit, little-endian
    data[6] = 1
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 3, 1, 0x8048400, 0, 0x200, 0, 52, 0, 0, 40, 6, 5)
    data[0x100:0x108] = b"\0gets\0\0\0"
    data[0x110:0x114] = b"\xc9\xc3\x90\xc3"  # leave_ret at +0, ret at +1/+3
    struct.pack_into("<IIIBBH", data, 0x130, 1, 0, 0, 0x12, 0, 0)
    struct.pack_into("<II", data, 0x150, 0x804a00c, 1 << 8)  # Elf32_Rel -> sym 1
    names = b"\0.dynstr\0.dynsym\0.rel.plt\0.plt\0.shstrtab\0"
    data[0x170:0x170 + len(names)] = names
    struct.pack_into("<IIIIIIIIII", data, 0x228, 1, 3, 2, 0, 0x100, 8, 0, 0, 1, 0)
    struct.pack_into("<IIIIIIIIII", data, 0x250, 9, 11, 2, 0, 0x120, 32, 1, 1, 4, 16)
    struct.pack_into("<IIIIIIIIII", data, 0x278, 17, 9, 2, 0, 0x150, 8, 2, 0, 4, 8)
    struct.pack_into("<IIIIIIIIII", data, 0x2A0, 26, 1, 6, 0x8048300, 0x110, 32, 0, 0, 16, 16)
    struct.pack_into("<IIIIIIIIII", data, 0x2C8, 31, 3, 0, 0, 0x170, len(names), 0, 0, 1, 0)

    info = parse_binary(bytes(data))
    assert info.bits == 32
    assert info.architecture == "x86"
    assert info.metadata["plt_addresses"] == {"0x8048310": "gets"}
    assert info.metadata["gadgets"]["leave_ret"] == [0x8048300]


def test_pe32_imports_cfg_and_rwx_section():
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10B)  # PE32
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<H", data, opt + 70, 0x4140)  # NX + ASLR + CFG
    struct.pack_into("<II", data, opt + 104, 0x2000, 0x40)  # Import directory at opt+96+8
    sec = opt + 0xE0
    data[sec:sec + 8] = b".rwx\0\0\0\0"
    struct.pack_into("<IIIIII", data, sec + 8, 0x200, 0x2000, 0x200, 0x200, 0, 0)
    struct.pack_into("<I", data, sec + 36, 0xE0000020)  # RWX section
    struct.pack_into("<IIIII", data, 0x200, 0x2020, 0, 0, 0x2040, 0)
    struct.pack_into("<II", data, 0x220, 0x2030, 0)
    data[0x230:0x239] = b"\0\0strcpy\0"

    info = parse_binary(bytes(data))
    assert info.bits == 32
    assert info.architecture == "x86"
    assert info.entrypoint == 0x401000
    assert info.mitigations["cfg"] is True
    assert info.mitigations["writable_executable"] is True
    assert info.metadata["rwx_sections"] == [".rwx"]
    assert info.metadata["parsed_imports"] == ["strcpy"]


def test_elf_stripped_canary_unknown_unless_symbol_string_present():
    # No section headers -> no symtab: absence of the symbol must not claim "off".
    assert parse_binary(minimal_elf64()).mitigations["stack_canary"] is None
    assert parse_binary(minimal_elf64(b"__stack_chk_fail\0")).mitigations["stack_canary"] is True


def test_macho_stripped_canary_unknown_unless_symbol_string_present():
    header = bytearray(32)
    struct.pack_into("<IIIIIIII", header, 0, 0xFEEDFACF, 0x01000007, 3, 0, 0, 0, 0, 0)
    assert parse_binary(bytes(header)).mitigations["stack_canary"] is None
    with_string = bytearray(32 + 20)
    struct.pack_into("<IIIIIIII", with_string, 0, 0xFEEDFACF, 0x01000007, 3, 0, 0, 0, 0, 0)
    with_string[32:32 + 18] = b"___stack_chk_fail\0"
    assert parse_binary(bytes(with_string)).mitigations["stack_canary"] is True


def test_elf32_arm_plt_addresses_use_12_byte_stride():
    data = bytearray(0x400)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x01\x01"  # 32-bit, little-endian
    data[6] = 1
    # e_machine=40 (ARM)
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 40, 1, 0x8000, 0, 0x200, 0, 52, 0, 0, 40, 6, 5)
    data[0x100:0x108] = b"\0gets\0\0\0"
    struct.pack_into("<IIIBBH", data, 0x130, 1, 0, 0, 0x12, 0, 0)
    struct.pack_into("<II", data, 0x150, 0x22, 1 << 8)  # Elf32_Rel -> sym 1
    names = b"\0.dynstr\0.dynsym\0.rel.plt\0.plt\0.shstrtab\0"
    data[0x170:0x170 + len(names)] = names
    struct.pack_into("<IIIIIIIIII", data, 0x228, 1, 3, 2, 0, 0x100, 8, 0, 0, 1, 0)
    struct.pack_into("<IIIIIIIIII", data, 0x250, 9, 11, 2, 0, 0x120, 32, 1, 1, 4, 16)
    struct.pack_into("<IIIIIIIIII", data, 0x278, 17, 9, 2, 0, 0x150, 8, 2, 0, 4, 8)
    struct.pack_into("<IIIIIIIIII", data, 0x2A0, 26, 1, 6, 0x8300, 0x110, 32, 0, 0, 12, 12)
    struct.pack_into("<IIIIIIIIII", data, 0x2C8, 31, 3, 0, 0, 0x170, len(names), 0, 0, 1, 0)
    info = parse_binary(bytes(data))
    assert info.architecture == "arm"
    assert info.metadata["plt_addresses"] == {"0x830c": "gets"}


def test_aarch64_gadget_byte_patterns():
    data = bytearray(0x200)
    data[:4] = b"\x7fELF"
    data[4:6] = b"\x02\x01"
    data[6] = 1
    # e_machine=183 (aarch64)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 183, 1, 0x400000, 0, 0x100, 0, 64, 0, 0, 64, 3, 2)
    data[0x100:0x104] = b"\xc0\x03\x5f\xd6"  # ret
    names = b"\0.text\0.shstrtab\0"
    data[0x180:0x180 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x140, 1, 1, 6, 0x400100, 0x100, 4, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x180 - 64 + 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  # placeholder overwritten below
    struct.pack_into("<IIQQQQIIQQ", data, 0x1C0, 6, 3, 0, 0, 0x180, len(names), 0, 0, 1, 0)
    info = parse_binary(bytes(data))
    assert info.architecture == "aarch64"
    assert info.metadata["gadgets"]["ret"] == [0x400100]


def test_string_addresses_scans_rodata_before_text():
    from pwnscan.parsers import _elf_string_addresses, _ElfSection

    text = _ElfSection(".text", 1, 6, 0x1000, 0, 40, 0, 0)      # executable, scanned last
    rodata = _ElfSection(".rodata", 1, 2, 0x2000, 40, 8, 0, 0)   # read-only, scanned first
    blob = b"A" * 40 + b"%127s\0"
    result = _elf_string_addresses(blob, [text, rodata], limit=10)
    assert result["%127s"] == [0x2000]
