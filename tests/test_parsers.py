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
