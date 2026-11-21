import json

from test_parsers import minimal_elf64

from pwnscan.analyzer import analyze, scan_bytes
from pwnscan.model import BinaryInfo
from pwnscan.report import render_json, render_text


def info(**updates):
    values = {
        "format": "ELF", "bits": 64, "endian": "little", "architecture": "x86_64",
        "entrypoint": 0x401000, "imports": [], "symbols": [], "strings": [],
        "mitigations": {"nx": True, "pie": True, "stack_canary": True}, "metadata": {},
    }
    values.update(updates)
    return BinaryInfo(**values)


def test_overflow_vector_uses_mitigations():
    findings = analyze(info(
        imports=["gets"], mitigations={"nx": True, "pie": False, "stack_canary": False},
        metadata={"parsed_imports": ["gets"], "ghidra": {"calls": [{"from": "00401020", "function": "main", "to": "gets"}]}},
    ))
    overflow = next(item for item in findings if item.id == "PWN-BOF-001")
    assert overflow.severity == "high"
    assert "ROP/ret2libc" in overflow.attack_vector


def test_glibc_isoc99_scanf_import_is_an_unbounded_surface():
    findings = analyze(info(
        imports=["__isoc99_scanf"],
        metadata={"parsed_imports": ["__isoc99_scanf"], "ghidra": {"calls": [
            {"from": "00401050", "function": "main", "to": "__isoc99_scanf"}]}},
    ))
    overflow = next(item for item in findings if item.id == "PWN-BOF-001")
    assert any("__isoc99_scanf" in reason for reason in overflow.evidence)


def test_format_string_requires_sink_and_clue():
    findings = analyze(info(imports=["printf"], strings=["hello %7$p", "%n"], metadata={"parsed_imports": ["printf"]}))
    assert any(item.id == "PWN-FMT-001" for item in findings)
    assert not any(item.id == "PWN-FMT-001" for item in analyze(info(imports=["printf"])))


def test_constant_normal_format_does_not_raise_format_finding():
    findings = analyze(info(imports=["printf"], strings=["user: %s count: %d"], metadata={"parsed_imports": ["printf"]}))
    assert not any(item.id == "PWN-FMT-001" for item in findings)


def test_ghidra_dynamic_format_is_high_confidence():
    findings = analyze(info(
        imports=["printf"], metadata={"parsed_imports": ["printf"], "ghidra": {"calls": [
            {"from": "00401020", "function": "main", "to": "printf", "arguments": [{"kind": "stack", "stack_offset": -64}]},
        ]}},
    ))
    finding = next(item for item in findings if item.id == "PWN-FMT-001")
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert "%p.%p.%p" in finding.attack_vector


def test_ghidra_constant_format_is_not_reported():
    findings = analyze(info(
        imports=["printf"], metadata={"parsed_imports": ["printf"], "ghidra": {"calls": [
            {"from": "00401020", "function": "main", "to": "printf", "arguments": [{"kind": "address_constant", "address": "00402000", "writable": False}]},
        ]}},
    ))
    assert not any(item.id == "PWN-FMT-001" for item in findings)


def test_ghidra_proves_constant_length_stack_overflow():
    findings = analyze(info(
        imports=["read"], metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00401110", "function": "read_name", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "buffer_size": 64, "variable": "name"},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    finding = next(item for item in findings if item.id == "PWN-BOUNDS-001")
    assert finding.severity == "critical"
    assert "overflow window 192 bytes" in finding.evidence[0]
    assert "exactly 256" in finding.validation[0]


def test_ghidra_safe_constant_length_is_not_overflow():
    findings = analyze(info(
        imports=["read"], metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00401110", "function": "read_name", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "buffer_size": 64},
                {"kind": "constant", "value": 63},
            ]},
        ]}},
    ))
    assert not any(item.id == "PWN-BOUNDS-001" for item in findings)


def test_exact_ret2win_payload_is_ready_only_with_complete_proof():
    findings = analyze(info(
        imports=["read"], symbols=["print_flag"],
        mitigations={"nx": True, "pie": False, "stack_canary": False},
        metadata={"symbol_addresses": {"print_flag": 0x401234}, "parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00401110", "function": "main", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "buffer_size": 64, "return_address_offset": 72, "variable": "name"},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    finding = next(item for item in findings if item.id == "PWN-FLAG-CHAIN-001")
    assert finding.exploit_status == "payload-ready"
    assert "print_flag" in finding.flag_path
    assert "3412400000000000" in finding.attack_vector
    assert "OFFSET" not in finding.attack_vector


def test_exact_ret2win_payload_is_withheld_when_pie_is_enabled():
    findings = analyze(info(
        imports=["read"], symbols=["print_flag"],
        mitigations={"nx": True, "pie": True, "stack_canary": False},
        metadata={"symbol_addresses": {"print_flag": 0x1234}, "ghidra": {"calls": [
            {"from": "00101110", "function": "main", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "buffer_size": 64, "return_address_offset": 72},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    assert not any(item.id == "PWN-FLAG-CHAIN-001" for item in findings)


def test_command_sink_without_dynamic_callsite_is_low_confidence():
    finding = next(item for item in analyze(info(
        imports=["system"], metadata={"parsed_imports": ["system"]},
    )) if item.id == "PWN-CMD-001")
    assert finding.severity == "low"
    assert finding.confidence == "low"


def test_dynamic_command_callsite_is_high_confidence():
    finding = next(item for item in analyze(info(
        imports=["system"], metadata={"parsed_imports": ["system"], "ghidra": {"calls": [
            {"from": "00401220", "function": "run", "to": "system", "arguments": [{"kind": "dynamic", "repr": "input"}]},
        ]}},
    )) if item.id == "PWN-CMD-001")
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert "cat /flag" in finding.attack_vector


def test_ret2win_clues():
    findings = analyze(info(symbols=["main", "print_flag"], strings=["Try again"]))
    finding = next(item for item in findings if item.id == "PWN-WIN-001")
    assert finding.confidence == "high"
    assert "symbol: print_flag" in finding.evidence


def test_no_signal_returns_manual_triage():
    findings = analyze(info())
    assert [item.id for item in findings] == ["PWN-TRIAGE-000"]


def test_json_is_deterministic_and_sorted():
    payload = minimal_elf64(b"gets\0win\0FLAG{demo}\0")
    first = render_json(scan_bytes(payload, "same"))
    second = render_json(scan_bytes(payload, "same"))
    assert first == second
    decoded = json.loads(first)
    assert decoded["schema"] == "pwnscan/v1"
    ids = [item["id"] for item in decoded["findings"]]
    assert "PWN-BOF-001" in ids
    assert "PWN-WIN-001" in ids


def test_text_has_vector_and_patch():
    text = render_text(scan_bytes(minimal_elf64(b"gets\0"), "fixture"), color=False)
    assert "vector:" in text
    assert "patch:" in text
    assert "exploit: validation-only" in text
    assert "flag path:" in text
    assert "\x1b[" not in text


def test_plain_api_name_is_only_low_confidence_hint():
    finding = next(item for item in analyze(info(
        imports=["strcpy"], metadata={"parsed_imports": [], "string_import_hints": ["strcpy"]},
    )) if item.id == "PWN-BOF-001")
    assert finding.severity == "low"
    assert finding.confidence == "low"
    assert finding.evidence == ["unverified string hint: strcpy"]


def expression(op, *inputs):
    return {"op": op, "size": 8, "inputs": list(inputs)}


def dynamic(name, operation=None):
    value = {"kind": "dynamic", "repr": name, "high_name": name, "size": 8}
    if operation is not None:
        value["expression"] = operation
    return value


def test_arithmetic_allocation_size_is_reported_without_claiming_payload_ready():
    count = dynamic("count", expression("INT_MULT", {"kind": "dynamic", "repr": "count", "size": 4}, {"kind": "constant", "value": 48, "size": 4}))
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401200", "function": "load", "to": "malloc", "arguments": [count]},
    ]}}))
    finding = next(item for item in findings if item.id == "PWN-INT-001")
    assert finding.confidence == "medium"
    assert finding.exploit_status == "validation-only"
    assert "SIZE_MAX" in finding.patch


def test_plain_dynamic_allocation_size_is_not_integer_overflow():
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401200", "function": "load", "to": "malloc", "arguments": [dynamic("size")]},
    ]}}))
    assert not any(item.id == "PWN-INT-001" for item in findings)


def test_width_conversion_in_write_length_is_reported():
    length = dynamic("signed_length", expression("INT_SEXT", {"kind": "dynamic", "repr": "input_length", "size": 4}))
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401300", "function": "copy", "to": "memcpy", "arguments": [dynamic("dst"), dynamic("src"), length]},
    ]}}))
    finding = next(item for item in findings if item.id == "PWN-SIGN-001")
    assert finding.confidence == "medium"
    assert "-1" in finding.attack_vector


def test_repeated_free_and_post_free_write_are_distinct_findings():
    pointer = dynamic("entry")
    calls = [
        {"from": "00401010", "function": "edit", "to": "free", "arguments": [pointer]},
        {"from": "00401020", "function": "edit", "to": "read", "arguments": [{"kind": "constant", "value": 0}, pointer, {"kind": "constant", "value": 16}]},
        {"from": "00401030", "function": "edit", "to": "free", "arguments": [pointer]},
    ]
    findings = analyze(info(metadata={"ghidra": {"calls": calls}}))
    ids = {item.id for item in findings}
    assert {"PWN-HEAP-001", "PWN-HEAP-002"} <= ids
    assert all(item.exploit_status == "validation-only" for item in findings if item.id.startswith("PWN-HEAP"))


def test_separate_pointer_identities_do_not_raise_heap_lifetime_finding():
    calls = [
        {"from": "00401010", "function": "edit", "to": "free", "arguments": [dynamic("old_entry")]},
        {"from": "00401020", "function": "edit", "to": "read", "arguments": [{"kind": "constant", "value": 0}, dynamic("new_entry"), {"kind": "constant", "value": 16}]},
    ]
    findings = analyze(info(metadata={"ghidra": {"calls": calls}}))
    assert not any(item.id.startswith("PWN-HEAP") for item in findings)


def test_stack_derived_indirect_call_is_high_confidence_but_not_payload_ready():
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401400", "function": "dispatch", "to": None, "indirect": True,
         "target": {"kind": "stack", "stack_offset": -32, "high_name": "callback"}, "arguments": []},
    ]}}))
    finding = next(item for item in findings if item.id == "PWN-CFLOW-001")
    assert finding.confidence == "high"
    assert finding.exploit_status == "validation-only"


def test_partial_relro_is_reported_as_missing_full_relro():
    finding = next(item for item in analyze(info(metadata={"relro": "partial"})) if item.id == "PWN-MIT-001")
    assert "full_relro disabled" in finding.evidence


def test_subpiece_truncation_in_write_length_is_reported():
    length = dynamic("trunc_len", expression("SUBPIECE", {"kind": "dynamic", "repr": "wide_len", "size": 8}, {"kind": "constant", "value": 0, "size": 4}))
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401320", "function": "copy", "to": "read", "arguments": [
            {"kind": "constant", "value": 0}, dynamic("dst"), length,
        ]},
    ]}}))
    finding = next(item for item in findings if item.id == "PWN-SIGN-001")
    assert "SUBPIECE" in finding.evidence[0]


def test_constant_only_arithmetic_allocation_is_not_reported():
    const_size = {
        "kind": "constant", "value": 192, "size": 8,
        "expression": expression("INT_MULT", {"kind": "constant", "value": 4, "size": 4}, {"kind": "constant", "value": 48, "size": 4}),
    }
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401200", "function": "init", "to": "malloc", "arguments": [const_size]},
    ]}}))
    assert not any(item.id == "PWN-INT-001" for item in findings)


def test_fgets_constant_length_stack_overflow_is_proven():
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401150", "function": "prompt", "to": "fgets", "arguments": [
            {"kind": "stack", "stack_offset": -48, "buffer_size": 32, "variable": "buf"},
            {"kind": "constant", "value": 128},
            dynamic("stdin"),
        ]},
    ]}}))
    finding = next(item for item in findings if item.id == "PWN-BOUNDS-001")
    assert "overflow window 96 bytes" in finding.evidence[0]


def test_snprintf_dynamic_format_argument_is_detected():
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401180", "function": "log_msg", "to": "snprintf", "arguments": [
            dynamic("out"), {"kind": "constant", "value": 64}, dynamic("user_fmt"),
        ]},
    ]}}))
    finding = next(item for item in findings if item.id == "PWN-FMT-001")
    assert finding.severity == "high"
    assert finding.confidence == "high"


def test_post_free_read_and_realloc_are_reported_as_uaf():
    pointer = dynamic("note")
    calls = [
        {"from": "00401010", "function": "show", "to": "free", "arguments": [pointer]},
        {"from": "00401020", "function": "show", "to": "puts", "arguments": [pointer]},
        {"from": "00401030", "function": "show", "to": "realloc", "arguments": [pointer, {"kind": "constant", "value": 64}]},
    ]
    findings = analyze(info(metadata={"ghidra": {"calls": calls}}))
    uaf = next(item for item in findings if item.id == "PWN-HEAP-002")
    assert any("puts" in item for item in uaf.evidence)
    assert any("realloc" in item for item in uaf.evidence)


def test_underscore_prefixed_ghidra_callsite_and_import_normalization(tmp_path):
    from pwnscan.analyzer import _merge_ghidra

    export = tmp_path / "export.json"
    export.write_text(json.dumps({
        "schema": "pwnscan-ghidra/v1",
        "functions": [{"name": "main", "entry": "100001000"}],
        "imports": ["EXTERNAL::_gets", "EXTERNAL::__isoc99_scanf"],
        "calls": [{"from": "100001020", "function": "main", "to": "_gets"}],
    }), encoding="utf-8")
    merged = _merge_ghidra(info(format="Mach-O"), export)
    assert "gets" in merged.metadata["parsed_imports"]
    assert "__isoc99_scanf" in merged.metadata["parsed_imports"]
    bof = next(item for item in analyze(merged) if item.id == "PWN-BOF-001")
    assert bof.severity == "high"
    assert bof.confidence == "high"
    assert any("Ghidra reference:" in item for item in bof.evidence)


def test_ghidra_call_without_to_resolves_from_elf_plt_addresses(tmp_path):
    from pwnscan.analyzer import _merge_ghidra

    export = tmp_path / "export.json"
    export.write_text(json.dumps({
        "schema": "pwnscan-ghidra/v1",
        "functions": [{"name": "func", "entry": "00401387"}],
        "imports": ["<EXTERNAL>::printf"],
        "calls": [{
            "from": "00401491",
            "function": "func",
            "to": None,
            "indirect": False,
            "target": {"kind": "dynamic", "repr": "(ram, 0x401170, 8)", "size": 8},
            "arguments": [{"kind": "stack", "stack_offset": -1048}],
        }],
    }), encoding="utf-8")
    merged = _merge_ghidra(info(metadata={"plt_addresses": {"0x401170": "printf"}}), export)
    fmt = next(item for item in analyze(merged) if item.id == "PWN-FMT-001")
    assert fmt.severity == "high"
    assert fmt.confidence == "high"
    assert "00401491 in func -> printf" in fmt.evidence[0]


def test_ghidra_pie_image_base_and_dat_symbol_resolve_plt_and_strip_versions(tmp_path):
    from pwnscan.analyzer import _merge_ghidra

    export = tmp_path / "pie_export.json"
    export.write_text(json.dumps({
        "schema": "pwnscan-ghidra/v1",
        "image_base": "00100000",
        "functions": [{"name": "main", "entry": "00101200"}],
        "imports": ["EXTERNAL::free@GLIBC_2.2.5"],
        "calls": [
            {
                "from": "00101731",
                "function": "main",
                "to": "DAT_00101110",
                "indirect": False,
                "target": {"kind": "dynamic", "repr": "(ram, 0x101110, 8)", "size": 8},
                "arguments": [dynamic("ptr")],
            },
            {
                "from": "00101833",
                "function": "main",
                "to": None,
                "indirect": False,
                "target": {"kind": "dynamic", "repr": "(ram, 0x101130, 8)", "size": 8},
                "arguments": [dynamic("ptr")],
            },
        ],
    }), encoding="utf-8")
    merged = _merge_ghidra(info(metadata={"plt_addresses": {"0x1110": "free", "0x1130": "puts"}}), export)
    assert merged.metadata["parsed_imports"] == ["free"]
    uaf = next(item for item in analyze(merged) if item.id == "PWN-HEAP-002")
    assert "puts" in uaf.evidence[0]
    assert "00101731" in uaf.evidence[0]


def test_fortify_source_disabled_and_chk_format_argument():
    mit = next(item for item in analyze(info(mitigations={"nx": True, "pie": True, "stack_canary": True, "fortify": False})) if item.id == "PWN-MIT-001")
    assert "fortify_source disabled" in mit.evidence

    dyn_chk = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401100", "function": "main", "to": "__printf_chk", "arguments": [
            {"kind": "constant", "value": 1},
            {"kind": "stack", "stack_offset": -32},
        ]},
    ]}}))
    assert any(item.id == "PWN-FMT-001" for item in dyn_chk)

    const_chk = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401100", "function": "main", "to": "__printf_chk", "arguments": [
            {"kind": "constant", "value": 1},
            {"kind": "address_constant", "address": "00402000", "writable": False},
        ]},
    ]}}))
    assert not any(item.id == "PWN-FMT-001" for item in const_chk)


def test_untyped_stack_read_within_return_offset_is_not_bounds_overflow():
    findings = analyze(info(
        imports=["read"],
        metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00101693", "function": "func", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -988, "return_address_offset": 988, "variable": "local_3dc"},
                {"kind": "constant", "value": 947},
            ]},
        ]}},
    ))
    assert not any(item.id == "PWN-BOUNDS-001" for item in findings)

    overflow = analyze(info(
        imports=["read"],
        metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00101693", "function": "func", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "stack", "stack_offset": -80, "return_address_offset": 80, "variable": "local_50"},
                {"kind": "constant", "value": 256},
            ]},
        ]}},
    ))
    assert any(item.id == "PWN-BOUNDS-001" for item in overflow)


def test_bounded_scanf_format_suppresses_unbounded_bof_finding():
    bounded = analyze(info(
        imports=["__isoc99_scanf"],
        metadata={"parsed_imports": ["__isoc99_scanf"], "ghidra": {"calls": [
            {"from": "00401d10", "function": "challenge", "to": "__isoc99_scanf", "arguments": [
                {"kind": "address_constant", "address": "0040354c", "writable": False, "string": "%127s%*c"},
                {"kind": "stack", "stack_offset": -152, "return_address_offset": 152, "variable": "local_98"},
            ]},
        ]}},
    ))
    assert not any(item.id == "PWN-BOF-001" for item in bounded)

    unbounded = analyze(info(
        imports=["__isoc99_scanf"],
        metadata={"parsed_imports": ["__isoc99_scanf"], "ghidra": {"calls": [
            {"from": "00401d10", "function": "challenge", "to": "__isoc99_scanf", "arguments": [
                {"kind": "address_constant", "address": "0040354c", "writable": False, "string": "%s"},
                {"kind": "stack", "stack_offset": -152, "return_address_offset": 152, "variable": "local_98"},
            ]},
        ]}},
    ))
    assert any(item.id == "PWN-BOF-001" for item in unbounded)


def test_file_stream_overwrite_and_post_close_use_are_detected():
    fp_arg = {"kind": "dynamic", "repr": "(ram, 0x404208, 8)", "high_name": "fp"}
    findings = analyze(info(
        imports=["fopen", "fclose", "fwrite", "read"],
        metadata={"parsed_imports": ["fopen", "fclose", "fwrite", "read"], "ghidra": {"calls": [
            {"from": "00401f3c", "function": "challenge", "to": "fclose", "arguments": [fp_arg]},
            {"from": "00402004", "function": "challenge", "to": "fwrite", "arguments": [
                dynamic("buf"), {"kind": "constant", "value": 1}, {"kind": "constant", "value": 64}, fp_arg,
            ]},
            {"from": "0040204b", "function": "challenge", "to": "read", "arguments": [
                {"kind": "constant", "value": 0}, fp_arg, {"kind": "constant", "value": 480},
            ]},
        ]}},
    ))
    file_finding = next(item for item in findings if item.id == "PWN-FILE-001")
    assert file_finding.severity == "high"
    assert any("writes into FILE stream fp" in item for item in file_finding.evidence)
    assert any("after fclose" in item for item in file_finding.evidence)

    stderr_findings = analyze(info(
        imports=["read"],
        metadata={"parsed_imports": ["read"], "ghidra": {"calls": [
            {"from": "00101304", "function": "challenge", "to": "read", "arguments": [
                {"kind": "constant", "value": 0},
                {"kind": "dynamic", "repr": "(ram, 0x104040, 8)", "high_name": "stderr"},
                {"kind": "constant", "value": 480},
            ]},
        ]}},
    ))
    assert any(item.id == "PWN-FILE-001" for item in stderr_findings)


def test_crt_indirect_calls_are_ignored_while_user_indirect_calls_remain():
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00101014", "function": "_init", "to": None, "indirect": True, "target": {"kind": "dynamic", "repr": "(unique, 0x1000001a, 8)"}, "arguments": []},
        {"from": "00101208", "function": "_start", "to": None, "indirect": True, "target": {"kind": "dynamic", "repr": "(unique, 0x10000049, 8)"}, "arguments": []},
        {"from": "00101999", "function": "__libc_csu_init", "to": None, "indirect": True, "target": {"kind": "dynamic", "repr": "(unique, 0x1000008a, 8)"}, "arguments": []},
    ]}}))
    assert not any(item.id == "PWN-CFLOW-001" for item in findings)

    user_findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00101400", "function": "dispatch", "to": None, "indirect": True, "target": {"kind": "dynamic", "repr": "(ram, 0x104010, 8)"}, "arguments": []},
    ]}}))
    assert any(item.id == "PWN-CFLOW-001" for item in user_findings)


def test_fwrite_after_free_is_reported_as_uaf():
    pointer = dynamic("note")
    findings = analyze(info(metadata={"ghidra": {"calls": [
        {"from": "00401ea8", "function": "challenge", "to": "free", "arguments": [pointer]},
        {"from": "00402004", "function": "challenge", "to": "fwrite", "arguments": [pointer, {"kind": "constant", "value": 1}, {"kind": "constant", "value": 16}, dynamic("fp")]},
    ]}}))
    assert any(item.id == "PWN-HEAP-002" for item in findings)


def test_pcode_unique_temporary_reuse_is_not_pointer_identity():
    """Distinct free arguments can occupy the same Ghidra unique varnode."""
    argument = {"kind": "dynamic", "repr": "(unique, 0x23e00, 8)",
                "high_name": "UNNAMED"}
    calls = [
        {"from": "00101f71", "function": "challenge", "to": "free",
         "arguments": [argument]},
        {"from": "00101fdf", "function": "challenge", "to": "free",
         "arguments": [argument]},
    ]
    findings = analyze(info(metadata={"ghidra": {"calls": calls}}))
    assert not any(item.id == "PWN-HEAP-001" for item in findings)


def test_named_pointer_repeated_free_stays_unproven_candidate():
    pointer = {"kind": "dynamic", "high_name": "entry", "repr": "(unique, 0x1234, 8)"}
    calls = [
        {"from": "00401010", "function": "edit", "to": "free", "arguments": [pointer]},
        {"from": "00401030", "function": "edit", "to": "free", "arguments": [pointer]},
    ]
    findings = analyze(info(metadata={"ghidra": {"calls": calls}}))
    candidate = next(item for item in findings if item.id == "PWN-HEAP-001")
    assert candidate.confidence == "low"
    assert candidate.exploit_status == "validation-only"
