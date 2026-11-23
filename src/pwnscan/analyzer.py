from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import List, Optional, Sequence

from .model import BinaryInfo, Finding, ScanReport
from .parsers import parse_binary

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
UNBOUNDED_FORMAT = "may use an unbounded %s"
UNKNOWN = "<unknown>"
UNBOUNDED = {"gets": "reads an unbounded line", "strcpy": "copies without a length", "stpcpy": "copies without a length", "strcat": "appends without a length", "sprintf": "formats without a destination length", "vsprintf": "formats without a destination length", "scanf": UNBOUNDED_FORMAT, "sscanf": UNBOUNDED_FORMAT, "fscanf": UNBOUNDED_FORMAT, "__isoc99_scanf": UNBOUNDED_FORMAT, "__isoc99_sscanf": UNBOUNDED_FORMAT, "__isoc99_fscanf": UNBOUNDED_FORMAT}
FORMAT_SINKS = {"printf", "fprintf", "dprintf", "sprintf", "snprintf", "asprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf", "vasprintf", "syslog"}
FORMAT_INDEXES = {
    "printf": 0, "vprintf": 0,
    "fprintf": 1, "dprintf": 1, "sprintf": 1, "asprintf": 1, "vfprintf": 1, "vsprintf": 1, "vasprintf": 1, "syslog": 1,
    "snprintf": 2, "vsnprintf": 2,
    "printf_chk": 1, "vprintf_chk": 1,
    "fprintf_chk": 2, "dprintf_chk": 2, "vfprintf_chk": 2, "asprintf_chk": 2, "vasprintf_chk": 2,
    "sprintf_chk": 3, "vsprintf_chk": 3,
    "snprintf_chk": 4, "vsnprintf_chk": 4,
}
COMMAND_SINKS = {
    "system", "popen", "execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle",
    "posix_spawn", "posix_spawnp", "wordexp", "WinExec", "CreateProcess", "CreateProcessA", "CreateProcessW",
}
COMMAND_ARG_INDEXES = {
    "CreateProcess": (0, 1),
    "CreateProcessA": (0, 1),
    "CreateProcessW": (0, 1),
    "execv": (0, 1),
    "execvp": (0, 1),
    "execvpe": (0, 1),
    "execve": (0, 1),
}
VARARG_COMMAND_SINKS = {"execl", "execlp", "execle"}
BOUNDED_WRITES = {
    "read": (1, 2), "recv": (1, 2), "recvfrom": (1, 2), "pread": (1, 2), "pread64": (1, 2),
    "memcpy": (0, 2), "memmove": (0, 2), "strncpy": (0, 2), "strncat": (0, 2),
    "memset": (0, 2), "bzero": (0, 1),
    "fgets": (0, 1), "snprintf": (0, 1),
    "read_chk": (1, 2), "recv_chk": (1, 2), "memcpy_chk": (0, 2), "memmove_chk": (0, 2), "fgets_chk": (0, 2),
}
# String writes that do not guarantee NUL termination: a request exactly equal
# to the capacity leaves no room for the terminator (off-by-one class).
BOUNDARY_STRING_WRITES = {"strncpy", "strncat"}
DEALLOCATORS = {"free", "operator delete", "delete"}
HEAP_DEREFERENCE_ARGUMENTS = {
    "read": {1}, "recv": {1}, "recvfrom": {1}, "write": {1}, "send": {1}, "sendto": {1},
    "memcpy": {0, 1}, "memmove": {0, 1}, "strcpy": {0, 1}, "strcat": {0, 1}, "strncat": {0, 1},
    "fgets": {0}, "snprintf": {0}, "puts": {0}, "strlen": {0}, "realloc": {0},
    "fwrite": {0}, "fread": {0}, "fputs": {0},
    "strcmp": {0, 1}, "strncmp": {0, 1}, "memcmp": {0, 1},
    "strcasecmp": {0, 1}, "strncasecmp": {0, 1},
    "strstr": {0}, "strcasestr": {0}, "strchr": {0}, "strrchr": {0},
}
INPUT_FILLERS = {
    "read": 1, "recv": 1, "recvfrom": 1, "pread": 1, "pread64": 1,
    "fgets": 0, "gets": 0,
    "scanf": 1, "isoc99_scanf": 1, "sscanf": 2, "isoc99_sscanf": 2,
    "fscanf": 2, "isoc99_fscanf": 2,
}
SCANF_FORMAT_INDEX = {
    "scanf": 0, "__isoc99_scanf": 0, "vscanf": 0,
    "sscanf": 1, "__isoc99_sscanf": 1, "vsscanf": 1,
    "fscanf": 1, "__isoc99_fscanf": 1, "vfscanf": 1,
}
SCANF_SPEC_RE = re.compile(r"%(\*)?(?:\d+\$)?(\d+)?(?:hh|h|ll|l|j|z|t|L|m|a)?([diuoxXfFeEgGaAcspn\[])")
CRT_FUNCTIONS = frozenset({
    "_init", "_fini", "_start", "__libc_csu_init", "__libc_csu_fini",
    "__do_global_dtors_aux", "deregister_tm_clones", "register_tm_clones",
    "frame_dummy", "_dl_relocate_static_pie",
})
STANDARD_FILE_STREAMS = frozenset({"stdin", "stdout", "stderr"})
FILE_STREAM_ARGS = {
    "fclose": {0}, "fflush": {0}, "fseek": {0}, "ftell": {0}, "rewind": {0},
    "feof": {0}, "ferror": {0}, "clearerr": {0}, "fileno": {0}, "setbuf": {0}, "setvbuf": {0},
    "fgetc": {0}, "getc": {0}, "ungetc": {1}, "fputc": {1}, "putc": {1}, "fputs": {1},
    "fgets": {2}, "fprintf": {0}, "vfprintf": {0}, "fscanf": {0}, "__isoc99_fscanf": {0},
    "vfscanf": {0}, "fread": {3}, "fwrite": {3},
}
FILE_WRITE_DESTS = {
    "read": 1, "recv": 1, "recvfrom": 1, "read_chk": 1, "recv_chk": 1,
    "fread": 0, "fgets": 0, "fgets_chk": 0, "gets": 0, "gets_chk": 0,
    "memcpy": 0, "memmove": 0, "strcpy": 0, "stpcpy": 0, "strncpy": 0, "strcat": 0, "strncat": 0,
}
ARITHMETIC_WRAP_OPS = {"INT_ADD", "INT_MULT", "INT_LEFT", "INT_SUB"}
WIDTH_CHANGE_OPS = {"INT_SEXT", "SUBPIECE"}
WIN_NAMES = re.compile(r"(?:^|[^a-z])(win|print[_-]?flag|give[_-]?flag|shell|secret)(?:[^a-z]|$)", re.I)
FLAG_TEXT = re.compile(r"(?:flag|ctf|secret|password|/bin/sh|cat\s+[^\s]*flag)", re.I)
FLAG_OPEN_NAMES = {"open", "open64", "openat", "fopen"}
FLAG_FD_SINKS = {"sendfile": 1, "write": 0, "pwrite": 0, "send": 0, "sendto": 0, "fwrite": 3}
OUTPUT_STRING_NAMES = {"puts", "printf", "fputs", "write", "fprintf", "dprintf", "perror"}
GUARD_TEXT = re.compile(r"cannot|invalid|freed|denied|forbidden|not allowed|error|failed", re.I)


def _strip_underscores(name: str) -> str:
    return name.lstrip("_")


def _expand_name_table(table: dict) -> None:
    """Index every lookup key also in its underscore-stripped form.

    Ghidra/ELF names arrive as ``__isoc99_scanf``, ``__read_chk``, ``_printf``
    while the rule tables use the bare form; matching goes through
    ``_call_name`` (stripped), so the tables must contain the stripped keys.
    """

    for key in list(table):
        table.setdefault(_strip_underscores(key), table[key])


def _expand_name_set(names: set) -> None:
    for name in list(names):
        names.add(_strip_underscores(name))


for _table in (UNBOUNDED, FORMAT_INDEXES, BOUNDED_WRITES, HEAP_DEREFERENCE_ARGUMENTS, INPUT_FILLERS, SCANF_FORMAT_INDEX, FILE_STREAM_ARGS, FILE_WRITE_DESTS, FLAG_FD_SINKS, COMMAND_ARG_INDEXES):
    _expand_name_table(_table)
for _names in (FORMAT_SINKS, COMMAND_SINKS, VARARG_COMMAND_SINKS, DEALLOCATORS, FLAG_OPEN_NAMES, OUTPUT_STRING_NAMES):
    _expand_name_set(_names)


def _finding(identity: str, title: str, severity: str, confidence: str, evidence: Sequence[str], vector: str, validation: Sequence[str], patch: str, exploit_status: str = "validation-only", flag_path: str = "Manual confirmation required before a flag-recovery payload exists.") -> Finding:
    return Finding(identity, title, severity, confidence, sorted(set(evidence), key=str.lower), vector, list(validation), patch, exploit_status, flag_path)


def _call_name(call: dict) -> str:
    """Canonical rule-matching name: drop namespace, version suffix and leading underscores."""

    tail = str(call.get("to") or "").rsplit("::", 1)[-1].split("@", 1)[0]
    return _strip_underscores(tail)


def _call_argument(call: dict, index: int) -> dict:
    arguments = call.get("arguments")
    if not isinstance(arguments, list) or index >= len(arguments) or not isinstance(arguments[index], dict):
        return {}
    return arguments[index]


def _dynamic_argument(argument: dict) -> bool:
    return argument.get("kind") in {"dynamic", "stack"}


def _normalize_import_name(name: str) -> str:
    tail = name.rsplit("::", 1)[-1].split("@", 1)[0]
    if tail.startswith("_") and not tail.startswith("__"):
        return tail[1:]
    return tail


def _expression_ops(argument: dict) -> set[str]:
    result: set[str] = set()
    pending = [argument.get("expression")]
    while pending:
        expression = pending.pop()
        if not isinstance(expression, dict):
            continue
        operation = expression.get("op")
        if isinstance(operation, str):
            result.add(operation)
        inputs = expression.get("inputs")
        if isinstance(inputs, list):
            pending.extend(inputs)
    return result


def _expression_has_dynamic_input(argument: dict) -> bool:
    pending = [argument.get("expression")]
    saw_leaf = False
    while pending:
        node = pending.pop()
        if not isinstance(node, dict):
            continue
        inputs = node.get("inputs")
        if isinstance(inputs, list) and inputs:
            pending.extend(inputs)
            continue
        nested = node.get("expression")
        if isinstance(nested, dict):
            pending.append(nested)
            continue
        kind = node.get("kind")
        if isinstance(kind, str):
            saw_leaf = True
            if kind != "constant":
                return True
    return not saw_leaf and _dynamic_argument(argument)


def _argument_identity(argument: dict) -> str | None:
    high_name = argument.get("high_name")
    if isinstance(high_name, str) and high_name and high_name not in {"UNNAMED", "null"}:
        return "high:%s" % high_name
    stack_offset = argument.get("stack_offset")
    if isinstance(stack_offset, int):
        return "stack:%d" % stack_offset
    representation = argument.get("repr")
    if isinstance(representation, str) and representation and argument.get("kind") != "constant":
        return "repr:%s" % representation
    return None


def _call_position(call: dict) -> tuple[str, int, str]:
    value = str(call.get("from") or "")
    try:
        numeric = int(value, 16)
    except ValueError:
        numeric = 0
    return str(call.get("function") or ""), numeric, value


def _record_free(call: dict, function: str, freed: dict, double_free: list) -> None:
    identity = _argument_identity(_call_argument(call, 0))
    if identity is None:
        return
    key = function, identity
    previous = freed.get(key)
    if previous is not None:
        double_free.append(
            "%s frees %s at %s after an earlier free at %s"
            % (function, identity, call.get("from"), previous.get("from"))
        )
    else:
        freed[key] = call


def _call_sort_key(call: dict) -> int:
    return _call_position(call)[1]


def _flag_open_calls(calls: Sequence[dict]) -> dict[str, list[tuple[dict, str]]]:
    result: dict[str, list[tuple[dict, str]]] = {}
    for call in calls:
        if _call_name(call) not in FLAG_OPEN_NAMES:
            continue
        argument = _call_argument(call, 0)
        text = argument.get("string") if argument.get("kind") == "address_constant" else None
        if isinstance(text, str) and text and FLAG_TEXT.search(text):
            function = str(call.get("function") or UNKNOWN)
            result.setdefault(function, []).append((call, text))
    return result


def _guard_strings(calls: Sequence[dict]) -> dict[str, list[tuple[int, str, str]]]:
    result: dict[str, list[tuple[int, str, str]]] = {}
    for call in calls:
        if _call_name(call) not in OUTPUT_STRING_NAMES:
            continue
        argument = _call_argument(call, 0)
        text = argument.get("string") if argument.get("kind") == "address_constant" else None
        if isinstance(text, str) and text and GUARD_TEXT.search(text):
            function = str(call.get("function") or UNKNOWN)
            result.setdefault(function, []).append((_call_sort_key(call), str(call.get("from") or ""), text))
    return result


def _heap_lifetime_candidates(calls: Sequence[dict]) -> tuple[list[str], list[str], list[str]]:
    double_free: list[str] = []
    use_after_free: list[str] = []
    flag_notes: list[str] = []
    freed: dict[tuple[str, str], dict] = {}
    ordered = sorted(calls, key=_call_position)
    guards = _guard_strings(ordered)
    flag_opens = _flag_open_calls(ordered)
    for call in ordered:
        function = str(call.get("function") or UNKNOWN)
        name = _call_name(call)
        if name in DEALLOCATORS:
            _record_free(call, function, freed, double_free)
            continue
        indexes = HEAP_DEREFERENCE_ARGUMENTS.get(name, set())
        for index in indexes:
            identity = _argument_identity(_call_argument(call, index))
            previous = freed.get((function, identity or ""))
            if previous is None:
                continue
            entry = "%s passes freed %s to %s argument %d at %s; free at %s" % (
                function, identity, name, index, call.get("from"), previous.get("from"),
            )
            for guard_pos, guard_from, guard_text in guards.get(function, []):
                if _call_sort_key(previous) < guard_pos < _call_sort_key(call):
                    entry = "[guarded] " + entry + "; guard string %r at %s intervenes between free and use" % (guard_text, guard_from)
                    break
            use_after_free.append(entry)
            for open_call, path in flag_opens.get(function, []):
                flag_notes.append(
                    "flag file %r opened at %s in %s; buffer %s freed at %s and reused by %s at %s may alias the flag buffer"
                    % (path, open_call.get("from"), function, identity, previous.get("from"), name, call.get("from"))
                )
    return (
        sorted(set(double_free), key=str.lower),
        sorted(set(use_after_free), key=str.lower),
        sorted(set(flag_notes), key=str.lower),
    )


def _fread_requested(call: dict) -> Optional[int]:
    """fread(ptr, size, nmemb, stream): the byte count is the product of args 1 and 2."""

    size_arg = _call_argument(call, 1)
    count_arg = _call_argument(call, 2)
    if size_arg.get("kind") == "constant" and count_arg.get("kind") == "constant":
        size, count = size_arg.get("value"), count_arg.get("value")
        if isinstance(size, int) and isinstance(count, int):
            return size * count
    return None


def _write_capacity(destination: dict) -> Optional[tuple[int, str]]:
    buffer_size = destination.get("buffer_size")
    return_offset = destination.get("return_address_offset")
    if isinstance(buffer_size, int) and buffer_size > 0:
        return buffer_size, "buffer_size"
    if isinstance(return_offset, int) and return_offset > 0:
        return return_offset, "return_address_offset"
    return None


def _bounded_overflows(calls: Sequence[dict]) -> list[dict]:
    result = []
    for call in calls:
        name = _call_name(call)
        if name == "fread":
            destination_index, requested = 0, _fread_requested(call)
        elif name in BOUNDED_WRITES:
            destination_index, length_index = BOUNDED_WRITES[name]
            length = _call_argument(call, length_index)
            requested = length.get("value") if length.get("kind") == "constant" else None
        else:
            continue
        destination = _call_argument(call, destination_index)
        capacity = _write_capacity(destination)
        if capacity is None:
            continue
        capacity_value, capacity_kind = capacity
        if isinstance(requested, int) and requested > capacity_value:
            result.append({
                "call": call, "name": name, "buffer_size": capacity_value,
                "capacity_kind": capacity_kind, "requested": requested, "destination": destination,
            })
    return result


def _boundary_writes(calls: Sequence[dict]) -> list[dict]:
    """String writes whose request exactly fills the destination (no NUL terminator room)."""

    result = []
    for call in calls:
        name = _call_name(call)
        if name not in BOUNDARY_STRING_WRITES:
            continue
        destination_index, length_index = BOUNDED_WRITES[name]
        destination = _call_argument(call, destination_index)
        length = _call_argument(call, length_index)
        capacity = _write_capacity(destination)
        requested = length.get("value") if length.get("kind") == "constant" else None
        if capacity is not None and isinstance(requested, int) and requested == capacity[0]:
            result.append({
                "call": call, "name": name, "buffer_size": capacity[0],
                "capacity_kind": capacity[1], "requested": requested, "destination": destination,
            })
    return result


def _exact_ret2win(info: BinaryInfo, bounded: Sequence[dict], win_symbols: Sequence[str], symbol_addresses: dict) -> Finding | None:
    address_key = "pie" if info.format in {"ELF", "Mach-O"} else "aslr"
    if info.mitigations.get("stack_canary") is not False or info.mitigations.get(address_key) is not False:
        return None
    if info.bits not in {32, 64} or info.endian not in {"little", "big"}:
        return None
    function_symbols = set(info.metadata.get("function_symbols") or ())
    candidate_names = [name for name in win_symbols if name in function_symbols] if function_symbols else list(win_symbols)
    addressed = [(name, symbol_addresses.get(name)) for name in candidate_names]
    addressed = [(name, address) for name, address in addressed if isinstance(address, int) and address > 0]
    if not addressed:
        return None
    chosen_name, chosen_address = addressed[0]
    pointer_size = info.bits // 8
    for item in bounded:
        return_offset = item["destination"].get("return_address_offset")
        if not isinstance(return_offset, int) or return_offset <= 0:
            continue
        if item["requested"] < return_offset + pointer_size:
            continue
        payload = (b"A" * return_offset) + chosen_address.to_bytes(pointer_size, info.endian)
        call = item["call"]
        payload_hex = payload.hex()
        return _finding(
            "PWN-FLAG-CHAIN-001", "Verified direct flag-path overwrite", "critical", "high",
            [
                "Ghidra recovered saved return address offset %d for %s at %s" % (return_offset, item["name"], call.get("from")),
                "fixed %s address: 0x%x" % (chosen_name, chosen_address),
                "stack canary disabled; %s disabled" % address_key,
            ],
            "payload_hex=%s; send bytes.fromhex(\"%s\") to the input consumed by %s at %s."
            % (payload_hex, payload_hex, item["name"], call.get("from")),
            [
                "Run only against the authorized challenge instance.",
                "Confirm execution reaches %s and capture its flag output." % chosen_name,
            ],
            "Bound the write to the destination capacity and enable stack canaries plus position-independent code.",
            "payload-ready",
            "The payload overwrites the saved return address with %s (0x%x), the statically identified flag path." % (chosen_name, chosen_address),
        )
    return None


def _check_bounded_overflows(bounded: Sequence[dict]) -> Optional[Finding]:
    if not bounded:
        return None
    evidence = []
    validation = []
    for item in bounded:
        call = item["call"]
        variable = item["destination"].get("variable") or "stack destination"
        delta = item["requested"] - item["buffer_size"]
        if item.get("capacity_kind") == "return_address_offset":
            detail = "past saved return offset of %s" % variable
        else:
            detail = "into %s" % variable
        evidence.append(
            "Ghidra call %s at %s in %s writes up to %d bytes %s (%d bytes); overflow window %d bytes"
            % (item["name"], call.get("from"), call.get("function") or UNKNOWN, item["requested"], detail, item["buffer_size"], delta)
        )
        validation.append("Send exactly %d non-newline bytes to the input reaching %s and confirm saved-state corruption in a debugger." % (item["requested"], call.get("from")))
    return _finding(
        "PWN-BOUNDS-001", "Proven constant-length stack overwrite", "critical", "high", evidence,
        "The decompiler recovered a destination smaller than the requested write. Use a cyclic pattern of the reported request length, measure the saved-state offset, then select ret2win or ROP from the reported mitigations and addresses.",
        validation,
        "Cap each write at the recovered destination size minus required terminator space and reject larger input before the call.",
    )


def _check_boundary_writes(boundary: Sequence[dict]) -> Optional[Finding]:
    if not boundary:
        return None
    evidence = [
        "Ghidra call %s at %s in %s fills the whole %s (%d bytes) with no room for a NUL terminator"
        % (item["name"], item["call"].get("from"), item["call"].get("function") or UNKNOWN,
           item["destination"].get("variable") or "stack destination", item["buffer_size"])
        for item in boundary
    ]
    return _finding(
        "PWN-BOF-002", "Boundary write leaves no terminator room", "low", "medium", evidence,
        "If the destination is later treated as a C string (strlen/strcpy/printf %s), the missing terminator reads or copies past the buffer. Confirm the follow-up use in the decompiler before building a payload.",
        ["Check every consumer of the destination for unbounded string operations."],
        "Cap string copies at destination size minus one, or terminate explicitly after the copy.",
    )


def _check_integer_allocations(ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    # calloc is excluded: the allocator checks the count*size product internally.
    allocation_indexes = {
        "malloc": {0}, "realloc": {1}, "aligned_alloc": {1},
        "memalign": {1}, "posix_memalign": {2},
        "operator new": {0}, "operator new[]": {0}, "new": {0},
    }
    arithmetic_allocations = []
    for call in ghidra_calls:
        name = _call_name(call)
        for index in allocation_indexes.get(name, set()):
            argument = _call_argument(call, index)
            operations = _expression_ops(argument)
            if (operations & ARITHMETIC_WRAP_OPS) and _expression_has_dynamic_input(argument):
                arithmetic_allocations.append((call, index, sorted(operations & ARITHMETIC_WRAP_OPS)))
    if not arithmetic_allocations:
        return None
    evidence = [
        "Ghidra traces %s argument %d at %s through %s"
        % (_call_name(call), index, call.get("from"), ", ".join(operations))
        for call, index, operations in arithmetic_allocations
    ]
    return _finding(
        "PWN-INT-001", "Wrap-prone arithmetic controls an allocation size", "medium", "medium", evidence,
        "Drive the reported count or element size toward the integer-width boundary. Confirm allocation wraps smaller than the later initialized element count before deriving a heap-overflow payload.",
        ["Recover operand widths and input bounds in the decompiler.", "Break on the allocator and compare the requested byte count with the following write volume."],
        "Reject operands above SIZE_MAX / element_size before multiplication and above SIZE_MAX - increment before addition.",
    )


DIVISION_OPS = {"INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM"}


def _check_division(ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    risky = []
    for call in ghidra_calls:
        arguments = call.get("arguments")
        if not isinstance(arguments, list):
            continue
        for index, argument in enumerate(arguments):
            if not isinstance(argument, dict):
                continue
            operations = _expression_ops(argument)
            if (operations & DIVISION_OPS) and _expression_has_dynamic_input(argument):
                risky.append((call, index, sorted(operations & DIVISION_OPS)))
    if not risky:
        return None
    evidence = [
        "Ghidra traces %s argument %d at %s through %s"
        % (_call_name(call), index, call.get("from"), ", ".join(operations))
        for call, index, operations in risky
    ]
    return _finding(
        "PWN-INT-002", "Dynamic value reaches a division or modulo", "low", "medium", evidence,
        "Drive the divisor toward zero or INT_MIN/-1 (signed overflow trap) and observe whether the program crashes or miscomputes a size/offset.",
        ["Confirm the divisor can be zero or -1 on the reported path."],
        "Validate the divisor before dividing and use checked arithmetic helpers.",
    )


def _check_width_conversions(ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    width_changed_lengths = []
    for call in ghidra_calls:
        name = _call_name(call)
        if name == "fread":
            length_indexes: tuple[int, ...] = (1, 2)
        elif name in BOUNDED_WRITES:
            length_indexes = (BOUNDED_WRITES[name][1],)
        else:
            continue
        for length_index in length_indexes:
            argument = _call_argument(call, length_index)
            operations = _expression_ops(argument)
            if (operations & WIDTH_CHANGE_OPS) and _expression_has_dynamic_input(argument):
                width_changed_lengths.append((call, length_index, sorted(operations & WIDTH_CHANGE_OPS)))
    if not width_changed_lengths:
        return None
    return _finding(
        "PWN-SIGN-001", "Width or signedness conversion controls a write length", "high", "medium",
        [
            "Ghidra traces %s length argument %d at %s through %s"
            % (_call_name(call), index, call.get("from"), ", ".join(operations))
            for call, index, operations in width_changed_lengths
        ],
        "Test boundary values -1, 0, the destination size, and the source type maximum. A negative value converted to size_t or a truncated large value can produce an oversized write; build a payload only after the debugger confirms that conversion.",
        ["Recover source and destination integer types.", "Compare the validated value with the value passed to the write call."],
        "Validate in the unsigned destination type before conversion, reject negatives, and use checked conversion helpers.",
    )


def _check_heap_lifetime(ghidra_calls: Sequence[dict]) -> List[Finding]:
    findings: List[Finding] = []
    double_free, use_after_free, flag_notes = _heap_lifetime_candidates(ghidra_calls)
    if double_free:
        findings.append(_finding(
            "PWN-HEAP-001", "Repeated free of the same recovered pointer", "high", "medium", double_free,
            "Reach both reported frees on one execution path. If confirmed, use allocator diagnostics to test duplicate-bin insertion; derive a write target only for the challenge allocator and version.",
            ["Confirm both frees execute without an intervening reassignment.", "Record allocator family and hardening before selecting a heap technique."],
            "Give each allocation one owner and clear or transfer the pointer after free.",
        ))
    if use_after_free:
        flag_path = "Manual confirmation required before a flag-recovery payload exists."
        if flag_notes:
            flag_path = (
                "Leak the flag buffer through the reported use-after-free: %s. "
                "Reclaim the freed chunk and read it back with puts/write before reallocating it."
                % flag_notes[0]
            )
        findings.append(_finding(
            "PWN-HEAP-002", "Freed pointer reused by a memory operation", "high", "medium",
            use_after_free + flag_notes,
            "Reach the free and later dereference on one path, reclaim the same size class with controlled data, then test whether the reported operation reads or overwrites the replacement object.",
            ["Confirm no reassignment dominates the later use.", "Use allocator tracing to prove the chunk was reclaimed."],
            "Invalidate aliases after free and enforce object lifetime through single ownership.",
            flag_path=flag_path,
        ))
    return findings


def _check_indirect_calls(ghidra_calls: Sequence[dict]) -> List[Finding]:
    findings: List[Finding] = []
    stack_indirect = []
    loaded_indirect = []
    other_indirect = []
    for call in ghidra_calls:
        if call.get("indirect") is not True:
            continue
        target = call.get("target") if isinstance(call.get("target"), dict) else {}
        function = call.get("function") or UNKNOWN
        is_stack = target.get("kind") == "stack"
        if not is_stack and function in CRT_FUNCTIONS:
            continue
        entry = "indirect call at %s in %s; target %s" % (
            call.get("from"), function,
            _argument_identity(target) or target.get("repr") or "not recovered",
        )
        if is_stack:
            stack_indirect.append(entry)
        elif "LOAD" in _expression_ops(target):
            loaded_indirect.append(entry)
        else:
            other_indirect.append(entry)
    if stack_indirect:
        findings.append(_finding(
            "PWN-CFLOW-001", "Stack-derived indirect call target", "high", "high", stack_indirect,
            "Map writes to the reported stack slot. If challenge input controls the full function pointer, redirect it to a compatible fixed success routine or validated gadget.",
            ["Confirm the target slot is writable from challenge input.", "Check the function signature and CFI policy before choosing a destination."],
            "Keep control-flow targets outside writable input buffers and enable CFI or CFG.",
        ))
    if loaded_indirect:
        findings.append(_finding(
            "PWN-CFLOW-002", "Indirect call through a memory-loaded pointer (vtable/function-pointer)", "low", "medium", loaded_indirect,
            "The target was LOADed from memory, i.e. a vtable or function-pointer slot. Trace the object to its last write; continue only if challenge input controls that write (type confusion / vtable overwrite).",
            ["Identify the owning object/struct and every write to the slot.", "Check whether an overflow or UAF can reach the vtable pointer."],
            "Validate vtable pointers, protect dispatch tables from untrusted writes, and enable CFI or CFG.",
        ))
    if other_indirect:
        findings.append(_finding(
            "PWN-CFLOW-001", "Indirect call requires target provenance review", "low", "low", other_indirect,
            "Trace the recovered function pointer to its last write. Continue only if challenge input controls that write.",
            ["Distinguish normal dispatch from a writable function pointer.", "Inspect all assignments reaching the call."],
            "Protect dispatch tables from untrusted writes and enable CFI or CFG.",
        ))
    return findings


SECCOMP_APIS = {"seccomp", "seccomp_init", "seccomp_rule_add", "prctl"}
DYNLOAD_APIS = {"LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "dlopen", "dlsym"}


def _check_dynamic_loading(parsed_imports: set[str]) -> Optional[Finding]:
    present = sorted(set(parsed_imports) & DYNLOAD_APIS, key=str.lower)
    if not present:
        return None
    return _finding(
        "PWN-DYNLOAD-001", "Dynamic library/symbol resolution present", "low", "medium",
        ["parsed import: %s" % name for name in present],
        "If challenge input can influence the loaded library or resolved symbol name, this is a code-execution or GOT-hijack primitive; otherwise it is benign platform plumbing.",
        ["Trace the library/symbol name argument to its source.", "Check allowlists on the resolved names."],
        "Use fixed library paths and validate resolved symbol names against an allowlist.",
    )


def _check_syscall_filter(info: BinaryInfo) -> Optional[Finding]:
    """Static binaries that install seccomp rules restrict ret2syscall/ROP gadgets."""

    if info.format != "ELF" or info.metadata.get("dynamic") is not False:
        return None
    present = sorted(set(info.imports) & SECCOMP_APIS, key=str.lower)
    if not present:
        return None
    return _finding(
        "PWN-SYSCALL-001", "Syscall filtering may constrain ROP", "info", "medium",
        ["static binary references: %s" % name for name in present],
        "If a seccomp filter is installed at runtime, syscall-based gadgets (execve/open/read/write) may be blocked; prefer gadgets that stay within the allowed syscall set.",
        ["Confirm in a debugger which syscalls the filter allows (SECCOMP_RET_ALLOW vs KILL)."],
        "Not a vulnerability: keep the filter allowlist minimal and documented.",
    )


def _scanf_call_is_bounded(call: dict, format_index: int) -> bool:
    format_arg = _call_argument(call, format_index)
    format_str = format_arg.get("string") if format_arg.get("kind") == "address_constant" else None
    if not isinstance(format_str, str) or not format_str:
        return False
    dest_index = format_index + 1
    for match in SCANF_SPEC_RE.finditer(format_str.replace("%%", "")):
        suppressed, width_text, conversion = match.groups()
        if suppressed:
            continue
        if conversion in {"s", "["}:
            if not width_text:
                return False
            width = int(width_text)
            dest = _call_argument(call, dest_index)
            capacity = dest.get("buffer_size") or dest.get("return_address_offset")
            if isinstance(capacity, int) and capacity > 0 and width + 1 > capacity:
                return False
        dest_index += 1
    return True


def _bounded_scanf_imports(ghidra_calls: Sequence[dict]) -> set[str]:
    calls_by_name: dict[str, list[dict]] = {}
    for call in ghidra_calls:
        name = _call_name(call)
        if name in SCANF_FORMAT_INDEX:
            calls_by_name.setdefault(name, []).append(call)
    return {
        name for name, matching in calls_by_name.items()
        if all(_scanf_call_is_bounded(call, SCANF_FORMAT_INDEX[name]) for call in matching)
    }


def _check_unbounded_writes(info: BinaryInfo, imports: set[str], parsed_imports: set[str], string_hints: set[str], ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    bounded_scanf = _bounded_scanf_imports(ghidra_calls)
    dangerous = sorted(
        (name for name in imports & set(UNBOUNDED) if _strip_underscores(name) not in bounded_scanf),
        key=str.lower,
    )
    if not dangerous:
        return None
    dangerous_set = set(dangerous) | {_strip_underscores(name) for name in dangerous}
    proven = sorted(dangerous_set & parsed_imports, key=str.lower)
    hints = sorted(dangerous_set & string_hints, key=str.lower)
    callsites = [item for item in ghidra_calls if _call_name(item) in dangerous_set]
    reasons = (
        ["parsed import: %s (%s)" % (name, UNBOUNDED[name]) for name in proven]
        + ["unverified string hint: %s" % name for name in hints]
        + ["Ghidra reference: %s in %s -> %s" % (item.get("from"), item.get("function") or UNKNOWN, item.get("to")) for item in callsites]
    )
    nx = info.mitigations.get("nx")
    canary = info.mitigations.get("stack_canary")
    if canary is False and nx is False:
        vector = "Find the overwrite offset, control the return address, then jump to injected stack data or a win function."
    elif canary is False:
        vector = "Find the overwrite offset, control the return address, then build a ROP/ret2libc chain or jump to a win function."
    else:
        vector = "Trace attacker-controlled lengths to the destination. If a stack canary blocks return-address control, target adjacent data or leak the canary first."
    if callsites and "gets" in proven:
        level = "high"
    elif proven:
        level = "medium"
    else:
        level = "low"
    return _finding(
        "PWN-BOF-001", "Unbounded memory-write surface", level, level, reasons, vector,
        ["Inspect each call site and destination size.", "Generate a cyclic pattern in an isolated challenge runner.", "Confirm control of saved state with a debugger."],
        "Replace unbounded calls with length-aware APIs and reject input larger than the destination.",
    )


def _format_input_sources(ghidra_calls: Sequence[dict]) -> dict[int, str]:
    """Map id() of a dynamic format call to evidence of the input call filling its format buffer."""
    fillers: list[tuple[str, str, dict]] = []
    for call in ghidra_calls:
        name = _call_name(call)
        if name in INPUT_FILLERS:
            dest = _call_argument(call, INPUT_FILLERS[name])
            identity = _argument_identity(dest)
            if identity is not None:
                fillers.append((str(call.get("function") or UNKNOWN), identity, call))
    sources: dict[int, str] = {}
    for call in ghidra_calls:
        if _call_name(call) not in FORMAT_INDEXES:
            continue
        argument = _call_argument(call, FORMAT_INDEXES[_call_name(call)])
        if not _dynamic_argument(argument):
            continue
        identity = _argument_identity(argument)
        if identity is None:
            continue
        function = str(call.get("function") or UNKNOWN)
        for filler_function, filler_identity, filler_call in fillers:
            if filler_function == function and filler_identity == identity:
                length = _call_argument(filler_call, 2).get("value") if _call_name(filler_call) in {"read", "recv", "recvfrom"} else None
                detail = " (%d bytes)" % length if isinstance(length, int) else ""
                sources[id(call)] = (
                    "format argument at %s is the buffer filled by %s at %s%s"
                    % (call.get("from"), _call_name(filler_call), filler_call.get("from"), detail)
                )
                break
    return sources


def _check_format_strings(info: BinaryInfo, imports: set[str], parsed_imports: set[str], ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    dynamic_format_calls = [
        call for call in ghidra_calls
        if _call_name(call) in FORMAT_INDEXES and _dynamic_argument(_call_argument(call, FORMAT_INDEXES[_call_name(call)]))
    ]
    if dynamic_format_calls:
        sources = _format_input_sources(ghidra_calls)
        call_evidence = [
            "dynamic format argument at %s in %s -> %s" % (item.get("from"), item.get("function") or UNKNOWN, item.get("to"))
            for item in dynamic_format_calls
        ]
        call_evidence.extend(sources[id(item)] for item in dynamic_format_calls if id(item) in sources)
        vector = "Send `%p.%p.%p` to confirm pointer disclosure. If the same input reaches `%n`, use a positional write only after mapping the argument index in the isolated CTF runner."
        if info.format == "ELF" and info.metadata.get("relro") in {"none", "partial"}:
            vector += " Full RELRO is off, so the GOT remains a writable `%n` target."
        elif not info.mitigations.get("pie" if info.format in {"ELF", "Mach-O"} else "aslr"):
            vector += " Code and writable data are at fixed addresses, giving `%n` a deterministic target."
        return _finding(
            "PWN-FMT-001", "Attacker-reachable dynamic format candidate", "high", "high", call_evidence,
            vector,
            ["Compare output for a literal marker and `%p.%p.%p`.", "Confirm the decompiled format argument comes from challenge input."],
            "Pass a constant format such as `%s` and move the dynamic value to a separate argument.",
        )
    parsed_format = sorted(imports & FORMAT_SINKS & parsed_imports, key=str.lower)
    format_clues = sorted(value for value in info.strings if "%n" in value or re.search(r"%\d+\$[pxsn]", value))[:8]
    if parsed_format and format_clues:
        return _finding(
            "PWN-FMT-001", "Format-string review required", "medium", "low",
            ["parsed format sink: %s" % item for item in parsed_format] + ["format token in binary: %s" % item for item in format_clues],
            "Supply positional format specifiers to map the stack. Use reads to disclose pointers or a controlled %n write if the program passes user data as the format string.",
            ["Decompile each sink call and identify the format argument.", "Check whether input reaches that argument unchanged."],
            "Pass a constant format string and provide user data through a value argument.",
        )
    return None


def _has_dynamic_command_argument(call: dict) -> bool:
    name = _call_name(call)
    if name not in COMMAND_SINKS:
        return False
    if name in VARARG_COMMAND_SINKS:
        arguments = call.get("arguments")
        return isinstance(arguments, list) and any(isinstance(arg, dict) and _dynamic_argument(arg) for arg in arguments)
    return any(_dynamic_argument(_call_argument(call, index)) for index in COMMAND_ARG_INDEXES.get(name, (0,)))


def _check_command_sinks(parsed_imports: set[str], ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    dynamic_command_calls = [item for item in ghidra_calls if _has_dynamic_command_argument(item)]
    if dynamic_command_calls:
        return _finding(
            "PWN-CMD-001", "Dynamic command execution candidate", "high", "high",
            ["dynamic command at %s in %s -> %s" % (item.get("from"), item.get("function") or UNKNOWN, item.get("to")) for item in dynamic_command_calls],
            "The decompiler recovered a non-constant command argument. Preserve the known prefix and test a shell separator followed by `cat /flag` only inside the authorized challenge runner.",
            ["Inspect how input reaches the command argument.", "Record quoting, allowlists and the invoked shell before choosing a separator."],
            "Avoid shell command construction. Use fixed executable paths and validated argument arrays.",
        )
    commands = sorted(parsed_imports & COMMAND_SINKS, key=str.lower)
    if commands:
        return _finding(
            "PWN-CMD-001", "Command execution sink requires data-flow review", "low", "low",
            ["parsed command sink without proven dynamic argument: %s" % name for name in commands],
            "Inspect the command argument. Build a flag-read probe only if challenge input reaches it after quoting and validation.",
            ["Decompile the sink call and trace argument zero."],
            "Keep the executable and argument vector constant or validate each token against an allowlist.",
        )
    return None


def _win_address_note(info: BinaryInfo, win_symbols: Sequence[str], symbol_addresses: dict) -> str:
    addressed = [(name, symbol_addresses[name]) for name in win_symbols if name in symbol_addresses]
    if addressed:
        chosen_name, chosen_address = addressed[0]
        pack = "p64" if info.bits == 64 else "p32"
        target = "image-relative offset" if info.mitigations.get("pie") else "virtual address"
        return "%s %s=0x%x; scaffold: payload = b\"A\" * OFFSET + %s(0x%x)." % (target, chosen_name, chosen_address, pack, chosen_address)
    if info.mitigations.get("pie"):
        return "PIE requires a code-pointer leak or relative transfer."
    return "Resolve the routine address before building ret2win."


def _flag_output_notes(calls: Sequence[dict]) -> tuple[list[str], str]:
    """Structural correlation: open(flag path) whose fd reaches an output sink.

    Requires a call-result descriptor (expression op CALL), so a plain
    write(1, ...) to stdout never produces a note.
    """
    notes: list[str] = []
    flag_opens = _flag_open_calls(calls)
    if not flag_opens:
        return notes, ""
    for call in calls:
        name = _call_name(call)
        if name not in FLAG_FD_SINKS:
            continue
        function = str(call.get("function") or UNKNOWN)
        opens = flag_opens.get(function)
        if not opens:
            continue
        descriptor = _call_argument(call, FLAG_FD_SINKS[name])
        if descriptor.get("kind") != "dynamic" or "CALL" not in _expression_ops(descriptor):
            continue
        for open_call, path in opens:
            notes.append(
                "flag file %r opened at %s in %s; its descriptor is passed to %s argument %d at %s (candidate flag output)"
                % (path, open_call.get("from"), function, name, FLAG_FD_SINKS[name], call.get("from"))
            )
    notes = sorted(set(notes), key=str.lower)
    flag_path = ""
    if notes:
        flag_path = (
            "Candidate flag output path: %s. Reach the branch that performs the output after the flag file is opened."
            % notes[0]
        )
    return notes, flag_path


def _check_win_paths(info: BinaryInfo, bounded: Sequence[dict], symbols: set[str], symbol_addresses: dict, flag_output: Sequence[str] = (), flag_output_path: str = "") -> List[Finding]:
    findings: List[Finding] = []
    win_symbols = sorted(name for name in symbols if WIN_NAMES.search(name))
    win_strings = sorted((value for value in info.strings if FLAG_TEXT.search(value)), key=str.lower)[:12]
    exact_chain = _exact_ret2win(info, bounded, win_symbols, symbol_addresses)
    if exact_chain is not None:
        findings.append(exact_chain)
    if win_symbols or win_strings or flag_output:
        address_note = _win_address_note(info, win_symbols, symbol_addresses)
        findings.append(_finding(
            "PWN-WIN-001", "Hidden success path or flag material", "medium", "high" if win_symbols else "medium",
            ["symbol: %s" % name for name in win_symbols] + ["string: %s" % value for value in win_strings] + list(flag_output),
            "Reach the success routine through a corrupted return address, function pointer, or intended state transition. " + address_note,
            ["Cross-reference each clue.", "List callers and guard conditions for candidate success routines."],
            "Remove dormant privileged paths and keep secrets outside the challenge binary in production software.",
            flag_path=flag_output_path or "Manual confirmation required before a flag-recovery payload exists.",
        ))
    return findings


def _check_mitigations(info: BinaryInfo) -> Optional[Finding]:
    missing = [name for name in ("nx", "stack_canary", "pie" if info.format in {"ELF", "Mach-O"} else "aslr") if info.mitigations.get(name) is False]
    if info.format == "ELF" and info.metadata.get("relro") in {"none", "partial"}:
        missing.append("full_relro")
    if info.format == "ELF" and info.mitigations.get("fortify") is False:
        missing.append("fortify_source")
    if info.format == "PE" and info.mitigations.get("cfg") is False:
        missing.append("cfg")
    if not missing:
        return None
    return _finding(
        "PWN-MIT-001", "Exploit mitigations disabled", "medium", "high",
        ["%s disabled" % name for name in sorted(missing)],
        "Use the missing mitigations to simplify an existing memory-corruption vector: fixed code addresses help ROP, no canary helps stack overwrite, and executable memory helps shellcode.",
        ["Confirm loader policy on the challenge host.", "Pair this finding with a controllable corruption primitive."],
        "Enable compiler and linker hardening: stack protector, non-executable memory, PIE/ASLR, RELRO, and platform control-flow protection.",
    )


def _collect_file_stream_identities(ghidra_calls: Sequence[dict]) -> tuple[set[tuple[str, str]], set[str]]:
    local_streams: set[tuple[str, str]] = set()
    global_streams: set[str] = set()
    for call in ghidra_calls:
        name = _call_name(call)
        indexes = FILE_STREAM_ARGS.get(name, set())
        if not indexes:
            continue
        function = str(call.get("function") or UNKNOWN)
        for index in indexes:
            argument = _call_argument(call, index)
            identity = _argument_identity(argument)
            if identity is None:
                continue
            local_streams.add((function, identity))
            repr_text = argument.get("repr")
            if identity.startswith("high:"):
                global_streams.add(identity)
            if isinstance(repr_text, str) and repr_text.startswith("(ram,"):
                global_streams.add("repr:%s" % repr_text)
    return local_streams, global_streams


def _is_file_stream_argument(argument: dict, function: str, local_streams: set[tuple[str, str]], global_streams: set[str]) -> bool:
    if argument.get("high_name") in STANDARD_FILE_STREAMS:
        return True
    identity = _argument_identity(argument)
    if identity is not None and ((function, identity) in local_streams or identity in global_streams):
        return True
    repr_text = argument.get("repr")
    return isinstance(repr_text, str) and ("repr:%s" % repr_text) in global_streams


def _check_file_streams(ghidra_calls: Sequence[dict]) -> Optional[Finding]:
    local_streams, global_streams = _collect_file_stream_identities(ghidra_calls)
    evidence: list[str] = []
    closed: dict[tuple[str, str], dict] = {}
    for call in sorted(ghidra_calls, key=_call_position):
        name = _call_name(call)
        function = str(call.get("function") or UNKNOWN)
        if name in FILE_WRITE_DESTS:
            dst = _call_argument(call, FILE_WRITE_DESTS[name])
            if _is_file_stream_argument(dst, function, local_streams, global_streams):
                label = dst.get("high_name") if dst.get("high_name") not in {None, "UNNAMED", "null"} else (_argument_identity(dst) or "FILE*")
                evidence.append("Ghidra call %s at %s in %s writes into FILE stream %s" % (name, call.get("from"), function, label))
        if name == "fclose":
            identity = _argument_identity(_call_argument(call, 0))
            if identity is not None:
                closed.setdefault((function, identity), call)
        elif name in FILE_STREAM_ARGS and name not in {"setbuf", "setvbuf"}:
            for index in FILE_STREAM_ARGS[name]:
                identity = _argument_identity(_call_argument(call, index))
                previous = closed.get((function, identity or ""))
                if previous is not None:
                    evidence.append("%s uses FILE stream %s in %s at %s after fclose at %s" % (name, identity, function, call.get("from"), previous.get("from")))
    if not evidence:
        return None
    return _finding(
        "PWN-FILE-001", "Input or write targets a FILE stream structure", "high", "high", evidence,
        "Inspect what fields of the _IO_FILE structure can be overwritten (flags, _IO_read_*/_IO_write_*, _fileno, or vtable/wide_data) before subsequent stdio calls flush or close the stream.",
        ["Verify in a debugger whether attacker bytes overwrite the live FILE structure.", "Check glibc version and vtable pointer validation before testing FSOP primitives."],
        "Read untrusted input into a dedicated byte buffer rather than a FILE structure, and clear FILE pointers immediately after fclose.",
    )


def analyze(info: BinaryInfo) -> List[Finding]:
    imports = set(info.imports)
    symbols = set(info.symbols)
    parsed_imports = set(info.metadata.get("parsed_imports", []))
    string_hints = set(info.metadata.get("string_import_hints", []))
    symbol_addresses = info.metadata.get("symbol_addresses", {})
    ghidra_calls = info.metadata.get("ghidra", {}).get("calls", [])
    bounded = _bounded_overflows(ghidra_calls)
    boundary = _boundary_writes(ghidra_calls)

    candidates: List[Optional[Finding]] = [
        _check_bounded_overflows(bounded),
        _check_boundary_writes(boundary),
        _check_integer_allocations(ghidra_calls),
        _check_division(ghidra_calls),
        _check_width_conversions(ghidra_calls),
        _check_unbounded_writes(info, imports, parsed_imports, string_hints, ghidra_calls),
        _check_format_strings(info, imports, parsed_imports, ghidra_calls),
        _check_file_streams(ghidra_calls),
        _check_command_sinks(parsed_imports, ghidra_calls),
        _check_syscall_filter(info),
        _check_dynamic_loading(parsed_imports),
        _check_mitigations(info),
    ]
    findings: List[Finding] = [item for item in candidates if item is not None]
    findings.extend(_check_indirect_calls(ghidra_calls))
    findings.extend(_check_heap_lifetime(ghidra_calls))
    flag_output, flag_output_path = _flag_output_notes(ghidra_calls)
    findings.extend(_check_win_paths(info, bounded, symbols, symbol_addresses, flag_output, flag_output_path))

    rwx_sections = list(info.metadata.get("rwx_sections", []))
    if rwx_sections:
        findings.append(_finding(
            "PWN-RWX-001", "Writable executable memory", "medium", "high",
            ["writable executable section: %s" % name for name in rwx_sections],
            "Place staged code in the reported region only after proving an attacker-controlled write and control transfer.",
            ["Confirm section permissions in the challenge loader.", "Pair this enabler with a proven write primitive."],
            "Remove execute permission from writable sections and enforce W^X in the linker and loader.",
        ))

    gadgets = info.metadata.get("gadgets", {})
    useful_strings = info.metadata.get("useful_strings", {})
    if gadgets or useful_strings:
        evidence = (
            ["%s: %s" % (name, ", ".join("0x%x" % value for value in addresses[:3])) for name, addresses in sorted(gadgets.items())]
            + ["string %r: %s" % (value, ", ".join("0x%x" % address for address in addresses)) for value, addresses in sorted(useful_strings.items())]
        )
        findings.append(_finding(
            "PWN-ROP-001", "Addressed exploit primitives", "info", "high", evidence,
            "Use only primitives compatible with the architecture and mitigations. PIE addresses are image-relative until a base leak is known.",
            ["Validate instruction boundaries in a disassembler.", "Rebase addresses when PIE or ASLR is active."],
            "Reduce gadget density through control-flow protection; remove embedded command strings when unnecessary.",
        ))

    if not findings:
        findings.append(_finding(
            "PWN-TRIAGE-000", "No high-signal static primitive found", "info", "high", [],
            "Review input parsing, integer arithmetic, state transitions, and indirect calls in a decompiler. Static triage cannot prove safety.",
            ["Map all input sources to memory writes.", "Inspect comparisons around flag and success strings."],
            "Apply bounds checks and hardening after manual review identifies the trust boundary.",
        ))
    return sorted(findings, key=lambda finding: (SEVERITY_ORDER[finding.severity], finding.id, tuple(finding.evidence)))


def scan_bytes(data: bytes, target: str = "<memory>") -> ScanReport:
    info = parse_binary(data)
    return ScanReport("pwnscan/v1", target, hashlib.sha256(data).hexdigest(), len(data), info, analyze(info))


_AUTO_LABEL_RE = re.compile(r"^(?:FUN|DAT|LAB|SUB|EXT)_([0-9a-fA-F]+)$")


def _resolve_candidate_addresses(call: dict, ghidra_base: int) -> List[int]:
    candidates: List[int] = []
    current_to = call.get("to")
    if isinstance(current_to, str):
        match = _AUTO_LABEL_RE.match(current_to)
        if match:
            candidates.append(int(match.group(1), 16))
    target = call.get("target")
    repr_text = target.get("repr") if isinstance(target, dict) else None
    if isinstance(repr_text, str):
        match = re.search(r"\(ram,\s*0x([0-9a-fA-F]+)", repr_text)
        if match:
            candidates.append(int(match.group(1), 16))
    addresses: List[int] = []
    for addr in candidates:
        addresses.append(addr)
        if ghidra_base and addr >= ghidra_base:
            addresses.append(addr - ghidra_base)
    return addresses


def _resolve_call_target(call: dict, plt_addresses: dict, ghidra_base: int) -> None:
    current_to = call.get("to")
    if isinstance(current_to, str) and current_to and not _AUTO_LABEL_RE.match(current_to):
        return
    for addr in _resolve_candidate_addresses(call, ghidra_base):
        addr_key = "0x%x" % addr
        if addr_key in plt_addresses:
            call["to"] = plt_addresses[addr_key]
            return


def _resolve_ghidra_calls(calls: Sequence[object], plt_addresses: dict, ghidra_base: int = 0) -> List[dict]:
    resolved: List[dict] = []
    for item in calls:
        if not isinstance(item, dict):
            continue
        call = dict(item)
        if plt_addresses:
            _resolve_call_target(call, plt_addresses, ghidra_base)
        resolved.append(call)
    return sorted(resolved, key=lambda item: (str(item.get("to", "")), str(item.get("from", ""))))


def _fill_missing_strings(resolved_calls: Sequence[dict], string_addresses: object, ghidra_base: int) -> None:
    if not isinstance(string_addresses, dict) or not string_addresses:
        return
    address_to_string: dict[int, str] = {}
    for text, addresses in string_addresses.items():
        if isinstance(text, str) and isinstance(addresses, list):
            for address in addresses:
                if isinstance(address, int):
                    address_to_string[address] = text
    if not address_to_string:
        return
    for call in resolved_calls:
        arguments = call.get("arguments")
        if not isinstance(arguments, list):
            continue
        updated_args = None
        for index, argument in enumerate(arguments):
            if not isinstance(argument, dict) or argument.get("kind") != "address_constant" or argument.get("string"):
                continue
            try:
                address = int(str(argument.get("address")), 16)
            except (TypeError, ValueError):
                continue
            candidates = [address]
            if ghidra_base and address >= ghidra_base:
                candidates.append(address - ghidra_base)
            for candidate in candidates:
                if candidate in address_to_string:
                    if updated_args is None:
                        updated_args = list(arguments)
                    updated_args[index] = {**argument, "string": address_to_string[candidate]}
                    break
        if updated_args is not None:
            call["arguments"] = updated_args


def _merge_ghidra(info: BinaryInfo, export_path: Path) -> BinaryInfo:
    try:
        payload = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid Ghidra export: %s" % exc) from exc
    if payload.get("schema") != "pwnscan-ghidra/v1":
        raise ValueError("invalid Ghidra export schema")
    functions = payload.get("functions")
    imports = payload.get("imports")
    calls = payload.get("calls", [])
    if not isinstance(functions, list) or not isinstance(imports, list) or not isinstance(calls, list):
        raise ValueError("invalid Ghidra export structure")
    function_names = {item.get("name") for item in functions if isinstance(item, dict) and isinstance(item.get("name"), str)}
    clean_imports = {_normalize_import_name(value) for value in imports if isinstance(value, str)}
    metadata = dict(info.metadata)
    addresses = dict(metadata.get("symbol_addresses", {}))
    for item in functions:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("entry"), str):
            continue
        try:
            addresses[item["name"]] = int(item["entry"], 16)
        except ValueError:
            continue
    metadata["symbol_addresses"] = {name: addresses[name] for name in sorted(addresses, key=str.lower)}
    if "function_symbols" in metadata or function_names:
        merged_funcs = set(metadata.get("function_symbols", [])) | function_names
        metadata["function_symbols"] = sorted(merged_funcs, key=lambda value: (value.lower(), value))
    plt_addresses = metadata.get("plt_addresses", {})
    ghidra_base = 0
    if isinstance(payload.get("image_base"), str):
        try:
            ghidra_base = int(payload["image_base"], 16)
        except ValueError:
            ghidra_base = 0
    resolved_calls = _resolve_ghidra_calls(calls, plt_addresses if isinstance(plt_addresses, dict) else {}, ghidra_base)
    _fill_missing_strings(resolved_calls, metadata.get("string_addresses"), ghidra_base)
    metadata["ghidra"] = {
        "language": payload.get("language"),
        "image_base": payload.get("image_base"),
        "calls": resolved_calls,
    }
    metadata["parsed_imports"] = sorted(set(metadata.get("parsed_imports", [])) | clean_imports, key=str.lower)
    return BinaryInfo(
        format=info.format,
        bits=info.bits,
        endian=info.endian,
        architecture=info.architecture,
        entrypoint=info.entrypoint,
        image_base=info.image_base,
        imports=sorted(set(info.imports) | clean_imports, key=str.lower),
        symbols=sorted(set(info.symbols) | function_names, key=lambda value: (value.lower(), value)),
        strings=info.strings,
        mitigations=info.mitigations,
        metadata=metadata,
    )


def scan_file(path: Path, ghidra_export: Optional[Path] = None) -> ScanReport:
    data = path.read_bytes()
    info = parse_binary(data)
    if ghidra_export is not None:
        info = _merge_ghidra(info, ghidra_export)
    return ScanReport("pwnscan/v1", str(path), hashlib.sha256(data).hexdigest(), len(data), info, analyze(info))
