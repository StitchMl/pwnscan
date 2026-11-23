# PwnscanExport.py
# @category CTF
# @menupath Tools.CTF.Pwnscan Export

"""Export deterministic call and P-code argument facts for pwnscan."""

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import Array, Structure, TypeDef
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import ExternalReference
from java.io import File


def _signed(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _stack_offset(program, varnode, seen=None):
    if varnode is None:
        return None
    if seen is None:
        seen = set()
    key = str(varnode)
    if key in seen:
        return None
    seen.add(key)
    address = varnode.getAddress()
    if address is not None and address.isStackAddress():
        return address.getOffset()
    operation = varnode.getDef()
    if operation is None:
        return None
    opcode = operation.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT):
        return _stack_offset(program, operation.getInput(0), seen)
    if opcode in (PcodeOp.PTRSUB, PcodeOp.PTRADD):
        base = operation.getInput(0)
        offset = operation.getInput(1)
        base_address = base.getAddress() if base is not None else None
        base_reg = program.getRegister(base) if base is not None else None
        stack_reg = program.getCompilerSpec().getStackPointer()
        stack_base = (base_address is not None and base_address.isStackAddress()) or (
            base_reg is not None and stack_reg is not None and base_reg == stack_reg
        )
        if offset is not None and offset.isConstant() and stack_base:
            return _signed(offset.getOffset(), offset.getSize() * 8)
        return _stack_offset(program, base, seen)
    if opcode == PcodeOp.MULTIEQUAL:
        values = set(_stack_offset(program, operation.getInput(i), set(seen)) for i in range(operation.getNumInputs()))
        values.discard(None)
        return values.pop() if len(values) == 1 else None
    return None


def _constant_address_value(varnode, seen=None):
    if varnode is None:
        return None
    if seen is None:
        seen = set()
    key = str(varnode)
    if key in seen:
        return None
    seen.add(key)
    if varnode.isConstant():
        return varnode.getOffset()
    operation = varnode.getDef()
    if operation is None:
        return None
    opcode = operation.getOpcode()
    if opcode in (PcodeOp.COPY, PcodeOp.CAST):
        return _constant_address_value(operation.getInput(0), seen)
    if opcode == PcodeOp.PTRSUB and operation.getNumInputs() >= 2:
        base = operation.getInput(0)
        offset = operation.getInput(1)
        if base is not None and base.isConstant() and base.getOffset() == 0 and offset is not None and offset.isConstant():
            return offset.getOffset()
    return None


def _expression(varnode, depth=0, seen=None):
    if varnode is None or depth >= 5:
        return None
    if seen is None:
        seen = set()
    key = str(varnode)
    if key in seen:
        return None
    seen.add(key)
    operation = varnode.getDef()
    if operation is None:
        return None
    inputs = []
    for index in range(operation.getNumInputs()):
        node = operation.getInput(index)
        child = {"kind": "constant", "value": node.getOffset(), "size": node.getSize()} if node.isConstant() else {
            "kind": "dynamic", "repr": str(node), "size": node.getSize()
        }
        nested = _expression(node, depth + 1, set(seen))
        if nested is not None:
            child["expression"] = nested
        inputs.append(child)
    return {"op": operation.getMnemonic(), "size": varnode.getSize(), "inputs": inputs}


def _read_ascii_string(program, address):
    chars = []
    try:
        for index in range(256):
            value = program.getMemory().getByte(address.add(index)) & 0xFF
            if value == 0:
                return "".join(chars) if chars else None
            if (value < 0x20 or value > 0x7E) and value not in (9, 10, 13):
                return None
            chars.append(chr(value))
    except Exception:
        return None
    return None


def _argument(program, function, varnode):
    item = {"kind": "dynamic", "repr": str(varnode), "size": varnode.getSize()}
    const_value = _constant_address_value(varnode)
    if const_value is not None:
        item.update({"kind": "constant", "value": const_value})
        try:
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(const_value)
            block = program.getMemory().getBlock(address)
            if block is not None:
                item.update({"kind": "address_constant", "address": str(address), "block": block.getName(), "writable": bool(block.isWrite()), "executable": bool(block.isExecute())})
                if not block.isWrite():
                    text = _read_ascii_string(program, address)
                    if text is not None:
                        item["string"] = text
        except Exception:
            pass
    offset = _stack_offset(program, varnode)
    if offset is not None:
        item.update({"kind": "stack", "stack_offset": offset})
        try:
            return_address = function.getStackFrame().getReturnAddressOffset()
            overwrite_offset = return_address - offset
            if overwrite_offset > 0:
                item["return_address_offset"] = overwrite_offset
            variable = function.getStackFrame().getVariableContaining(offset)
            if variable is not None:
                item["variable"] = variable.getName()
                data_type = variable.getDataType()
                while isinstance(data_type, TypeDef):
                    data_type = data_type.getBaseDataType()
                if isinstance(data_type, (Array, Structure)):
                    remaining = (variable.getStackOffset() + variable.getLength()) - offset
                    if remaining > 0:
                        item["buffer_size"] = remaining
        except Exception:
            pass
    try:
        high = varnode.getHigh()
        if high is not None:
            item["high_name"] = high.getName()
    except Exception:
        pass
    expression = _expression(varnode)
    if expression is not None:
        item["expression"] = expression
    return item


def _resolve_address_name(program, address):
    if address is None:
        return None
    function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        function = program.getFunctionManager().getFunctionContaining(address)
    if function is not None:
        return function.getName()
    symbol = program.getSymbolTable().getPrimarySymbol(address)
    return symbol.getName() if symbol is not None else None


def _target_name(program, operation):
    target = operation.getInput(0)
    if target is not None:
        address = target.getAddress()
        if target.isConstant():
            try:
                address = program.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset())
            except Exception:
                address = None
        resolved = _resolve_address_name(program, address)
        if resolved is not None:
            return resolved
    call_site = operation.getSeqnum().getTarget()
    for ref in program.getReferenceManager().getReferencesFrom(call_site):
        if not ref.getReferenceType().isCall():
            continue
        if isinstance(ref, ExternalReference):
            return ref.getExternalLocation().getLabel()
        resolved = _resolve_address_name(program, ref.getToAddress())
        if resolved is not None:
            return resolved
    return None


def _return_var(output):
    if output is None:
        return None
    item = {"repr": str(output), "size": int(output.getSize())}
    try:
        if output.getHigh() is not None:
            item["high_name"] = output.getHigh().getName()
    except Exception:
        pass
    return item


def _var_identity(node):
    if node is None or node.isConstant():
        return None
    try:
        if node.getHigh() is not None and node.getHigh().getName():
            high_name = node.getHigh().getName()
            if high_name not in ("UNNAMED", "null"):
                return "high:" + high_name
    except Exception:
        pass
    return "repr:" + str(node)


def _function_cfg(high):
    blocks = {}
    for bb in high.getBasicBlocks():
        succs = [int(bb.getOut(i).getIndex()) for i in range(bb.getOutSize())]
        blocks[str(bb.getIndex())] = succs
    guards = []
    ops = high.getPcodeOps()
    cmp_ops = {PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL}
    unwrap_ops = {PcodeOp.BOOL_NEGATE, PcodeOp.COPY, PcodeOp.CAST}
    while ops.hasNext():
        op = ops.next()
        if op.getOpcode() != PcodeOp.CBRANCH or op.getParent() is None or op.getNumInputs() < 2:
            continue
        cond = op.getInput(1)
        for _ in range(4):
            if cond is None or cond.getDef() is None or cond.getDef().getOpcode() not in unwrap_ops:
                break
            cond = cond.getDef().getInput(0)
        cmp_def = cond.getDef() if cond is not None else None
        if cmp_def is None or cmp_def.getNumInputs() < 2 or cmp_def.getOpcode() not in cmp_ops:
            continue
        for i in range(2):
            vid = _var_identity(cmp_def.getInput(i))
            if vid is not None:
                guards.append({"block": int(op.getParent().getIndex()), "op": cmp_def.getMnemonic(), "var": vid})
    cfg = {"blocks": blocks}
    if guards:
        cfg["guards"] = guards
    return cfg


def _decompiled_calls(program, monitor):
    interface = DecompInterface()
    try:
        interface.openProgram(program)
        result = []
        cfg = {}
        iterator = program.getFunctionManager().getFunctions(True)
        while iterator.hasNext() and not monitor.isCancelled():
            function = iterator.next()
            if function.isThunk():
                continue
            block = program.getMemory().getBlock(function.getEntryPoint())
            if block is not None and block.getName().startswith(".plt"):
                continue
            completed = interface.decompileFunction(function, 30, monitor)
            high = completed.getHighFunction() if completed is not None and completed.decompileCompleted() else None
            if high is None:
                continue
            cfg[function.getName()] = _function_cfg(high)
            operations = high.getPcodeOps()
            while operations.hasNext():
                operation = operations.next()
                if operation.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                    continue
                arguments = [_argument(program, function, operation.getInput(index)) for index in range(1, operation.getNumInputs())]
                entry = {
                    "from": str(operation.getSeqnum().getTarget()), "function": function.getName(),
                    "order": int(operation.getSeqnum().getOrder()),
                    "to": _target_name(program, operation), "indirect": operation.getOpcode() == PcodeOp.CALLIND,
                    "target": _argument(program, function, operation.getInput(0)), "arguments": arguments,
                }
                if operation.getParent() is not None:
                    entry["block"] = int(operation.getParent().getIndex())
                ret = _return_var(operation.getOutput())
                if ret is not None:
                    entry["return_var"] = ret
                result.append(entry)
        return result, cfg
    finally:
        interface.dispose()


def collect(program, monitor):
    listing = program.getListing()
    functions = []
    iterator = listing.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        functions.append({"entry": str(function.getEntryPoint()), "name": function.getName(), "thunk": bool(function.isThunk())})
    imports = []
    symbols = program.getSymbolTable().getExternalSymbols()
    while symbols.hasNext():
        imports.append(symbols.next().getName(True))
    calls, cfg = _decompiled_calls(program, monitor)
    # Same ordering as PwnscanExport.java: raw (case-sensitive) to + function + from.
    return {
        "schema": "pwnscan-ghidra/v1", "program": program.getName(),
        "language": str(program.getLanguageID()), "image_base": str(program.getImageBase()),
        "functions": sorted(functions, key=lambda item: (item["name"].lower(), item["entry"])),
        "imports": sorted(set(imports), key=lambda value: (value.lower(), value)),
        "calls": sorted(calls, key=lambda item: (str(item["to"]) + "\0" + item["function"] + "\0" + item["from"])),
        "cfg": cfg,
    }


if currentProgram is None:
    printerr("No program open in CodeBrowser.")
else:
    arguments = getScriptArgs()
    output = File(arguments[0]) if arguments else askFile("Save pwnscan Ghidra export", "Save")
    payload = collect(currentProgram, monitor)
    handle = open(output.getAbsolutePath(), "w", encoding="utf-8")
    try:
        # ensure_ascii=False matches Gson's disableHtmlEscaping output (raw UTF-8).
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    finally:
        handle.close()
    print("pwnscan metadata: " + output.getAbsolutePath())
