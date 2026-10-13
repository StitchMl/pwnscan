# PwnscanExport.py
# @category CTF
# @menupath Tools.CTF.Pwnscan Export

"""Export deterministic call and P-code argument facts for pwnscan."""

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from java.io import File


def _signed(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _stack_offset(varnode, seen=None):
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
        return _stack_offset(operation.getInput(0), seen)
    if opcode in (PcodeOp.PTRSUB, PcodeOp.PTRADD):
        base = operation.getInput(0)
        offset = operation.getInput(1)
        base_address = base.getAddress() if base is not None else None
        if offset is not None and offset.isConstant() and base_address is not None and (base_address.isStackAddress() or "RSP" in str(base).upper() or "ESP" in str(base).upper()):
            return _signed(offset.getOffset(), offset.getSize() * 8)
        return _stack_offset(base, seen)
    if opcode == PcodeOp.MULTIEQUAL:
        values = set(_stack_offset(operation.getInput(i), set(seen)) for i in range(operation.getNumInputs()))
        values.discard(None)
        return values.pop() if len(values) == 1 else None
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


def _argument(program, function, varnode):
    item = {"kind": "dynamic", "repr": str(varnode), "size": varnode.getSize()}
    if varnode.isConstant():
        value = varnode.getOffset()
        item.update({"kind": "constant", "value": value})
        try:
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
            block = program.getMemory().getBlock(address)
            if block is not None:
                item.update({"kind": "address_constant", "address": str(address), "block": block.getName(), "writable": bool(block.isWrite()), "executable": bool(block.isExecute())})
        except Exception:
            pass
    offset = _stack_offset(varnode)
    if offset is not None:
        item.update({"kind": "stack", "stack_offset": offset})
        try:
            return_address = function.getStackFrame().getReturnAddressOffset()
            overwrite_offset = return_address - offset
            if overwrite_offset > 0:
                item["return_address_offset"] = overwrite_offset
            variable = function.getStackFrame().getVariableContaining(offset)
            if variable is not None:
                item.update({"buffer_size": variable.getLength(), "variable": variable.getName()})
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


def _target_name(program, operation):
    target = operation.getInput(0)
    if target is None:
        return None
    address = target.getAddress()
    if target.isConstant():
        try:
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset())
        except Exception:
            return None
    function = program.getFunctionManager().getFunctionAt(address)
    return function.getName() if function is not None else None


def _decompiled_calls(program, monitor):
    interface = DecompInterface()
    interface.openProgram(program)
    result = []
    iterator = program.getFunctionManager().getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        completed = interface.decompileFunction(function, 30, monitor)
        high = completed.getHighFunction() if completed is not None and completed.decompileCompleted() else None
        if high is None:
            continue
        operations = high.getPcodeOps()
        while operations.hasNext():
            operation = operations.next()
            if operation.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue
            arguments = [_argument(program, function, operation.getInput(index)) for index in range(1, operation.getNumInputs())]
            result.append({
                "from": str(operation.getSeqnum().getTarget()), "function": function.getName(),
                "to": _target_name(program, operation), "indirect": operation.getOpcode() == PcodeOp.CALLIND,
                "target": _argument(program, function, operation.getInput(0)), "arguments": arguments,
            })
    interface.dispose()
    return result


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
    calls = _decompiled_calls(program, monitor)
    return {
        "schema": "pwnscan-ghidra/v1", "program": program.getName(),
        "language": str(program.getLanguageID()), "image_base": str(program.getImageBase()),
        "functions": sorted(functions, key=lambda item: (item["name"].lower(), item["entry"])),
        "imports": sorted(set(imports), key=lambda value: (value.lower(), value)),
        "calls": sorted(calls, key=lambda item: (str(item["to"]).lower(), item["function"].lower(), item["from"])),
    }


arguments = getScriptArgs()
output = File(arguments[0]) if arguments else askFile("Save pwnscan Ghidra export", "Save")
payload = collect(currentProgram, monitor)
handle = open(output.getAbsolutePath(), "w")
try:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
finally:
    handle.close()
print("pwnscan metadata: " + output.getAbsolutePath())
