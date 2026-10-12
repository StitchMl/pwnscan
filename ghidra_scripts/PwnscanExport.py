# PwnscanExport.py
# @category CTF
# @menupath Tools.CTF.Pwnscan Export

"""Export deterministic Ghidra metadata for correlation with pwnscan."""

import json


def collect(program):
    listing = program.getListing()
    functions = []
    iterator = listing.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        functions.append({
            "entry": str(function.getEntryPoint()),
            "name": function.getName(),
            "thunk": bool(function.isThunk()),
        })

    imports = []
    calls = []
    symbols = program.getSymbolTable().getExternalSymbols()
    while symbols.hasNext():
        symbol = symbols.next()
        imports.append(symbol.getName(True))
        references = program.getReferenceManager().getReferencesTo(symbol.getAddress())
        while references.hasNext():
            reference = references.next()
            source = listing.getFunctionContaining(reference.getFromAddress())
            calls.append({
                "from": str(reference.getFromAddress()),
                "function": source.getName() if source else None,
                "to": symbol.getName(True),
                "type": str(reference.getReferenceType()),
            })

    return {
        "schema": "pwnscan-ghidra/v1",
        "program": program.getName(),
        "language": str(program.getLanguageID()),
        "image_base": str(program.getImageBase()),
        "functions": sorted(functions, key=lambda item: (item["name"].lower(), item["entry"])),
        "imports": sorted(set(imports), key=lambda value: (value.lower(), value)),
        "calls": sorted(calls, key=lambda item: (item["to"].lower(), item["from"])),
    }


output = askFile("Save pwnscan Ghidra export", "Save")
payload = collect(currentProgram)
handle = open(output.getAbsolutePath(), "w")
try:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
finally:
    handle.close()
print("pwnscan metadata: " + output.getAbsolutePath())
