// Export deterministic call and P-code argument facts for pwnscan.
// @category CTF
// @menupath Tools.CTF.Pwnscan Export

import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class PwnscanExport extends GhidraScript {
    private Map<String, Object> expression(Varnode node, int depth, Set<String> seen) {
        if (node == null || depth >= 5 || !seen.add(node.toString())) return null;
        PcodeOp operation = node.getDef();
        if (operation == null) return null;
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("op", operation.getMnemonic());
        result.put("size", node.getSize());
        List<Map<String, Object>> inputs = new ArrayList<>();
        for (int index = 0; index < operation.getNumInputs(); index++) {
            Varnode input = operation.getInput(index);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("kind", input.isConstant() ? "constant" : "dynamic");
            if (input.isConstant()) {
                item.put("value", input.getOffset());
            } else {
                item.put("repr", input.toString());
                try {
                    if (input.getHigh() != null && input.getHigh().getName() != null) {
                        String highName = input.getHigh().getName();
                        if (!highName.isEmpty() && !"UNNAMED".equals(highName) && !"null".equals(highName)) {
                            item.put("high_name", highName);
                        }
                    }
                } catch (RuntimeException ignored) {
                    // High variables are optional decompiler metadata.
                }
            }
            item.put("size", input.getSize());
            Map<String, Object> nested = expression(input, depth + 1, new HashSet<>(seen));
            if (nested != null) item.put("expression", nested);
            inputs.add(item);
        }
        result.put("inputs", inputs);
        return result;
    }

    private long signedConstant(Varnode node) {
        long value = node.getOffset();
        int bits = node.getSize() * 8;
        if (bits > 0 && bits < 64 && (value & (1L << (bits - 1))) != 0) {
            value -= 1L << bits;
        }
        return value;
    }

    private Long baseStackOffset(Program program, Varnode base, Set<String> seen) {
        if (base == null) return null;
        Register baseReg = program.getRegister(base);
        Register stackReg = program.getCompilerSpec().getStackPointer();
        if (baseReg != null && stackReg != null && baseReg.equals(stackReg)) {
            return 0L;
        }
        return stackOffset(program, base, seen);
    }

    private Long stackOffset(Program program, Varnode node, Set<String> seen) {
        if (node == null || !seen.add(node.toString())) return null;
        Address address = node.getAddress();
        if (address != null && address.isStackAddress()) return address.getOffset();
        PcodeOp operation = node.getDef();
        if (operation == null) return null;
        int opcode = operation.getOpcode();
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INDIRECT) {
            return stackOffset(program, operation.getInput(0), seen);
        }
        if (opcode == PcodeOp.PTRSUB && operation.getNumInputs() >= 2) {
            Varnode base = operation.getInput(0);
            Varnode offset = operation.getInput(1);
            if (offset == null || !offset.isConstant()) return null;
            Long baseOff = baseStackOffset(program, base, seen);
            return baseOff == null ? null : baseOff + signedConstant(offset);
        }
        if (opcode == PcodeOp.PTRADD && operation.getNumInputs() >= 3) {
            Varnode base = operation.getInput(0);
            Varnode index = operation.getInput(1);
            Varnode elemSize = operation.getInput(2);
            if (index == null || !index.isConstant() || elemSize == null || !elemSize.isConstant()) return null;
            Long baseOff = baseStackOffset(program, base, seen);
            return baseOff == null ? null : baseOff + signedConstant(index) * elemSize.getOffset();
        }
        if (opcode == PcodeOp.INT_ADD && operation.getNumInputs() >= 2) {
            Varnode lhs = operation.getInput(0);
            Varnode rhs = operation.getInput(1);
            if (rhs != null && rhs.isConstant()) {
                Long baseOff = baseStackOffset(program, lhs, seen);
                return baseOff == null ? null : baseOff + signedConstant(rhs);
            }
            if (lhs != null && lhs.isConstant()) {
                Long baseOff = baseStackOffset(program, rhs, seen);
                return baseOff == null ? null : baseOff + signedConstant(lhs);
            }
            return null;
        }
        if (opcode == PcodeOp.MULTIEQUAL) {
            Set<Long> values = new HashSet<>();
            for (int index = 0; index < operation.getNumInputs(); index++) {
                Long value = stackOffset(program, operation.getInput(index), new HashSet<>(seen));
                if (value != null) values.add(value);
            }
            return values.size() == 1 ? values.iterator().next() : null;
        }
        return null;
    }

    private Long constantAddressValue(Varnode node, Set<String> seen) {
        if (node == null || !seen.add(node.toString())) return null;
        if (node.isConstant()) return node.getOffset();
        PcodeOp operation = node.getDef();
        if (operation == null) return null;
        int opcode = operation.getOpcode();
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
            return constantAddressValue(operation.getInput(0), seen);
        }
        if (opcode == PcodeOp.PTRSUB && operation.getNumInputs() >= 2) {
            Varnode base = operation.getInput(0);
            Varnode offset = operation.getInput(1);
            if (base != null && base.isConstant() && base.getOffset() == 0 && offset != null && offset.isConstant()) {
                return offset.getOffset();
            }
        }
        return null;
    }

    private String readAsciiString(Program program, Address address) {
        StringBuilder builder = new StringBuilder();
        try {
            for (int index = 0; index < 256; index++) {
                byte value = program.getMemory().getByte(address.add(index));
                if (value == 0) {
                    return builder.length() > 0 ? builder.toString() : null;
                }
                int unsigned = value & 0xff;
                if ((unsigned < 0x20 || unsigned > 0x7e) && unsigned != '\t' && unsigned != '\n' && unsigned != '\r') {
                    return null;
                }
                builder.append((char) unsigned);
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private Map<String, Object> argument(Program program, Function function, Varnode node) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("kind", "dynamic");
        item.put("repr", node.toString());
        item.put("size", node.getSize());
        Long constValue = constantAddressValue(node, new HashSet<>());
        if (constValue != null) {
            long value = constValue;
            item.put("kind", "constant");
            item.put("value", value);
            try {
                Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                MemoryBlock block = program.getMemory().getBlock(address);
                if (block != null) {
                    item.put("kind", "address_constant");
                    item.put("address", address.toString());
                    item.put("block", block.getName());
                    item.put("writable", block.isWrite());
                    item.put("executable", block.isExecute());
                    if (!block.isWrite()) {
                        String text = readAsciiString(program, address);
                        if (text != null) item.put("string", text);
                    }
                }
            } catch (RuntimeException ignored) {
                // Preserve the numeric constant when it is not a valid address.
            }
        }
        Long offset = stackOffset(program, node, new HashSet<>());
        if (offset != null) {
            item.put("kind", "stack");
            item.put("stack_offset", offset);
            try {
                int returnAddress = function.getStackFrame().getReturnAddressOffset();
                long overwriteOffset = (long) returnAddress - offset;
                if (overwriteOffset > 0) item.put("return_address_offset", overwriteOffset);
                Variable variable = function.getStackFrame().getVariableContaining((int) (long) offset);
                if (variable != null) {
                    item.put("variable", variable.getName());
                    DataType dataType = variable.getDataType();
                    while (dataType instanceof TypeDef) {
                        dataType = ((TypeDef) dataType).getBaseDataType();
                    }
                    if (dataType instanceof Array || dataType instanceof Structure) {
                        long endOffset = (long) variable.getStackOffset() + variable.getLength();
                        long remaining = endOffset - offset;
                        if (remaining > 0) item.put("buffer_size", remaining);
                    }
                }
            } catch (RuntimeException ignored) {
                // Ghidra may not recover a stack variable for the address.
            }
        }
        try {
            if (node.getHigh() != null) item.put("high_name", node.getHigh().getName());
        } catch (RuntimeException ignored) {
            // High variables are optional decompiler metadata.
        }
        Map<String, Object> expression = expression(node, 0, new HashSet<>());
        if (expression != null) item.put("expression", expression);
        return item;
    }

    private String resolveAddressName(Program program, Address address) {
        if (address == null) return null;
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) function = program.getFunctionManager().getFunctionContaining(address);
        if (function != null) return function.getName();
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        return symbol == null ? null : symbol.getName();
    }

    private String targetName(Program program, PcodeOpAST operation) {
        Varnode target = operation.getInput(0);
        if (target != null) {
            Address address = target.getAddress();
            if (target.isConstant()) {
                try {
                    address = program.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset());
                } catch (RuntimeException ignored) {
                    address = null;
                }
            }
            String resolved = resolveAddressName(program, address);
            if (resolved != null) return resolved;
        }
        Address callSite = operation.getSeqnum().getTarget();
        for (Reference ref : program.getReferenceManager().getReferencesFrom(callSite)) {
            if (!ref.getReferenceType().isCall()) continue;
            if (ref instanceof ExternalReference) {
                return ((ExternalReference) ref).getExternalLocation().getLabel();
            }
            String resolved = resolveAddressName(program, ref.getToAddress());
            if (resolved != null) return resolved;
        }
        return null;
    }

    private Map<String, Object> returnVar(Varnode output) {
        if (output == null) return null;
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("repr", output.toString());
        item.put("size", output.getSize());
        try {
            if (output.getHigh() != null) item.put("high_name", output.getHigh().getName());
        } catch (RuntimeException ignored) {
            // High variables are optional decompiler metadata.
        }
        return item;
    }

    private String varIdentity(Varnode node) {
        if (node == null || node.isConstant()) return null;
        try {
            if (node.getHigh() != null && node.getHigh().getName() != null) {
                String highName = node.getHigh().getName();
                if (!highName.isEmpty() && !"UNNAMED".equals(highName) && !"null".equals(highName)) {
                    return "high:" + highName;
                }
            }
        } catch (RuntimeException ignored) {
            // Fall back to raw varnode representation.
        }
        return "repr:" + node.toString();
    }

    private Map<String, Object> functionCfg(HighFunction high) {
        Map<String, Object> blocks = new LinkedHashMap<>();
        for (ghidra.program.model.pcode.PcodeBlockBasic bb : high.getBasicBlocks()) {
            List<Integer> succs = new ArrayList<>();
            for (int i = 0; i < bb.getOutSize(); i++) {
                succs.add(bb.getOut(i).getIndex());
            }
            blocks.put(String.valueOf(bb.getIndex()), succs);
        }
        List<Map<String, Object>> guards = new ArrayList<>();
        Iterator<PcodeOpAST> ops = high.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() != PcodeOp.CBRANCH || op.getParent() == null || op.getNumInputs() < 2) continue;
            Varnode cond = op.getInput(1);
            for (int hop = 0; hop < 4 && cond != null && cond.getDef() != null; hop++) {
                int cOp = cond.getDef().getOpcode();
                if (cOp == PcodeOp.BOOL_NEGATE || cOp == PcodeOp.COPY || cOp == PcodeOp.CAST) {
                    cond = cond.getDef().getInput(0);
                } else {
                    break;
                }
            }
            PcodeOp cmp = cond != null ? cond.getDef() : null;
            if (cmp == null || cmp.getNumInputs() < 2) continue;
            int cmpOp = cmp.getOpcode();
            if (cmpOp != PcodeOp.INT_LESS && cmpOp != PcodeOp.INT_LESSEQUAL
                && cmpOp != PcodeOp.INT_SLESS && cmpOp != PcodeOp.INT_SLESSEQUAL) continue;
            for (int i = 0; i < 2; i++) {
                String vid = varIdentity(cmp.getInput(i));
                if (vid != null) {
                    Map<String, Object> guard = new LinkedHashMap<>();
                    guard.put("block", op.getParent().getIndex());
                    guard.put("op", cmp.getMnemonic());
                    guard.put("var", vid);
                    guards.add(guard);
                }
            }
        }
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("blocks", blocks);
        if (!guards.isEmpty()) cfg.put("guards", guards);
        return cfg;
    }

    private List<Map<String, Object>> calls(Program program, Map<String, Object> cfgOut) {
        List<Map<String, Object>> result = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isThunk()) continue;
                MemoryBlock fnBlock = program.getMemory().getBlock(function.getEntryPoint());
                if (fnBlock != null && fnBlock.getName().startsWith(".plt")) continue;
                DecompileResults completed = decompiler.decompileFunction(function, 30, monitor);
                HighFunction high = completed != null && completed.decompileCompleted() ? completed.getHighFunction() : null;
                if (high == null) continue;
                cfgOut.put(function.getName(), functionCfg(high));
                Iterator<PcodeOpAST> operations = high.getPcodeOps();
                while (operations.hasNext()) {
                    PcodeOpAST operation = operations.next();
                    if (operation.getOpcode() != PcodeOp.CALL && operation.getOpcode() != PcodeOp.CALLIND) continue;
                    List<Map<String, Object>> arguments = new ArrayList<>();
                    for (int index = 1; index < operation.getNumInputs(); index++) {
                        arguments.add(argument(program, function, operation.getInput(index)));
                    }
                    Map<String, Object> call = new LinkedHashMap<>();
                    call.put("from", operation.getSeqnum().getTarget().toString());
                    call.put("function", function.getName());
                    if (operation.getParent() != null) call.put("block", operation.getParent().getIndex());
                    call.put("order", operation.getSeqnum().getOrder());
                    call.put("to", targetName(program, operation));
                    call.put("indirect", operation.getOpcode() == PcodeOp.CALLIND);
                    call.put("target", argument(program, function, operation.getInput(0)));
                    Map<String, Object> ret = returnVar(operation.getOutput());
                    if (ret != null) call.put("return_var", ret);
                    call.put("arguments", arguments);
                    result.add(call);
                }
            }
        } finally {
            decompiler.dispose();
        }
        result.sort(Comparator.comparing(item -> String.valueOf(item.get("to")) + "\0" + item.get("function") + "\0" + item.get("from")));
        return result;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program open in CodeBrowser.");
            return;
        }
        List<Map<String, Object>> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("entry", function.getEntryPoint().toString());
            item.put("name", function.getName());
            item.put("thunk", function.isThunk());
            functions.add(item);
        }
        functions.sort(Comparator.comparing(item -> String.valueOf(item.get("name")).toLowerCase() + "\0" + item.get("entry")));

        Set<String> imports = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        SymbolIterator symbols = currentProgram.getSymbolTable().getExternalSymbols();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            imports.add(symbol.getName(true));
        }

        Map<String, Object> cfg = new LinkedHashMap<>();
        List<Map<String, Object>> exportedCalls = calls(currentProgram, cfg);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("schema", "pwnscan-ghidra/v1");
        payload.put("program", currentProgram.getName());
        payload.put("language", currentProgram.getLanguageID().toString());
        payload.put("image_base", currentProgram.getImageBase().toString());
        payload.put("functions", functions);
        payload.put("imports", imports);
        payload.put("calls", exportedCalls);
        payload.put("cfg", cfg);

        String[] arguments = getScriptArgs();
        File output = arguments.length > 0 ? new File(arguments[0]) : askFile("Save pwnscan Ghidra export", "Save");
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8)) {
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(payload, writer);
            writer.write("\n");
        }
        println("pwnscan metadata: " + output.getAbsolutePath());
    }
}
