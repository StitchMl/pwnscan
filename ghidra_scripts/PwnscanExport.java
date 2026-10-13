// Export deterministic call and P-code argument facts for pwnscan.
// @category CTF
// @menupath Tools.CTF.Pwnscan Export

import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
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
            if (input.isConstant()) item.put("value", input.getOffset());
            else item.put("repr", input.toString());
            item.put("size", input.getSize());
            Map<String, Object> nested = expression(input, depth + 1, new HashSet<>(seen));
            if (nested != null) item.put("expression", nested);
            inputs.add(item);
        }
        result.put("inputs", inputs);
        return result;
    }

    private Long stackOffset(Varnode node, Set<String> seen) {
        if (node == null || !seen.add(node.toString())) return null;
        Address address = node.getAddress();
        if (address != null && address.isStackAddress()) return address.getOffset();
        PcodeOp operation = node.getDef();
        if (operation == null) return null;
        int opcode = operation.getOpcode();
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.INDIRECT) {
            return stackOffset(operation.getInput(0), seen);
        }
        if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.PTRADD) {
            Varnode base = operation.getInput(0);
            Varnode offset = operation.getInput(1);
            Address baseAddress = base == null ? null : base.getAddress();
            if (offset != null && offset.isConstant() && baseAddress != null && baseAddress.isStackAddress()) {
                long value = offset.getOffset();
                int bits = offset.getSize() * 8;
                if (bits > 0 && bits < 64 && (value & (1L << (bits - 1))) != 0) value -= 1L << bits;
                return value;
            }
            return stackOffset(base, seen);
        }
        if (opcode == PcodeOp.MULTIEQUAL) {
            Set<Long> values = new HashSet<>();
            for (int index = 0; index < operation.getNumInputs(); index++) {
                Long value = stackOffset(operation.getInput(index), new HashSet<>(seen));
                if (value != null) values.add(value);
            }
            return values.size() == 1 ? values.iterator().next() : null;
        }
        return null;
    }

    private Map<String, Object> argument(Program program, Function function, Varnode node) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("kind", "dynamic");
        item.put("repr", node.toString());
        item.put("size", node.getSize());
        if (node.isConstant()) {
            long value = node.getOffset();
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
                }
            } catch (RuntimeException ignored) {
                // Preserve the numeric constant when it is not a valid address.
            }
        }
        Long offset = stackOffset(node, new HashSet<>());
        if (offset != null) {
            item.put("kind", "stack");
            item.put("stack_offset", offset);
            try {
                int returnAddress = function.getStackFrame().getReturnAddressOffset();
                long overwriteOffset = (long) returnAddress - offset;
                if (overwriteOffset > 0) item.put("return_address_offset", overwriteOffset);
                Variable variable = function.getStackFrame().getVariableContaining((int) (long) offset);
                if (variable != null) {
                    item.put("buffer_size", variable.getLength());
                    item.put("variable", variable.getName());
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

    private String targetName(Program program, PcodeOpAST operation) {
        Varnode target = operation.getInput(0);
        if (target == null) return null;
        Address address = target.getAddress();
        if (target.isConstant()) {
            try {
                address = program.getAddressFactory().getDefaultAddressSpace().getAddress(target.getOffset());
            } catch (RuntimeException ignored) {
                return null;
            }
        }
        Function function = program.getFunctionManager().getFunctionAt(address);
        return function == null ? null : function.getName();
    }

    private List<Map<String, Object>> calls(Program program) {
        List<Map<String, Object>> result = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            DecompileResults completed = decompiler.decompileFunction(function, 30, monitor);
            HighFunction high = completed != null && completed.decompileCompleted() ? completed.getHighFunction() : null;
            if (high == null) continue;
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
                call.put("to", targetName(program, operation));
                call.put("indirect", operation.getOpcode() == PcodeOp.CALLIND);
                call.put("target", argument(program, function, operation.getInput(0)));
                call.put("arguments", arguments);
                result.add(call);
            }
        }
        decompiler.dispose();
        result.sort(Comparator.comparing(item -> String.valueOf(item.get("to")) + "\0" + item.get("function") + "\0" + item.get("from")));
        return result;
    }

    @Override
    protected void run() throws Exception {
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

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("schema", "pwnscan-ghidra/v1");
        payload.put("program", currentProgram.getName());
        payload.put("language", currentProgram.getLanguageID().toString());
        payload.put("image_base", currentProgram.getImageBase().toString());
        payload.put("functions", functions);
        payload.put("imports", imports);
        payload.put("calls", calls(currentProgram));

        String[] arguments = getScriptArgs();
        File output = arguments.length > 0 ? new File(arguments[0]) : askFile("Save pwnscan Ghidra export", "Save");
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.UTF_8)) {
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(payload, writer);
            writer.write("\n");
        }
        println("pwnscan metadata: " + output.getAbsolutePath());
    }
}
