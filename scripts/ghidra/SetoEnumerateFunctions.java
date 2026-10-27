// Read-only Ghidra post-script that emits a bounded discovery manifest.
//
// Run it with -process against an existing, analyzed project; do not import the
// EBOOT again for each page. The emitted records are hints only. Python must
// independently validate each selected function boundary before compilation.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class SetoEnumerateFunctions extends GhidraScript {
    private static final int DEFAULT_LIMIT = 4096;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String module = args.length > 0 ? args[0].trim() : defaultModuleName();
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : DEFAULT_LIMIT;
        if (module.isEmpty() || limit < 1 || limit > DEFAULT_LIMIT) {
            println("SETO_ERROR=module must be non-empty and limit must be in 1..4096");
            return;
        }

        List<Function> functions = new ArrayList<Function>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function function = iterator.next();
            if (function.getBody().getNumAddresses() > 0) {
                functions.add(function);
            }
        }
        Collections.sort(functions, new Comparator<Function>() {
            @Override
            public int compare(Function left, Function right) {
                return left.getEntryPoint().compareTo(right.getEntryPoint());
            }
        });

        println("SETO_ENUMERATION_BEGIN module=" + module
            + " total=" + functions.size() + " limit=" + limit);
        int emitted = 0;
        for (Function function : functions) {
            if (monitor.isCancelled() || emitted >= limit) {
                break;
            }
            String record = functionRecord(module, function);
            if (record != null) {
                println("SETO_FUNCTION_JSON=" + record);
                emitted++;
            }
        }
        println("SETO_ENUMERATION_END module=" + module
            + " emitted=" + emitted
            + " total=" + functions.size()
            + " truncated=" + (emitted < functions.size()));
    }

    private String defaultModuleName() {
        String program = currentProgram.getName();
        String upper = program.toUpperCase();
        if (upper.contains("EBOOT")) {
            return "EBOOT";
        }
        return program;
    }

    private String functionRecord(String module, Function function) {
        Address entry = function.getEntryPoint();
        Address bodyStart = function.getBody().getMinAddress();
        Address bodyEnd = function.getBody().getMaxAddress().add(1);
        long bodyAddresses = function.getBody().getNumAddresses();
        int addressableUnitSize = currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddressableUnitSize();
        long sizeBytes = bodyAddresses * addressableUnitSize;

        int bodyRanges = 0;
        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange ignored = ranges.next();
            bodyRanges++;
        }

        long instructionCount = 0;
        Address nextInstruction = bodyStart;
        boolean contiguous = addressableUnitSize == 1
            && bodyRanges == 1
            && bodyStart.equals(entry);
        Set<String> calls = new TreeSet<String>();
        Set<String> dataTargets = new TreeSet<String>();
        InstructionIterator instructions = currentProgram.getListing()
            .getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Address instructionAddress = instruction.getAddress();
            int instructionSize = instruction.getLength();
            if (!instructionAddress.equals(nextInstruction)
                || (instructionAddress.getOffset() & 3L) != 0
                || instructionSize != 4) {
                contiguous = false;
            }
            nextInstruction = instructionAddress.add(instructionSize);
            instructionCount++;

            if (instruction.getFlowType().isCall()) {
                Address[] flows = instruction.getFlows();
                if (flows != null) {
                    for (Address target : flows) {
                        calls.add(hex(target));
                    }
                }
            }
            for (Reference reference : currentProgram.getReferenceManager()
                    .getReferencesFrom(instructionAddress)) {
                Address target = reference.getToAddress();
                if (reference.getReferenceType().isData()
                    && target.getAddressSpace().equals(
                        currentProgram.getAddressFactory().getDefaultAddressSpace())) {
                    dataTargets.add(hex(target));
                }
            }
        }
        contiguous = contiguous
            && bodyAddresses == bodyEnd.subtract(bodyStart)
            && instructionCount == sizeBytes / 4
            && nextInstruction.equals(bodyEnd);

        StringBuilder out = new StringBuilder();
        out.append("{\"module\":").append(quote(module));
        out.append(",\"address\":").append(quote(hex(entry)));
        out.append(",\"size_bytes\":").append(sizeBytes);
        out.append(",\"instruction_count\":").append(instructionCount);
        out.append(",\"calls\":[");
        appendStrings(out, calls);
        out.append("],\"data_reference_count\":").append(dataTargets.size());
        out.append(",\"boundary_hint\":")
            .append(quote(contiguous ? "CONTIGUOUS" : "MULTIRANGE_OR_GAPPED"));
        out.append("}");
        return out.toString();
    }

    private void appendStrings(StringBuilder out, Set<String> values) {
        boolean first = true;
        for (String value : values) {
            if (!first) {
                out.append(',');
            }
            out.append(quote(value));
            first = false;
        }
    }

    private String hex(Address address) {
        String value = Long.toHexString(address.getOffset());
        StringBuilder padded = new StringBuilder();
        for (int index = value.length(); index < 8; index++) {
            padded.append('0');
        }
        padded.append(value);
        return "0x" + padded.toString();
    }

    private String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '\\' || character == '"') {
                out.append('\\').append(character);
            } else if (character < 0x20) {
                out.append(String.format("\\u%04x", (int)character));
            } else {
                out.append(character);
            }
        }
        return out.append('"').toString();
    }
}
