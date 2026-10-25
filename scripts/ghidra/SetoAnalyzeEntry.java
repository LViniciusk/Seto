// Read-only Ghidra post-script that proves the function body at one entry point.
//
// Usage:
//   analyzeHeadless <project-dir> <project> -import <EBOOT.elf> \
//     -scriptPath scripts/ghidra -postScript SetoAnalyzeEntry.java 0x8040
//
// Unlike SetoAnalyzeFunction, this script discovers the end from Ghidra's
// Function body. It makes no edits to the program or input image.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;

public class SetoAnalyzeEntry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("SETO_ERROR=expected one entry address");
            return;
        }

        long startOffset = Long.decode(args[0]);
        Address start = toAddr(startOffset);
        int addressableUnitSize = currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddressableUnitSize();
        println("SETO_LANGUAGE=" + currentProgram.getLanguageID().getIdAsString());
        println("SETO_COMPILER_SPEC=" + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        println("SETO_FUNCTION_START=0x" + Long.toHexString(startOffset));

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            println("SETO_BOUNDARY_STATUS=NOT_FOUND");
            println("SETO_DECOMP_STATUS=NOT_RUN");
            return;
        }

        long bodyAddresses = function.getBody().getNumAddresses();
        int bodyRanges = 0;
        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        boolean singleRange = true;
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            bodyRanges++;
            if (bodyRanges > 1) {
                singleRange = false;
            }
        }
        Address bodyStart = function.getBody().getMinAddress();
        Address bodyEnd = function.getBody().getMaxAddress().add(1);
        long size = bodyEnd.subtract(bodyStart);
        boolean exact = addressableUnitSize == 1
            && function.getEntryPoint().equals(start)
            && bodyStart.equals(start)
            && singleRange
            && bodyAddresses == size
            && (size & 3) == 0;

        println("SETO_FUNCTION_END=" + bodyEnd);
        println("SETO_FUNCTION_BODY_START=" + bodyStart);
        println("SETO_FUNCTION_BODY_END=" + bodyEnd);
        println("SETO_FUNCTION_BODY_ADDRESSES=" + bodyAddresses);
        println("SETO_FUNCTION_BODY_RANGES=" + bodyRanges);
        println("SETO_ADDRESSABLE_UNIT_SIZE=" + addressableUnitSize);
        println("SETO_BOUNDARY_STATUS=" + (exact ? "EXACT" : "MISMATCH"));
        if (!exact) {
            println("SETO_DECOMP_STATUS=NOT_RUN");
            return;
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                println("SETO_DECOMP_STATUS=OK");
            } else {
                println("SETO_DECOMP_STATUS=FAILED");
            }
        } finally {
            decompiler.dispose();
        }
        println("SETO_INSTRUCTION_COUNT=" + (bodyAddresses / 4));
    }
}
