// Ghidra post-script for reproducible, read-only inspection of one address range.
//
// Example (addresses are start-inclusive/end-exclusive):
//   analyzeHeadless <project-dir> <project> -import <prx> \
//     -scriptPath scripts/ghidra -postScript SetoAnalyzeFunction.java 0x244 0x278
//
// The script prints the selected language/compiler spec, Ghidra's discovered
// function/decompilation when available, and the instructions in the requested
// range. It does not modify the input program or export any game data.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class SetoAnalyzeFunction extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("SETO_ERROR=expected start and end-exclusive addresses");
            return;
        }

        long startOffset = Long.decode(args[0]);
        long endExclusive = Long.decode(args[1]);
        if (endExclusive <= startOffset || ((endExclusive - startOffset) & 3) != 0) {
            println("SETO_ERROR=range must be non-empty, aligned, and end-exclusive");
            return;
        }

        Address start = toAddr(startOffset);
        Address last = toAddr(endExclusive - 4);
        println("SETO_LANGUAGE=" + currentProgram.getLanguageID().getIdAsString());
        println("SETO_COMPILER_SPEC=" + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            println("SETO_FUNCTION=not-defined-at-" + start);
        } else {
            println("SETO_FUNCTION=" + function.getName() + " body_bytes=" + function.getBody().getNumAddresses());
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                    println("SETO_DECOMP_C_BEGIN");
                    println(results.getDecompiledFunction().getC());
                    println("SETO_DECOMP_C_END");
                } else {
                    println("SETO_DECOMP_ERROR=" + results.getErrorMessage());
                }
            } finally {
                decompiler.dispose();
            }
        }

        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            new AddressSet(start, last), true
        );
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            println("SETO_INSN=" + instruction.getAddress() + " " + instruction);
        }
    }
}
