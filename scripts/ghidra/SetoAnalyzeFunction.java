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
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;

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
        Address lastByte = toAddr(endExclusive - 1);
        Address lastInstruction = toAddr(endExclusive - 4);
        long expectedBytes = endExclusive - startOffset;
        int addressableUnitSize = currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddressableUnitSize();
        println("SETO_LANGUAGE=" + currentProgram.getLanguageID().getIdAsString());
        println("SETO_COMPILER_SPEC=" + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        println("SETO_IMAGE_BASE=" + currentProgram.getImageBase());
        println("SETO_FUNCTION_START=0x" + Long.toHexString(startOffset));
        println("SETO_FUNCTION_END=0x" + Long.toHexString(endExclusive));

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            println("SETO_BOUNDARY_STATUS=NOT_FOUND");
            println("SETO_DECOMP_STATUS=NOT_RUN");
        } else {
            long bodyAddresses = function.getBody().getNumAddresses();
            int bodyRanges = 0;
            boolean rangesInsideRequest = true;
            AddressRangeIterator ranges = function.getBody().getAddressRanges();
            while (ranges.hasNext()) {
                AddressRange range = ranges.next();
                bodyRanges++;
                if (range.getMinAddress().compareTo(start) < 0
                    || range.getMaxAddress().compareTo(lastByte) > 0) {
                    rangesInsideRequest = false;
                }
            }
            boolean exact = addressableUnitSize == 1
                && function.getEntryPoint().equals(start)
                && function.getBody().getMinAddress().equals(start)
                && function.getBody().getMaxAddress().equals(lastByte)
                && bodyAddresses == expectedBytes
                && bodyRanges == 1
                && rangesInsideRequest;
            println("SETO_GHIDRA_FUNCTION=" + function.getName());
            println("SETO_FUNCTION_BODY_START=" + function.getBody().getMinAddress());
            println("SETO_FUNCTION_BODY_END=" + function.getBody().getMaxAddress().add(1));
            println("SETO_FUNCTION_BODY_ADDRESSES=" + bodyAddresses);
            println("SETO_FUNCTION_BODY_RANGES=" + bodyRanges);
            println("SETO_ADDRESSABLE_UNIT_SIZE=" + addressableUnitSize);
            println("SETO_BOUNDARY_STATUS=" + (exact ? "EXACT" : "MISMATCH"));

            if (!exact) {
                println("SETO_DECOMP_STATUS=NOT_RUN");
            } else {
                DecompInterface decompiler = new DecompInterface();
                try {
                    decompiler.openProgram(currentProgram);
                    DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                    if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                        println("SETO_DECOMP_STATUS=OK");
                        println("SETO_DECOMP_C_BEGIN");
                        println(results.getDecompiledFunction().getC());
                        println("SETO_DECOMP_C_END");
                    } else {
                        println("SETO_DECOMP_STATUS=FAILED");
                        println("SETO_DECOMP_ERROR=" + results.getErrorMessage());
                    }
                } finally {
                    decompiler.dispose();
                }
            }
        }

        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            new AddressSet(start, lastInstruction), true
        );
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            println("SETO_INSN=" + instruction.getAddress() + " " + instruction);
        }

        for (int index = 2; index < args.length; index++) {
            Address requested = toAddr(Long.decode(args[index]));
            MemoryBlock block = currentProgram.getMemory().getBlock(requested);
            if (block == null) {
                println("SETO_ADDRESS_MAP=" + args[index] + " UNMAPPED");
            } else {
                println("SETO_ADDRESS_MAP=" + args[index]
                    + " block=" + block.getName()
                    + " block_start=" + block.getStart()
                    + " block_end=" + block.getEnd()
                    + " initialized=" + block.isInitialized());
            }
        }
    }
}
