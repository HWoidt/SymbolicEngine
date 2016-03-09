# SymbolicEngine

This is a small and incomplete symbolic execution engine for x64 assembly
programs.
It reads assembly code in AT&T syntax e.g. as obtained from "objdump -d".
It then runs the code in an interpreter mode, interpolating any missing inputs
(registers, memory) using symbols and recording all symbolic computation in an AST.

The AST can be dumped as yaml and pickle files and further examined.

# Plans

1. Extend the AST analysis capabilities (e.g. using graph-tool)
2. Add a constraint solving engine, able to solve a symbolic trace AST given a
   set of boundary conditions.
3. Extend the supported instruction set
4. Fix some of the limitations

# Limitations

1. The memory model is too trivial and plain wrong (using a dict for any
   address, without any overlapping for e.g. 32bit and 64bit accesses to the
   same/consecutive addresses)
2. Unreasonable symbolic memory access: This is just indexed by the address
   expression, yielding a new symbol for the memory. Some sort of memory
   closure and history-tracking for symbolic accesses would be needed, in order
   to identify the correct data during the solver step.
3. No symbolic jump capability: Jump conditions need to be non-symbolically
   computable
4. Not all registers implemented (especially 16bit/8bit/high-byte access modes)
5. Severely limited subset of x86 instruction set (only supports part of the
   "unholy" example)
6. Many more... :D

A real alternative can be found at: http://triton.quarkslab.com/
