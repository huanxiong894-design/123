# Reverse engineering: classify, trace data, validate a hypothesis

This card is for challenge-provided binaries and files. Treat disassembly and runtime output as evidence; never execute unknown samples outside a disposable, scoped environment.

## 1. Identify the format and execution path

- Confirm architecture, bitness, OS/ABI, file type, entry point, imports, sections, and whether symbols/debug data remain. Check for scripts, archives, and nested files before assuming the outer file is the program.
- Run once with no input and with one ordinary input. Preserve output, exit status, and timing; avoid large or malformed inputs until the parser is understood.
- Use strings and imports to locate likely input, comparison, transform, and output paths. Cross-reference strings in the disassembler; a string alone is not proof that its code path is reachable.
- For stripped binaries, use function boundaries, cross-references, call sites, and format-specific metadata (for example, Go pclntab) before renaming functions.

## 2. Trace the value that matters

Follow input through parsing, normalization, transformation, comparison, and output. Look for:

- fixed-length tables or high-entropy constants near loops that read or transform them;
- hash/encoding routines and compiler-optimized arithmetic such as reciprocal multiplication;
- success/failure branches and whether the decoded value is ever emitted or used;
- decoy paths that perform substantial work but only print constant filler.

When a loop appears to decode data but never exposes the result, verify the writes and call sites before reverse-engineering the whole virtual machine. If a static constant is the likely answer source, derive a candidate transformation from instructions and independently cross-check the bytes against the code.

## 3. Select the cheapest reliable method

- **Static first:** reproduce short transform loops in Python and compare intermediate bytes, not just a guessed final string.
- **Dynamic second:** use a debugger or instrumentation only when static analysis cannot resolve state, relocations, or library behavior. Break after the relevant transform and inspect the buffer/registers that the disassembly actually uses.
- **Emulation:** use a minimal function-level emulator only for self-contained code. Map required segments, stack, and thread-local state explicitly; validate addresses and calling convention.
- **Packed/self-modifying code:** locate the unpacking boundary, dump the reconstructed bytes, and analyze the output rather than fighting the loader indefinitely.

## 4. Validation and stopping rules

- Build two independent checks: a known input/output pair or a local execution comparison, and a structural check against the disassembly/data layout.
- A candidate is not verified merely because it is printable or resembles a flag. Confirm the relevant bytes originate from the supplied challenge and appear in an actual output or intended comparison path.
- If a tool is absent, use a small standard-library script or another available utility; do not repeatedly retry the missing command.
- Time-box one hypothesis. If new evidence contradicts it, record why and switch to the next data-flow path instead of adding arbitrary transformations.
- Submit only a directly observed, evidence-backed answer within the platform's attempt limit. Stop after rejection.
