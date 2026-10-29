# Pwn pipeline: identify the primitive, then build the smallest exploit

Apply only to binaries and services supplied for the authorized challenge. Do not scan unrelated hosts or alter any service beyond what the challenge requires.

## 1. Triage the artifact and interface

- Record file type, architecture, bitness, interpreter, and whether the binary is stripped. Use `file`, `readelf`, `objdump`, `checksec`, or a short Python parser when available; note missing tools and move on rather than installing arbitrary packages in the target.
- Inspect protections: NX, PIE, stack canary, RELRO, and executable stack. Treat these as constraints, not proof of exploitability.
- Read the launcher/wrapper and the challenge protocol. Determine whether the target is stdin/stdout, a line protocol, or a network service. Preserve the exact prompt, delimiter, and read length behavior.
- Run the provided binary locally only when safe to do so. Use a timeout and a disposable working directory; do not execute unknown binaries on the host outside that scope.

## 2. Find a reproducible primitive

1. Map input parsing and bounds: length fields, signedness, terminators, repeated records, and format strings.
2. Start with benign boundary values. Increase only enough to distinguish truncation, rejection, controlled crash, or output change.
3. For memory corruption, establish control and calculate offsets from a reproducible crash/core/register state. Do not infer an offset from a single crash.
4. For leaks, identify exactly which bytes are controlled or disclosed. A leak is useful only when it reveals an address/canary/structure needed by a later stage.
5. Prefer a direct `win`/challenge function or an intended data leak over a more complex chain when both are supported by evidence.

## 3. Build the exploit with mitigations in mind

- **NX:** use code reuse rather than injected shellcode unless the challenge explicitly provides executable memory.
- **Canary:** find a legitimate leak or an input path that avoids overwriting it; never assume a missing crash means the canary is absent.
- **PIE / ASLR:** derive a base from a real pointer leak and a known offset. Re-check the leak across fresh runs if the service can restart.
- **ROP / ret2libc:** verify gadget addresses, calling convention, argument registers, stack alignment, and any required `ret` alignment. Use a local reproduction before sending the final chain.
- **ret2csu / constrained calls:** confirm the gadget sequence and argument setup against the binary's disassembly; do not copy an unrelated chain.
- **Format strings:** first map positional arguments with a bounded probe, then distinguish read and write capabilities. Keep writes limited to the challenge process.

## 4. Local-to-remote discipline

- Reproduce the protocol locally before connecting to a remote target. Match newline, buffering, endianness, and exact read size.
- Connect only to the host and port explicitly supplied by the challenge. Use the same active instance for final retrieval and submission when the platform binds the answer to a live target.
- If TLS is part of the supplied endpoint, verify the intended hostname/protocol; only relax certificate verification for that exact lab endpoint when its certificate is known to be self-signed.
- Avoid brute force, repeated crashes, or large payload floods. Use a small number of evidence-led probes and preserve the successful transcript.

## 5. Stop and report

A valid result needs a reproducible exploit path and direct output from the intended challenge process. Submit only an observed candidate under the platform's attempt policy; after rejection, stop. Record binary protections, primitive, offset/leak evidence, and the minimal working chain as generalized facts—not as a hard-coded answer for a different target.

## 6. Text wrappers around binary serialization

When a service accepts a serialized object through a text prompt, trace the complete input path before constructing a payload: line reader → Unicode decoding → whitespace/token splitting → character encoding → parser/deserializer. Each transformation can remove delimiters, truncate the payload, or change non-ASCII bytes.

- Start with a harmless known-valid value and record the exact prompt, accepted framing, and response. Use one bounded malformed probe only when it distinguishes a specific parser boundary.
- Compare the wire representation after every wrapper transformation with the serialization protocol's required opcodes and terminators. A payload that is valid as raw bytes may be invalid after a text decode/encode round-trip.
- Do not assume that calling a dangerous deserializer proves a remotely reachable code-execution primitive. Show how the required callable/object reference can be represented through the actual input filter before attempting execution.
- Keep payload tests local or within the exact authorized challenge service, avoid destructive side effects, and retrieve/submit only a value directly emitted by that same challenge instance when instance binding applies.
- If the wrapper blocks the expected protocol framing and no alternative is supported by evidence after a small number of probes, stop and report the exact transformation and remaining uncertainty; do not guess a flag or repeatedly crash the service.
