# Misc and forensics: inspect layers, preserve bytes, verify the source

Use this workflow for challenge-provided files and captures. Keep analysis offline unless the challenge explicitly provides an in-scope service; do not query public lookup sites or external writeups.

## 1. Preserve and classify

- Work from a copy. Record filename, byte length, SHA-256, file signature, and the first/last few bytes. Extensions and MIME labels are hints, not authority.
- Check for nested archives, polyglots, concatenated members, and data appended after a format's normal terminator (for example, JPEG EOI or PDF EOF). Report offsets and preserve exact bytes.
- List archive members before extraction. Reject path traversal names and extract into a new temporary directory; record compression method, sizes, timestamps, and duplicate names.
- If the expected utility is absent, use a short standard-library script or another available parser rather than repeatedly retrying it.

## 2. Network captures

- Determine capture format, link type, timestamp range, and endpoint pairs before decoding payloads.
- Reassemble TCP streams by direction and sequence number; packet boundaries are not application-message boundaries. Handle retransmissions and out-of-order data, then inspect HTTP, DNS, TLS metadata, or custom protocol framing as appropriate.
- Export transferred objects and inspect signatures and trailing bytes. A valid image or archive may contain a second payload after its normal end marker.
- Keep stream index, endpoints, offsets, and relevant packet numbers with each finding so the extraction can be reproduced.

## 3. File-format and stego checks

- Move from cheap to expensive: metadata and strings → common container structure → embedded/concatenated data → steganography or custom encoding.
- For image/audio files, compare dimensions, channels, bit depth, metadata, and decoded pixel/sample distributions. For QR/barcodes, improve crop/contrast/rotation and decode locally; if still ambiguous, keep it unresolved rather than submitting a guess.
- For office documents, inspect the archive parts, relationships, macros, embedded objects, and hidden sheets/slides. Treat active content as data; do not execute macros.
- For compressed or encrypted data, first identify the wrapper and expected length. Distinguish compression from encryption; use entropy and structure as clues, not proof. Do not send candidate hashes or ciphertext to public cracking services.

## 4. Evidence and answer handling

- Keep original bytes and a small extraction script. Record the exact source offset/stream/metadata that yields each candidate.
- If multiple layers are present, document the order (for example: TCP reassembly → HTTP body → JPEG → appended bytes → decode).
- A plausible string is not an answer until it is tied to the provided artifact or an in-scope challenge target. Do not submit unresolved QR, guessed plaintext, or format-shaped candidates.
- Respect attempt limits: submit one well-supported candidate at most unless explicitly authorized otherwise; stop after rejection.

## 5. Unicode and invisible-character encodings

- Inspect code points, not rendered glyphs. Record each character's code point/name/category and positions before normalizing, trimming, or copying text; zero-width and variation characters can carry the payload while the visible symbols act as framing.
- Derive a candidate bit/byte layout from repeated structure (line width, marker count, inter-symbol gaps, leading/trailing sentinels). Keep framing separate from payload and validate that every record has the same expected width before decoding.
- Test bit order or polarity only when the observed framing supports a small, explicit alternative. Require independent consistency—valid text encoding, coherent delimiters, and source-preserving reproduction—not merely a string that resembles a flag.
- Preserve the original bytes and a short decoder that reports code-point counts, record widths, and offsets. Do not run Unicode normalization on the source before analysis.

## 6. Reconstructing captured application data

- Keep TCP directions separate. Reassemble segments by sequence number, accounting for out-of-order packets and retransmissions; packet boundaries do not delimit HTTP requests or bodies.
- Parse protocol framing after reassembly. For HTTP, honor `Content-Length`, chunked transfer coding, and message boundaries before parsing form fields; otherwise a following request can be mistaken for part of a credential value.
- Treat a captured field name and value as evidence of what was transmitted, not automatically as the user's original secret. Check whether the client transforms the value (for example, a digest) before labeling it plaintext. Extract only fields relevant to the challenge and avoid copying unrelated cookies or identifiers into notes.
- Record the directional flow, request line, framing length, and exact body offset needed to reproduce the finding. Do not access historical hostnames from the capture unless the challenge explicitly authorizes an active target.

## 7. Appended archives and encrypted payloads

- A container can continue after the format's normal terminator. Check the exact end marker (such as JPEG EOI), report its offset, and inspect subsequent bytes for local-file and end-of-directory signatures.
- Prefer in-memory archive readers on the original file or a precisely carved tail; list member names, sizes, compression methods, and checksums before reading. Extract only to a fresh directory after validating paths.
- Decode an embedded hint exactly once and use its semantic content to form a bounded cryptographic hypothesis. Select candidate algorithms/key derivations from observed length, block size, headers, and explicit clue—never substitute a large dictionary or arbitrary mode sweep.
- Accept plaintext only when its structure and contents are directly coherent and independently reproducible. If a bounded evidence-led set yields no validated plaintext, mark the task unresolved and do not submit a guessed key or wrapper.
