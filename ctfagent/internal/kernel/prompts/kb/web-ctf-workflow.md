# Web CTF workflow: evidence-first, low-noise

Use this card for an authorized practice target explicitly supplied in the challenge. Keep every request on that challenge's supplied host; do not expand to neighboring hosts, public services, or unrelated networks.

## 1. Establish a baseline

1. Read the challenge text and list the supplied URL(s), credentials, and any stated limits.
2. Request the root page once and preserve status, headers, cookies, redirects, and the complete body. Check `robots.txt`, linked assets, and source maps only on the supplied host.
3. Identify the application stack from observable evidence; treat banner/version guesses as hypotheses, not facts.
4. Reuse the same HTTP session after login. Distinguish unauthenticated behavior from authenticated behavior before interpreting 401/403/404/405.
5. Record a compact endpoint/parameter map from HTML forms, JavaScript, and observed requests. Client-side names are candidates; server responses are evidence.

## 2. Choose the next probe by information gain

Prefer source and behavior over large blind dictionaries:

- Look for challenge-provided source, debug output, backups, API schemas, and configuration paths. Keep guesses small and tied to evidence.
- For each input, test one harmless baseline and one controlled change. Compare status, headers, body length, and stable response markers.
- For a confirmed file path, template, query, or command input, check the corresponding parser behavior with a non-destructive probe before attempting to read the intended challenge artifact.
- Treat generic 200 pages as possible application fallbacks; compare against a random nonexistent path before trusting a directory hit.
- Use fuzzing only against the exact supplied route and a bounded candidate set. Stop when results become uniform or the authorized request budget is reached.

## 3. Common vulnerability families

- **File inclusion / traversal:** identify the server-side file parameter and normalization behavior. Prove the read using a benign known file or a challenge-provided hint, then follow the intended path to the challenge data.
- **SQL injection:** distinguish syntax errors, boolean differences, and authentication behavior. Use a local test or one minimal controlled pair; do not automate broad extraction when a narrower proof is enough.
- **Command injection:** first establish whether input reaches a command interpreter using a harmless identity/output probe. Keep commands scoped to reading the challenge's stated artifact; avoid persistence, destructive changes, or unrelated host discovery.
- **SSTI / deserialization:** fingerprint the evaluation context with a harmless expression or type error, then use the smallest evidence-backed path to the intended result.
- **SSRF / proxying:** inspect the route's actual outbound URL construction from source or response differences. Test only destinations explicitly within the challenge's authorized environment; do not probe cloud metadata or internal networks unless the challenge explicitly defines those as in-scope.

## 4. Verify and hand off

- A finding is a fact only when a tool response or supplied source supports it; store the exact evidence in the board.
- Keep a short list of tested and rejected hypotheses so the next round does not repeat them.
- If the challenge requires a live instance, obtain the answer from that same active instance and submit before it is restarted or released.
- Respect platform attempt limits. Submit only a directly observed, well-supported candidate; if rejected, stop unless the operator explicitly authorizes another attempt.
- Do not use internet search or external writeups when the task requires self-contained practice solving. Reuse only challenge-provided material and generalized internal notes.
