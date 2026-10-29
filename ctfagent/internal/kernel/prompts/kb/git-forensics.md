# Exposed Git Repository Forensics

Use only when repository metadata is genuinely readable within the authorized target scope. A generic SPA fallback that returns the home page for every path is not a repository leak; compare status, content type, response size, and a body fingerprint against a random nonexistent path first.

## Triage

1. Check whether `/.git/HEAD` and `/.git/config` return repository metadata rather than the site's normal page.
2. Read `HEAD`, the referenced branch/tag, `packed-refs`, and `logs/HEAD`. Reflogs can reveal commits that are no longer the current version.
3. Try a normal clone or an established, bounded repository dumper first. Some static servers expose the files but do not implement Git's smart HTTP protocol.
4. If loose objects are directly readable, reconstruct conservatively:
   - fetch commit objects referenced by `HEAD`, refs, and reflogs;
   - follow each commit's tree and parent links;
   - parse tree entries and fetch referenced blobs;
   - decompress loose objects and verify each object's Git hash before trusting it;
   - preserve separate commits so diffs can reveal files removed in later revisions.
5. If only packfiles are available, check whether the matching index is exposed and use standard Git tooling; do not brute-force object identifiers.

## Safety and efficiency

- Bound the number and total size of objects fetched, set short per-request timeouts, and stay on the in-scope origin.
- Treat recovered credentials, tokens, and environment values as secrets. Do not copy them into public summaries or traces unnecessarily.
- Source comments are hypotheses, not proof. Confirm behavior with a minimal, reversible request before relying on a claimed vulnerability or configuration.
- If metadata files return 403 or the normal page, mark the repository path as unavailable and move to a different source-discovery path instead of repeating the same requests.
