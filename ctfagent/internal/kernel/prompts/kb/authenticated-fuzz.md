# Authenticated Route and Parameter Fuzzing

Use this workflow whenever a route requires login, a role, an API token, or a session cookie.

## Establish and verify the session

1. Use the normal HTTP tool for login so its shared cookie jar records `Set-Cookie` values.
2. Make one authenticated control request to a known route and confirm it is no longer returning the unauthenticated response (for example, compare status, redirect, and a stable body marker).
3. Keep subsequent recon, route fuzzing, and parameter fuzzing on the same target origin and session. Do not manually copy cookies from a different challenge instance or a stale trace.
4. If the control request returns to the login page, 401, or 403, reauthenticate before interpreting fuzz results. Uniform authorization failures are not evidence that candidate routes or parameters are invalid.

## Fuzz with a meaningful oracle

- Capture the authenticated baseline using the same method, content type, headers, and session as the candidate requests.
- Prefer a stable semantic difference (a distinct error, success marker, redirect, or structured response field) over response length alone.
- Probe one dimension at a time: route, method, parameter location (query/form/JSON), parameter name, then value. Keep a small control candidate in each batch.
- When every candidate matches the baseline, verify that the session is still valid and that the endpoint is consuming the chosen location before expanding the dictionary.
- For state-changing actions, start with harmless values or a read-only action when available. Record the exact request shape and response before attempting a mutation.

## Session lifecycle and evidence

- Sessions are origin-scoped; a cookie from one host, port, container, or fresh challenge instance may not be valid on another.
- After a challenge restart or target change, re-login and re-check authorization rather than reusing old cookies.
- Record authentication state as a fact only when supported by a response difference; successful transport or a 200 status alone is not proof of authorization.
- Treat cookies, bearer tokens, and passwords as secrets. Keep them out of user-facing summaries; redact them from long-lived traces where grounding requirements permit, while preserving a secure evidence reference.
