# Operator UI Accessibility Checklist

## Phase G6 verification notes

- Global `--json` on the root `agentfirewall` command applies to every command group (policy, run, incident, approval, learner, server, witness).
- List-style RPC results (`policy list`, `run list`, `incident list`, `approval list`, `learner candidates`) emit JSON as `{"items":[...],"total":N}`; an empty result is `{"items":[],"total":0}`.
- When `--json` is set, failures print a single JSON object to stderr with an `error.code` and `error.message` aligned with the REST error codes in `docs/api/error-envelope.md`. gRPC `Unavailable` and connection failures surface as `UNAVAILABLE` with an explicit reachability message.
- `witness inspect|verify` are not yet implemented: with `--json`, the CLI exits non-zero and emits `UNIMPLEMENTED` via the same stderr envelope.

## CLI (Current Scope)

- [ ] All commands support `--json` for machine-readable output
- [ ] All mutation commands support non-interactive flags (no prompts in CI)
- [ ] Empty list results produce valid JSON with empty arrays
- [ ] Error messages include reason codes for programmatic handling
- [ ] Exit codes are non-zero on errors
- [ ] `--help` is available for every command and subcommand

## REST API (Current Scope)

- [ ] Error envelope includes machine-readable `code` field
- [ ] All responses include `X-Request-Id` header
- [ ] Content-Type is always `application/json`
- [ ] Empty list responses have consistent shape

## Web UI (Conditional — Not Yet In Scope)

When a web operator UI is introduced, the following must be verified:

- [ ] Contrast ratio meets WCAG AA (4.5:1 body text, 3:1 large text)
- [ ] All interactive elements are keyboard accessible
- [ ] Focus states are visible (`:focus-visible`)
- [ ] `prefers-reduced-motion` is respected
- [ ] State coverage: Loading, Empty, Error, Success, Partial, Offline
- [ ] Touch targets are >= 44px on mobile
