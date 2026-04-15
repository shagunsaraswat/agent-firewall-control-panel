# Contributing to Agent FirewallKit

Thank you for your interest in improving Agent FirewallKit. This guide explains how to set up your environment, match project conventions, and submit changes.

## Development environment

### Rust toolchain

1. Install [Rust](https://www.rust-lang.org/tools/install) (rustup recommended).
2. This repository pins a toolchain in `rust-toolchain.toml`; rustup will download the correct version on first use.
3. From the repository root, fetch dependencies and verify the workspace builds:

   ```bash
   cargo build --workspace
   ```

### Docker (integration tests)

Server-facing and end-to-end tests often depend on external services (for example PostgreSQL, Redis, NATS, or ClickHouse). Install [Docker](https://docs.docker.com/get-docker/) (or a compatible engine) so you can run those services locally.

When compose files or documented service topologies are added under this repo or in [final_prd/](final_prd/), follow those instructions to start dependencies before running integration tests. Until then, run `cargo test --workspace` for the default unit test set; skip or document any tests that require Docker if they are gated behind features or ignored locally.

## Code style

- **Formatting:** Run `cargo fmt --all` before committing. CI enforces `cargo fmt --all -- --check`.
- **Linting:** Run `cargo clippy --workspace --all-targets -- -D warnings` and fix all warnings. CI uses the same flags.

Prefer small, focused changes that are easy to review. Match existing naming, module layout, and error-handling patterns in the crate you touch.

## Required Checks

All pull requests must pass the following CI gates before merge:

1. **Formatting**: `cargo fmt --all -- --check`
2. **Linting**: `cargo clippy --workspace --all-targets -- -D warnings`
3. **Unit Tests**: `cargo test --workspace`
4. **Integration Tests**: `cargo test -p agentfirewall-integration-tests -- --include-ignored` (requires Postgres, Redis, NATS)
5. **Python Binding Tests**: `pytest bindings/python/tests/`
6. **Node Binding Tests**: `cd bindings/node && npm test`

In GitHub, configure branch protection so required status checks include at least:

- **CI** workflow: `Required Checks (Rust)` (aggregates fmt, Clippy, tests, and docs in that workflow)
- **Integration Tests** workflow: `integration`
- **Binding Tests** workflow: all matrix jobs you care about (for example `python` / `node` per Python and Node versions)

### Local Development

To run the full check suite locally:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For integration tests, start the local stack first:

```bash
docker compose -f docker/docker-compose.yml up -d
cargo test -p agentfirewall-integration-tests -- --include-ignored
```

## Pull request process

1. **Fork** the repository (or use a branch if you have write access).
2. **Branch** from `main` with a descriptive name (for example `fix/witness-cache-invalidation` or `feat/sentinel-threshold-config`).
3. **Implement** your change with tests where appropriate (see below).
4. **Run** `cargo fmt`, `cargo clippy` with `-D warnings`, and `cargo test --workspace` (and `--all-features` if your change touches optional features).
5. **Open a pull request** against `main` with a clear description of the problem, the solution, and any trade-offs or follow-up work.

Maintainers will review for correctness, style, tests, and fit with the architecture described in [specs/](specs/) and [final_prd/](final_prd/).

## Commit messages

Use messages that explain *what* changed and *why* when it is not obvious from the diff alone.

Conventions that work well here:

- **Imperative mood** in the subject line (for example “Add witness TTL to config”, not “Added…”).
- **Subject ~50 characters**, no trailing period; **blank line** before body if you add detail.
- **Reference issues** when applicable (`Fixes #123`, `Refs #456`).

## Testing expectations

- **New logic** in library or application code should include **unit tests** in the same crate when feasible (pure functions, parsers, policy evaluation, etc.).
- **Server behavior** that spans HTTP/gRPC handlers, persistence, or messaging should include **integration tests** where practical, typically with services started via Docker or test harnesses provided in the repo.

If a test is expensive or environment-specific, gate it behind a Cargo feature or mark it `#[ignore]` with a short comment describing how to run it.

## Code of conduct

All contributors are expected to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Report concerns to the contacts listed there once they are published; until then, use [GOVERNANCE.md](GOVERNANCE.md) for escalation paths when they are defined.
