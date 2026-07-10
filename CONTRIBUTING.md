# Contributing to Busbar

Thanks for your interest in improving Busbar. This document covers how to build,
test, and submit changes.

## Ground rules

- Be respectful and constructive in all project spaces.
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

Busbar is a single Rust binary. You need a recent stable toolchain
(`rustup` recommended).

```bash
cargo build              # debug build
cargo test               # run tests
cargo clippy --all-targets -- -D warnings   # lints must be clean
cargo fmt --all          # format before committing
```

Run locally against the shipped example config (two YAML files; keys are supplied
via the env vars named in `config.yaml`):

```bash
export BUSBAR_CLIENT_TOKEN=dev-token
export ANTHROPIC_KEY=sk-ant-...      # any provider key referenced by config.yaml
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml cargo run
curl -s localhost:8080/healthz
curl -s -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" localhost:8080/stats | jq
```

See [docs/configuration.md](docs/configuration.md) for the full config reference.

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** — green.
4. Add or update tests for any behavior change. The circuit-breaker disposition
   logic in particular should be covered by tests, not just inspection.
5. **No `_ =>` catch-all arms** in disposition/breaker `match` statements — the
   exhaustive match is how the compiler enforces that every failure mode is
   handled. This is a project invariant.
6. Update documentation when you change behavior or config.

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

## Architecture

The circuit breaker — the upstream-vs-client failure taxonomy — is the core of the
project; changes there deserve extra care and review. A backend is ejected for
*upstream* faults but never for *client-supplied* 4xx.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
