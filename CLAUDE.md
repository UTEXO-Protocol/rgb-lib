# Claude Review Guidance

This repository contains `rgb-lib`, a Rust library with bindings.

When reviewing pull requests, focus on:

- Correctness and regressions in wallet, transfer, and synchronization logic.
- Safety around UTXO/accounting invariants and state transitions.
- Error handling, especially where partial state updates may happen.
- Security-sensitive boundaries (keys, signing, serialization, network calls).
- Test coverage for new behavior and edge cases.

Repository conventions:

- Keep changes minimal and scoped to the PR goal.
- Prefer explicit errors over silent fallback behavior.
- Avoid introducing breaking API changes unless the PR explicitly requires it.
- Keep CI/workflow changes conservative and deterministic.
