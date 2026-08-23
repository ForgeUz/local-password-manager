# Contributing

This project is a **zero-cloud, zero-trust, zero-recovery** password manager.
The codebase is held to an industrial verification standard. Read this before
opening a PR.

## Development discipline

Two rule files govern all work:

### `rules_light.txt` — Caveman Mode + Tracer-Bullet TDD

- **Caveman Mode:** terse output, no filler, arrows (`->`) for causality.
- **Tracer-Bullet TDD:** ONE failing test → ONE minimal implementation →
  refactor. NO speculative abstraction. NO whole-file rewrites (atomic patches
  only).
- **Context Sync:** before any code block > 10 lines, output a `[Context Sync]`
  block (Abstraction Shift, Callers, Dependencies, Flow Summary).
- **Atomic patches:** touch only the lines necessary. No drive-by refactoring.
- **Compiler-in-the-loop:** no code is complete until it passes
  analyzer → typecheck → test sandbox.

### `rules_heavy.txt` — J-Space Architecture

- **MCTS hypothesis evaluation:** at least 3 hypotheses per decision, with
  confidence/risk/complexity scores.
- **Adversarial dual-model review:** attack your own design for races, leaks,
  edge cases.
- **Typestate over runtime validation:** make invalid states unrepresentable.
- **Mutation testing:** ≥90% kill required on crypto + state machines, recorded.

## Definition of done

- `flutter analyze` clean (only the pre-existing `flutter_lints` include
  warning is tolerated).
- `flutter test` green (203 tests).
- `dart run tool/mutation_campaign.dart` reports ≥90% kill score.
- Every honest limitation string present in the UI where the spec requires it.
- No feature additions without a spec reference (v5_delta.md error ID).

## Spec-first

The guiding spec is [`v5_delta.md`](v5_delta.md) (the V5 Delta Specification,
keyed by audit error IDs E1..E23). If code contradicts spec, code is wrong.
Patch the spec BEFORE touching code.

## How to contribute

1. Fork + branch (`fix/e17-atomic-mp-change`).
2. Write ONE tracer-bullet test → implement → refactor.
3. Run the full gate: `flutter analyze && flutter test`.
4. Run the mutation campaign for crypto changes.
5. Open a PR with a terse Caveman-Mode summary + the error ID(s) closed.

## Code of conduct

Be precise, be honest about limitations, never claim enforcement that isn't
math. No home-rolled crypto — audited bindings only.