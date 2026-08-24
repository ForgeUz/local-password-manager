# Contributing

This project is a zero-cloud, zero-trust, zero-recovery password manager. The codebase is held to an industrial verification standard. Read this before opening a PR.

---

## Development discipline

Two rule files govern all work:

### `rules_light.txt` — Caveman Mode + Tracer-Bullet TDD

- **Caveman Mode:** terse output, no filler, arrows (`->`) for causality.
- **Tracer-Bullet TDD:** ONE failing test -> ONE minimal implementation -> refactor. NO speculative abstraction. NO whole-file rewrites (atomic patches only).
- **Context Sync:** before any code block > 10 lines, output a `[Context Sync]` block (Abstraction Shift, Callers, Dependencies, Flow Summary).
- **Atomic patches:** touch only the lines necessary. No drive-by refactoring.
- **Compiler-in-the-loop:** no code is complete until it passes `analyzer -> typecheck -> test sandbox`.

### `rules_heavy.txt` — J-Space Architecture

- **MCTS hypothesis evaluation:** at least 3 hypotheses per decision, with confidence/risk/complexity scores.
- **Adversarial dual-model review:** attack your own design for races, leaks, edge cases.
- **Typestate over runtime validation:** make invalid states unrepresentable.
- **Mutation testing:** 100% kill required on crypto + state machines, recorded (51/51 applied).

---

## Definition of done

- `flutter analyze` clean (only the pre-existing `flutter_lints` include warning is tolerated).
- `flutter test` green (203 tests).
- `dart run tool/mutation_campaign.dart` reports 100% kill score (51/51 applied, 0 survived).
- Every honest limitation string present in the UI where the spec requires it.
- No feature additions without a spec reference (v5_delta.md error ID).

---

## Security hardening verification

Following the post-audit hardening (see `SECURITY_AUDIT.md` Task 3), all changes to the Trusted Computing Base (TCB) must verify:

### Native Memory Zeroing (FFI)

If you modify FFI wrappers (`argon2id.dart`, `aes_gcm.dart`, `hkdf.dart`):
- Verify `sodium_memzero` is called before `calloc.free` for ALL secret buffers.
- Add a mutation test that removes the `memzero` call; the test must fail.

### Bounds Checking (Parser Hardening)

If you modify parsers (`header.dart`, `second_factor.dart`):
- Verify all length fields have sanity checks (DEK max 1024, ciphertext max 1MB, tag count max 100).
- Verify `checkBounds()` helper is called before every `sublist` operation.
- Add a mutation test that removes a bounds check; the test must fail with a malformed input.

### Error Oracle Prevention

If you modify error handling:
- Verify all parsing/decryption errors throw `CorruptBlobError` or `DecryptionFailedError` (no information leakage).
- Verify `padding.dart` catches all `FormatException` and rethrows as `CorruptBlobError`.
- Add a mutation test that changes an error type; the test must fail.

### URL Normalization (Search Tags)

If you modify `search_tag.dart`:
- Verify `http://`, `https://`, `ftp://` schemes are stripped.
- Verify minimum query length (3 chars) is enforced.
- Add a test that verifies `https://example.com` and `example.com` produce the same search tag.

---

## Spec-first

The guiding spec is [`v5_delta.md`](v5_delta.md) (the V5 Delta Specification, keyed by audit error IDs E1..E23). If code contradicts spec, code is wrong. Patch the spec BEFORE touching code.

---

## How to contribute

1. Fork + branch (`fix/e17-atomic-mp-change`).
2. Write ONE tracer-bullet test -> implement -> refactor.
3. Run the full gate: `flutter analyze && flutter test`.
4. Run the mutation campaign for crypto changes: `dart run tool/mutation_campaign.dart`.
5. Open a PR with a terse Caveman-Mode summary + the error ID(s) closed.

---

## Code of conduct

Be precise, be honest about limitations, never claim enforcement that isn't math. No home-rolled crypto — audited bindings only.

---

## Mutation testing details

The mutation campaign (`tool/mutation_campaign.dart`) covers **51 mutations** across the entire Trusted Computing Base:

| Group | Mutations | Invariants Tested |
|-------|-----------|-------------------|
| vault_crypto_v4 | 15 | format, outer GCM, MP change, duress, memory zeroing |
| key_hierarchy | 5 | VRK derivation, DEK wrap/unwrap, CSPRNG |
| header | 8 | parser, bounds checks, endianness |
| padding | 4 | bucket masking, CSPRNG |
| second_factor | 6 | rate-limit, single-use, constant-time, memory zeroing |
| duress | 2 | domain separation |
| search_tag | 5 | SearchKey zeroing, bucket padding, normalization |
| argon2id | 3 | FFI memory zeroing, fail-closed |
| aes_gcm | 2 | FFI memory zeroing, AES-NI check |
| hkdf | 1 | PRK zeroing |

**Current result: 51/51 killed (100% kill score)**

If you add new crypto code or modify existing crypto code, you MUST add mutations to verify the new invariants. A "killed" result means the test suite detected the invariant violation.

---

## Honest limitations

- Mutation testing covers only what is encoded as a mutation. It does not replace external cryptographic audit.
- `V4VaultEntry.password` remains a Dart `String` in the UI model (unavoidable Flutter limitation). The crypto core never holds it as String.
- Equivalent mutants (security-only, not functional) are documented but not counted as gaps.