# Coverage Matrix (Part IV item 4)

Every security feature sits behind four layers: a documented invariant, a test,
a lint/tool, and a CI gate. **Empty cell = gap.** This matrix is the "no gaps"
instrument. The four Part II items are now filled (Phase 0).

Legend: ✅ = present, ⚠️ = partial / needs device, ❌ = gap.

## Phase 2/3 status (updated)

- **God-class split (2.5):** ✅ `VaultService` now delegates to `CanaryService`,
  `CsvService`, `RecoveryService`, `DecoyService` (each with its own test file).
- **KDF calibration (3.1):** ✅ `createVault` accepts raised KDF params; header
  records them; test `KDF calibration at creation`.
- **Boundary docs (3.2):** ✅ `security.md` §16 documents String-on-heap,
  no-browser-extension, decoy-vs-coercion, KDF calibration.
- **Dependency audit (3.3):** ✅ removed unused `pointycastle 3.9.1` (the flagged
  advisory surface); `verify_deps` allowlist updated to 13 deps.
- **Decrypt-on-demand (3.4):** ❌ backlog — requires reworking the entry model +
  UI; post-ship.

## Phase 0 — P0 fixes (now closed)

| Feature | Invariant | Test | Tool | CI gate |
|---|---|---|---|---|
| Duress write-guard | Decoy session is read-only; a write under VRK_duress would brick the primary | `test/app/vault_service_p0_test.dart` 'duress session is read-only' | `_guardDuressWrite()` in `vault_service.dart` | `unit-tests` job |
| Service-layer key zeroization (CWE-226) | MK/VRK zeroed after derivation at all 7 sites | `test/app/vault_service_p0_test.dart` + `tool/memory_dump.dart` service check | `try/finally` zeroing | `memory` job |
| `debugVrk` release guard | VRK-copying accessor throws in release (const-eliminated) | `test/app/vault_service_p0_test.dart` 'debugVrk is guarded' | `bool.fromEnvironment` const | `static-analysis` job |
| `unlock()` mutex + `lock()` full-wipe | No race on state swap; lock clears `_searchTags`/`_lastReveal`/`_isDuress` | `test/app/vault_service_p0_test.dart` 'lock() clears all session state' | mutex + full clear | `unit-tests` job |
| Search after VRK/shares unlock | `_searchTags` populated on every unlock path | `test/app/vault_service_p0_test.dart` (search-after-VRK, search-after-shares) | `VaultCryptoV4.unlockSessionWithVrk` | `unit-tests` job |
| Synchronous canary wipe | VRK never live after a canary hit returns | `test/app/vault_service_p0_test.dart` 'canary access wipes VRK synchronously' | inline wipe in `getEntry` | `unit-tests` job |

## Phase 1 — Threat hardening

| Feature | Invariant | Test | Tool | CI gate |
|---|---|---|---|---|
| Memory-dump patterns (MK/MP/derived-key) | No residual key material post-lock | `test/crypto/memory_dump_test.dart` + `tool/memory_dump.dart` | `MemoryDumpVerifier` | `memory` job |
| Process-hardening ordering | PR_SET_DUMPABLE/mlockall before first `SecureBuffer.alloc` | `tool/memory_dump.dart` service check | `ProcessHardening.harden()` in `main()` | `memory` job |
| Keystore attestation | StrongBox-backed VRK key where available | ⚠️ needs real device | `.setIsStrongBoxBacked(true)` in `MainActivity.kt` | ⚠️ device-only |
| Clipboard auto-clear | ≤45s wipe, no content in notifications | `test/clipboard/clipboard_controller_test.dart` | 30s timer in `ClipboardController` | `unit-tests` job |
| Autofill per-event confirmation | Every fill requires explicit user tap | ⚠️ needs native `FillResponse` change + device | `AndroidAutofillBridge` | ⚠️ device-only |
| FLAG_SECURE | No screenshot/recording of credential screens | ⚠️ needs device | `MainActivity.kt` `FLAG_SECURE` | ⚠️ device-only |
| Gitleaks gate | No cleartext secrets in source | — | `gitleaks/gitleaks-action` | `gitleaks` job |
| `verify_deps` allowlist | No dependency outside explicit allowlist | — | `tool/verify_deps.dart` | `supply-chain` job |

## Phase 2 — Hygiene

| Feature | Invariant | Test | Tool | CI gate |
|---|---|---|---|---|
| Comment-traceability | Security-claiming comment is test-backed | — | `tool/verify_comment_traceability.dart` | ⚠️ not yet wired |
| `very_good_analysis` baseline | Stricter lint baseline | — | `analysis_options.yaml` | ⚠️ requires dependency add |
| Coverage matrix | No empty cells | — | this document | — |
| Mutation campaign | ≥90% kill, temp-copy mode | — | `tool/mutation_campaign.dart` | ⚠️ full run ~40 min |
| God-class split | One module = one security boundary | — | `vault_service.dart` split | ⚠️ large refactor |

## Known gaps (honest)

- **15 mutation search strings** no longer match source (`tool/verify_mutations.dart` reports 15 missing) — those mutants are silently SKIPPED, reducing effective coverage. Regenerate the baseline.
- **75 pre-existing security-claiming comments** lack a test reference per the traceability gate. Backlog: add test files or reference tests inline.
- **Autofill confirmation, Keystore attestation, FLAG_SECURE** require a real Android device to verify (CI never exercises real FFI/local_auth/Keystore).