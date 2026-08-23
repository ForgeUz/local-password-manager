# Roadmap: v2 -> v4 (via the v3 Final Master Plan route)

Zero-cloud. Zero-trust. Zero-recovery-by-design. Flutter (Android + Linux Mint), P2P LAN sync, single encrypted file per vault.

This is the **authoritative consolidated implementation roadmap** from the current v2 codebase to the v4 specification. It is written so a separate implementation chat, holding only this document plus the three specs (`v2.md`, `pass_v3_final_master_plan_EN.md`, `v4.md`), can execute every step without ambiguity.

- Source specs: [`v2.md`](v2.md) -> [`pass_v3_final_master_plan_EN.md`](pass_v3_final_master_plan_EN.md) -> [`v4.md`](v4.md)
- Discipline: [`rules_heavy.txt`](rules_heavy.txt) (J-Space MCTS + JSpaceState JSON decision gates) + [`rules_light.txt`](rules_light.txt) (caveman tracer-bullet TDD, atomic patches).

---

## 0. REALITY CHECK — WHERE THE CODE ACTUALLY IS

The codebase is **not** at v3. It is a **partial, pure-Dart, flat-blob v2** with a stubbed sync layer. `v4.md` assumes v3 is fully implemented; that assumption is false. This roadmap therefore adds a **Phase 0 (Foundation Swap)** that `v4.md` never needed to spell out, and treats `v4.md §8` phases A-P as the canonical skeleton.

### 0.1 Gap table (verified against source)

| Concern | Current state | Spec target (v2 §2/§4 -> v3 §19 -> v4 §4/§5) |
|---|---|---|
| Crypto backend | Pure-Dart `cryptography` pkg ([`pubspec.yaml`](pubspec.yaml:13), [`kdf.dart`](lib/src/crypto/kdf.dart:33), [`aead.dart`](lib/src/crypto/aead.dart:9)) | Audited bindings only: libsodium FFI (v2 §2) |
| Secret memory | Dart `Uint8List` + manual zero ([`secure_buffer.dart`](lib/src/crypto/secure_buffer.dart:5)) | `sodium_malloc/ sodium_mlock` native secure memory (v2 §4) |
| Key model | Single `EncKey` encrypts whole vault JSON ([`vault_crypto.dart`](lib/src/crypto/vault_crypto.dart:28)) | Per-entry hierarchy VRK + DEK_i (v3 §19) |
| File header | `'VULT'` / formatVersion=1 / 43B ([`header.dart`](lib/src/crypto/header.dart:8), [`constants.dart`](lib/src/crypto/constants.dart:3)) | `'GEN4'` / v4 / `vault_count=2` + wrapped-DEK table + `search_tag` + header MAC (v4 §4.3) |
| Entry model | `id,title,username,password,url` ([`vault_data.dart`](lib/src/vault/vault_data.dart:5)) | tier, per-entry DEK, per-entry vector clock, search_tag, schema_version, type (password/TOTP/canary/SSH) |
| HKDF info string | `'vault/v1/enc'` ([`kdf.dart`](lib/src/crypto/kdf.dart:60)) | `'GENESIS-VRK-v4'`, `'GENESIS-SEARCH-v4'`, `'GENESIS-VRK-DURESS'` (v4 §5/§8) |
| Sync Noise | MethodChannel stub, `TODO` native FFI ([`native_noise.dart`](lib/src/sync/native_noise.dart:5)) | Native Noise PSK + PQ-hybrid X25519/ML-KEM-768 (v3 §21.1) |
| Conflict granularity | Whole-vault vector clock ([`vector_clock.dart`](lib/src/sync/vector_clock.dart:2)) | Per-entry vector clocks (v3 §20.2) |
| 2FA / tiers / breach / Shamir / decoy / passkeys / PQ | absent | required by v3 §12-24, v4 §6 |
| Linux hardening | prctl + mlockall only ([`process_hardening.dart`](lib/src/os/process_hardening.dart:19)) | + seccomp-bpf (v3 §4, preserved by v4 §3) |

### 0.2 Demolition list (files superseded, not patched around)

These v2 files are replaced by the Phase 0 + Phase A work:

- [`lib/src/crypto/aead.dart`](lib/src/crypto/aead.dart) — REPLACE with libsodium FFI AES-256-GCM.
- [`lib/src/crypto/kdf.dart`](lib/src/crypto/kdf.dart) — REPLACE with libsodium Argon2id + HKDF + v4 info strings.
- [`lib/src/crypto/header.dart`](lib/src/crypto/header.dart) + [`lib/src/crypto/constants.dart`](lib/src/crypto/constants.dart) — REPLACE with v4 §4.3 layout.
- [`lib/src/crypto/vault_crypto.dart`](lib/src/crypto/vault_crypto.dart) — REPLACE flat blob with per-entry hierarchy.
- [`lib/src/crypto/secure_buffer.dart`](lib/src/crypto/secure_buffer.dart) — REPLACE Dart list with FFI native secure buffer.
- [`lib/src/vault/vault_data.dart`](lib/src/vault/vault_data.dart) + [`lib/src/vault/vault_storage.dart`](lib/src/vault/vault_storage.dart) — REPLACE with per-entry model + v4 two-slot storage.
- [`lib/src/sync/native_noise.dart`](lib/src/sync/native_noise.dart) + [`lib/src/sync/noise_controller.dart`](lib/src/sync/noise_controller.dart) — REPLACE stub with real native PQ-hybrid Noise.
- [`lib/src/os/process_hardening.dart`](lib/src/os/process_hardening.dart) — ADD seccomp-bpf filter.
- [`pubspec.yaml`](pubspec.yaml) — DROP `cryptography`; ADD FFI bindings.

### 0.3 Carry-forward (already correct, survives with extension)

- [`lib/src/lock/*`](lib/src/lock) (backoff, reducer, state, intent, auto-lock) — survives; Phase C extends with adaptive posture + behavioral biometrics.
- [`lib/src/backup/*`](lib/src/backup) (mp_strength, snapshot_manager, csv_importer) — survives; F.6 adds 2FA-interaction handling.
- `lib/src/biometric/*`, `lib/src/clipboard/*`, `lib/src/desktop/*` — survive; Phases D/E add real platform code (Android Keystore/autofill/DAL, TPM 2.0 sealing).
- [`lib/src/sync/vector_clock.dart`](lib/src/sync/vector_clock.dart) — algorithm survives; **usage** becomes per-entry (v3 §20.2).
- [`lib/src/crypto/padding.dart`](lib/src/crypto/padding.dart) — size-bucket logic survives unchanged.
- `test/` — rewritten red/green against the new specs, per rules_light tracer-bullet TDD.

---

## 1. DELTA MAP (v2 -> v3 -> v4)

### 1.1 v2 -> v3 (what [`pass_v3_final_master_plan_EN.md`](pass_v3_final_master_plan_EN.md) adds)

- §12: 2FA/MFA — TOTP KDF-bound (not a UI gate), companion-device push approval (number-matching), backup codes (10 single-use, Argon2id-hashed, stored outside vault), stored-TOTP for third-party accounts, clock-skew ±1 step.
- §13: Linux TPM 2.0 sealing (fallback libsecret/GNOME Keyring/KDE Wallet — never app-private file); app-downgrade note; MP-change and snapshot interactions with 2FA.
- §14: Risk tiers — Standard / Sensitive / Critical with per-tier reveal, autofill, push-approval, quick-copy policy; default heuristics (suggestion only); tier-downgrade cooldown + notification, tier-upgrade immediate.
- §15: Wallet-inspired hardening — autofill preview, look-alike/typosquat domain detection, MPC-style key split, Shamir (SLIP-39) opt-in recovery kit, decoy vault, Paired-device review/revocation, preview-before-commit (sync + CSV).
- §18: Threat landscape — infostealer reframing, passkeys/WebAuthn (v2 initiative, own threat-model pass), breach monitoring (Pwned Passwords k-anonymity, online + offline corpus, opt-in off-by-default), duplicate/weak password dashboard (fully local), FIDO2 hardware key unlock.
- §19: **Architectural revision** — per-entry key hierarchy (VRK + DEK_i), superseding the flat blob.
- §20: What hierarchy enables — crypto-shredding, fine-grained per-entry sync, native Critical-tier threshold access, capability-based scoped sharing.
- §21: PQ-hybrid Noise handshake now (X25519 + ML-KEM-768), Social P2P recovery, local integrity heartbeat, explicit rejection of autonomous rotation bot.
- §23: Phase L — key hierarchy migration as the new Phase A target.

### 1.2 v3 -> v4 (what [`v4.md`](v4.md) adds — the twelve)

As enumerated in v4 §2: honeypot canaries, duress MP + silent alert, rule-based adaptive posture, statistical behavioral biometrics, random-subset decryption, time-locked secrets (hash chain), cryptographic inheritance, two-vault deniability, searchable symmetric encryption (SSE), sync traffic padding, one-tap breach rotation, SSH keys as Critical-tier entries (v2 scope).

### 1.3 What v4 preserves from v3

See v4 §3. In particular: per-entry key hierarchy (v3 §19), per-entry vector clocks (v3 §20.2), PQ-hybrid Noise (v3 §21.1), and all of §12/§14/§15/§18 mechanisms carry forward unchanged.

---

## 2. DECISION GATES (rules_heavy JSpaceState)

Three architectural decisions govern the whole plan. Each is MCTS-evaluated: >=3 hypotheses, adversarial review, selected path.

### 2.1 Gate 1 — Sequencing v2 -> v3 -> v4

```json
{
  "current_state": "Codebase is pure-Dart flat-blob v2 with a stubbed Noise channel. v3 mandates a per-entry key hierarchy (VRK+DEK_i) replacing the flat blob; v4 mandates a new file format ('GEN4', vault_count=2, search_tag, header MAC) plus 12 additions layered on v3 mechanisms. The flat-blob crypto code has zero reuse value in the final architecture.",
  "hypotheses": [
    {
      "id": 1,
      "description": "Re-foundation merge: land libsodium FFI + PQ-Hybrid Noise + per-entry hierarchy + v4 file format as a single new Phase A, then run v3 feature phases, then v4 additions.",
      "confidence": 0.88,
      "risk": "Med",
      "complexity": "O(n) (one large Phase A rewrite, no re-migration)",
      "adversarial_review": "Largest contiguous rewrite; mitigated by tracer-bullet TDD (one test -> one impl) so the flat-blob tests are replaced, not abandoned. No user data exists to migrate. No intermediate format is ever shipped -> no downgrade/version ladder to maintain.",
      "justification": "v3 §19 explicitly states the flat blob must be revised 'before any Phase A implementation begins' and v4 §8 Phase A already specifies the merged per-entry + v4-format target. Writing flat-blob-with-FFI first, then per-entry, then v4-format would triple the header/KDF/churn for zero value."
    },
    {
      "id": 2,
      "description": "Literal version ladder: finish v2 as-spec'd (flat blob + FFI), then migrate flat->per-entry (v3), then per-entry->v4 format.",
      "confidence": 0.25,
      "risk": "Low",
      "complexity": "O(n) x3 (three Kafka-esque migrations)",
      "adversarial_review": "Every migration needs its own backward-compat reader/tests that are immediately thrown away. Two format bumps (v1->v3-header->v4-header) create dead code and two migration test suites. Rejected as pure tax.",
      "justification": "Fails the rules_light deletion test: intermediate flat-blob-with-FFI state concentrates no complexity; it is churn."
    },
    {
      "id": 3,
      "description": "Big-bang v4: skip v3 mechanisms, jump straight to final v4 architecture + all 12 additions.",
      "confidence": 0.15,
      "risk": "High",
      "complexity": "O(n^2) (untestable monolith)",
      "adversarial_review": "v4 additions build on v3 mechanisms (duress on decoy vault, adaptive posture on tiers, one-tap rotation on breach monitoring, SSH on Critical tier Shamir-split). Skipping v3 means re-inventing those foundations inline, violating tracer-bullet discipline and producing no intermediate acceptance criteria.",
      "justification": "Rejected: v4 §3 and §7 depend on the v3 substrate; the 'via v3 route' instruction is the correct dependency order."
    }
  ],
  "selected_path": 1,
  "justification": "Re-foundation merge eliminates redundant migrations while preserving the full v3 substrate that v4 depends on. It is exactly what v3 §19 and v4 §8 Phase A jointly prescribe.",
  "action": {
    "tool": "apply_patch",
    "command": "Implement Phase 0 (native dep swap) then Phase A (per-entry + v4 format) as one continuous red-green loop; see section 3.",
    "expected_result": "Phase A passes v4 §8 Phase A acceptance criteria with no pure-Dart crypto dependency remaining."
  }
}
```

### 2.2 Gate 2 — Native dependency acquisition

```json
{
  "current_state": "Specs require libsodium (secure mem, Argon2id, AES-GCM, HKDF, HMAC, SHA-256, X25519/Ed25519, constant-time), Noise PSK, and ML-KEM-768 (PQClean/liboqs). Current repo uses pure Dart and a MethodChannel TODO stub. J-Space rules forbid guessing tool signatures; bindings must be exact.",
  "hypotheses": [
    {
      "id": 1,
      "description": "dart:ffi bindings to prebuilt system libraries (libsodium + PQClean/liboqs), dynamic-load style as already used in process_hardening.dart for prctl.",
      "confidence": 0.82,
      "risk": "Med",
      "complexity": "O(n) (hand-written bindings for ~30 symbols each)",
      "adversarial_review": "Hand-written FFI is error-prone at the lookupFunction boundary; mitigated by a thin isolate-safe wrapper + a startup self-test that round-trips a known vector. No build-system rewrite. Matches the existing prctl/mlockall FFI precedent exactly.",
      "justification": "libsodium is the single audited-surface the spec already names (v2 §2 'libsodium or BoringSSL-class'). PQClean/liboqs provides ML-KEM-768 without a heavy toolchain."
    },
    {
      "id": 2,
      "description": "Compiled Rust cdylib via flutter_rust_bridge exposing libsodium + snow (Noise) + PQ clean.",
      "confidence": 0.6,
      "risk": "Low",
      "complexity": "O(n log n) (Rust toolchain + codegen added)",
      "adversarial_review": "Highest-quality Noise/PQ primitives (snow, pqcrypto crates) and memory safety for the native side. Cost: adds cargo + build glue to both Android (NDK) and Linux (cmake), a large moving part relative to value for this stage.",
      "justification": "Strong long-term candidate; deferred as a possible Phase 0.x replacement if hand-written FFI becomes unmaintainable, not pursued now."
    },
    {
      "id": 3,
      "description": "Keep pure-Dart cryptography package.",
      "confidence": 0.05,
      "risk": "High",
      "complexity": "O(1) (no change)",
      "adversarial_review": "Directly violates v2 §2 (audited bindings only) and v2 §4 (native secure memory). Pure-Dart Argon2id is not the audited binding and Dart Uint8List cannot provide sodium_mlock/PR_SET_DUMPABLE-semantics. SecureBuffer.dart already self-documents this gap.",
      "justification": "Rejected on spec compliance grounds; no mitigation exists for the managed-heap residue class."
    }
  ],
  "selected_path": 1,
  "justification": "libsodium via dart:ffi is the spec-mandated audited surface and mirrors the existing FFI precedent; Rust bridge is a heavier alternative kept in back pocket.",
  "action": {
    "tool": "apply_patch",
    "command": "Add native FFI layer for libsodium + PQClean(ML-KEM-768) and a Noise PSK static/ephemeral keypair + handshake; delete cryptography dependency.",
    "expected_result": "Startup self-test round-trips a known AES-GCM/Argon2id/HKDF vector and a Noise handshake; memory-dump test shows no residual plaintext."
  }
}
```

### 2.3 Gate 3 — Phase A target: single-pass to v4 format vs v3-intermediate header

```json
{
  "current_state": "v3 §19 specifies the per-entry hierarchy but leaves the header as the v2 layout extended with a wrapped-DEK table. v4 §4 specifies the final header ('GEN4', vault_count=2, search_tag, header MAC). Choosing whether to ship an intermediate v3 header then rewrite to v4.",
  "hypotheses": [
    {
      "id": 1,
      "description": "Single-pass Phase A directly to the v4 §4.3 file format (per-entry hierarchy + vault_count=2 + search_tag + header MAC as AAD).",
      "confidence": 0.86,
      "risk": "Low",
      "complexity": "O(n)",
      "adversarial_review": "No migration needed because no real user data exists (all current files are test fixtures). v4 §8 Phase A already enumerates A.1-A.14 as the definitive target, including the v3 per-entry hierarchy in A.4-A.7. Writing a v3 header then a v4 header doubles header/test work with zero shipped-artifact value.",
      "justification": "Single source of truth; avoids a dead intermediate format. The per-entry hierarchy from v3 §19 is fully represented inside v4 Phase A steps A.4-A.7."
    },
    {
      "id": 2,
      "description": "Implement v3 header first (per-entry, v2-ish header + DEK table), then migrate to v4 header.",
      "confidence": 0.3,
      "risk": "Low",
      "complexity": "O(n) x2",
      "adversarial_review": "Two serialized header formats, two sets of parse/serialize tests, two AAD layouts. Only defensible if v3 were already deployed in the field; it is not.",
      "justification": "Rejected under the deletion test and the actual codebase state."
    },
    {
      "id": 3,
      "description": "Skip search_tag/vault_count now; land per-entry hierarchy only, add v4 format fields later.",
      "confidence": 0.4,
      "risk": "Med",
      "complexity": "O(n)",
      "adversarial_review": "v4's Phase G (SSE), Phase J (deniability), and Phase M (search) all depend on vault_count and search_tag existing in the header and being AAD-authenticated. Deferring them forces a later header rewrite that invalidates all GCM tags of prior test fixtures and any real vault.",
      "justification": "Rejected: header format is the most expensive thing to change later; land it once."
    }
  ],
  "selected_path": 1,
  "justification": "Single-pass to the final v4 format is cheapest now (no shipped data) and keeps the header-format change amortized exactly once.",
  "action": {
    "tool": "apply_patch",
    "command": "Implement Phase A per v4 §8 A.1-A.14 with the v4 §4.3 header as the only format.",
    "expected_result": "vault_count always 2 with second slot indistinguishable from noise; search_tag computed; header tamper fails GCM; no v3-only header ever shipped."
  }
}
```

### 2.4 Rules reconciliation (heavy vs light)

- **Decision gates (architecture choices):** emit JSpaceState JSON per rules_heavy §6. That is what sections 2.1-2.3 are.
- **Code and inline docs:** caveman terse prose per rules_light §1/§7 (`Intent:` / `Invariants:` / `State Transition:` / `Dependencies:` tags).
- **Inside each phase:** rules_light tracer-bullet — ONE test -> ONE minimal implementation -> refactor, never a horizontal test-then-impl sweep.
- **Critical crypto/state-machine code:** PBT invariants + mutation testing (>=90% kill) per rules_heavy §4; formal note where Lean/Dafny is overkill.

---

## 3. CONSOLIDATED PHASED ROADMAP

Canonical step-level detail for Phases A-P lives in [`v4.md` §8](v4.md). This section supplies the **new Phase 0** that v4.md omits (it assumed v3 deps were complete) and marks, per phase, what is new vs carried from v3. Executor must hold both documents.

### Phase 0 — Foundation Swap (NEW; blocks everything; not in v4.md)

**0.1** Drop `cryptography` dep. Add dart:ffi layer: libsodium (secure mem, Argon2id, AES-256-GCM, HKDF-SHA256, HMAC-SHA256, SHA-256, X25519/Ed25519, constant-time compare) + PQClean/liboqs (ML-KEM-768).
**0.2** Rebuild [`secure_buffer.dart`](lib/src/crypto/secure_buffer.dart) as FFI `sodium_malloc/sodium_mlock/sodium_memzero`; zero-wipe on lock/background/terminate/entry-delete.
**0.3** Linux: add seccomp-bpf syscall filter on top of existing prctl+mlockall ([`process_hardening.dart`](lib/src/os/process_hardening.dart:19)).
**0.4** Replace [`native_noise.dart`](lib/src/sync/native_noise.dart) stub with real native Noise PSK channel: static keypair at install, ephemeral per session, forward secrecy (v2 §6.2), PQ-hybrid X25519+ML-KEM-768 (v3 §21.1).
**0.5** Startup self-test: round-trip known vector per primitive; hook into `main()`.

**AC:** memory-dump post-lock shows no residual plaintext · ptrace blocked · VmLck verified via /proc/pid/status · 10k nonce-uniqueness · active+passive MITM fail without PIN · no `cryptography` import remains.

### Phase A — Crypto Core (per-entry + v4 format)

**Carried superset of [`v4.md` §8 Phase A](v4.md), steps A.1–A.14, executed as a red-green loop.** Highlights:
- A.4 VRK = HKDF(MK, "GENESIS-VRK-v4"); A.5 SearchKey = HKDF(VRK, "GENESIS-SEARCH-v4"); A.6 DEK_i wrapped under VRK; A.7 per-entry AEAD + size-bucket padding.
- A.9 `vault_count=2` always; A.10 header as AAD; A.13 duress derivation ("GENESIS-VRK-DURESS"); A.14 time-lock SHA-256 chain.
- **Settles Gate 3:** first and only format is v4 §4.3.

**Blocked by:** Phase 0.

### Phases B–P — v3 mechanisms + v4 additions (see v4 §8 for steps)

| Phase | Scope (v4 §8) | New vs carried | Blocked by |
|---|---|---|---|
| B | Memory + process hardening | carried v3 §4 (native now real) | A |
| C | Lock/reveal + adaptive posture (6.3) + behavioral biometrics (6.4) + random-subset (6.5) | merge v3 lock + v4 3 additions | B |
| D | Android (biometric/autofill/DAL/clipboard/accessibility/Doze/root) | carried v3 §5.1 | A (D.1), C (D.2) |
| E | Linux (hotkey/tray/clipboard/TPM 2.0) | carried v3 §5.2 + §13 TPM | C |
| F | Backup/snapshots/import/export | carried v3 §7 + F.6 2FA snapshot note | A |
| G | P2P sync: PQ-hybrid Noise (done in 0.4), per-entry vector clocks (v3 §20.2), conflict archive, traffic padding (6.10), device review | v3 §6 + §20.2 + v4 padding | A (G.1), C (G.4) |
| H | 2FA/MFA (TOTP KDF-bound, push approval, backup codes, stored TOTP, clock skew, FIDO2) | carried v3 §12 | A (H.1), G (H.4) |
| I | Risk tiers + wallet hardening (autofill preview, look-alike, Shamir, preview-before-commit, capability sharing, tier-downgrade time-lock) | carried v3 §14/§15/§20.3/§20.4 | C (I.1), H (I.1 Critical), D (I.4), G (I.6), A (I.8) |
| J | Coercion resistance + deniability (canaries 6.1, duress 6.2, two-vault 6.8) | v4 NEW | A (J.1-3), C (J.2 shred) |
| K | Breach dashboard + monitoring + one-tap rotation (6.11) | v3 §18 + v4 rotation | A (K.1), I (K.3) |
| L | Time-locks (6.6) + inheritance (6.7) | v4 NEW | A (L.1), J (L.2 Shamir), G (L.2 social recovery) |
| M | SSE search (6.9) | v4 NEW (SearchKey/tags already in A) | A |
| P | Integrity heartbeat + runtime check + reproducible builds | carried v3 §21.4/§12.10 | A (P.1), P.2-4 independent |
| N | Passkeys/WebAuthn | v2 scope; own threat-model pass first | A, G |
| O | SSH keys as Critical entries (6.12) | v2 scope | A, C, I |

---

## 4. DEPENDENCY GRAPH

```
Phase 0 (Foundation Swap: libsodium FFI + PQ Noise + seccomp + secure buffer)
 |
 +-- Phase A (per-entry hierarchy + v4 file format)   <-- supersedes flat-blob v2
      |
      +-- Phase B (hardening)
      |    |
      |    +-- Phase C (lock / adaptive / behavioral / random-subset)
      |         |
      |         +-- Phase D (Android)
      |         +-- Phase E (Linux / TPM)
      |         +-- Phase I (tiers + wallet)  <-- also needs H (Critical M-of-N)
      |         +-- Phase J (coercion / deniability)
      |
      +-- Phase F (backup / snapshots / import-export)
      |
      +-- Phase G (P2P sync + PQ + per-entry VC + padding)
      |    |
      |    +-- Phase H (2FA / MFA)
      |         |
      |         +-- Phase I (tiers; Critical push approval)
      |
      +-- Phase K (breach + dashboard + one-tap rotation)   <-- needs I
      +-- Phase L (time-locks + inheritance)                <-- needs J, G
      +-- Phase M (SSE search)                              <-- SearchKey/tags from A
      +-- Phase P (integrity / provenance)
      |
      +-- Phase N (passkeys, v2)   <-- own threat-model pass
      +-- Phase O (SSH keys, v2)
```

---

## 5. IMPLEMENTATION DISCIPLINE (merged rules)

1. **Decision gates in JSON.** Any cross-cutting architectural fork emits a JSpaceState JSON (>=3 hypotheses, confidence/risk/complexity, adversarial_review, selected_path). No free-text architectural essays.
2. **Atomic patches only.** No whole-file rewrites except where a file is explicitly on the demolition list (§0.2) — and even then, each commit is one test plus the minimal lines to green it.
3. **Tracer-bullet TDD.** One test -> one minimal impl -> refactor. Never all-tests-first.
4. **PBT + mutation.** Crypto and state machines get property-based invariants (nonce uniqueness, round-trip, clock monotonicity) and must exceed 90% mutation kill.
5. **No new deps** beyond: libsodium, PQClean/liboqs (ML-KEM-768), Noise library. No ML frameworks.
6. **Kill switches.** Every v4 feature has an off switch; features that out-cost their value get removed, per v4 §12.
7. **Honest limitations in UI.** Decoy, time-lock calibration, SSE domain-privacy trade-off, capability-sharing analog-hole — all stated plainly (v4 §12.4).
8. **Invariants absolute.** Zero-cloud: only network egress is opt-in breach monitoring (5-char prefix or offline corpus). Zero-recovery: inheritance is opt-in and self-custodied. Sync optional: app works offline forever.

---

## 6. DEFINITION OF DONE (v2 -> v4 complete)

- [ ] Phase 0 self-test green; `cryptography` package removed; memory-dump clean; Noise handshake is native + PQ-hybrid.
- [ ] Phase A: per-entry VRK+DEK_i hierarchy; v4 §4.3 header (`GEN4`, `vault_count=2`, `search_tag`, header MAC); nonce uniqueness 10k; DEK destruction = crypto-shred of one entry only.
- [ ] v3 substrate present: KDF-bound TOTP (fails at GCM, not an if-check), backup codes outside vault, risk tiers with tier-downgrade time-lock, PQ-hybrid Noise, per-entry vector clocks, breach k-anonymity opt-in, Shamir opt-in, decoy vault.
- [ ] v4 twelve additions present + acceptanced per v4 §6.1–6.12.
- [ ] Duress/adaptive/behavioral/canary cross-interactions honored per v4 §7 interaction matrix (duress suspends canary+biometric, no adaptive escalation during duress, Critical excluded from random-subset decoys, decoy never syncs, SSE scoped to unlocked vault).
- [ ] `flutter analyze` clean, `flutter test` green, Android + Linux build reproducible.

---

**Status: analysis and specification complete. No v3/v4 implementation started. Execution begins at Phase 0.1 (dependency swap), then Phase A (per-entry + v4 format) under tracer-bullet TDD.**