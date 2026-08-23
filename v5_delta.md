# V5 Delta Specification — Corrections to V4

**Purpose:** Eliminate every internal contradiction and false claim in the v4
document set. V5 changes almost nothing the user sees; it makes the correctness
surface total. This document is the single source of truth for every corrected
mechanism, keyed by audit error ID (E1..E23).

**Source docs in this repo:** [`roadmap_v2_to_v4.md`](roadmap_v2_to_v4.md),
[`pass_v3_final_master_plan_EN.md`](pass_v3_final_master_plan_EN.md),
[`status.md`](status.md). `v4.md`/`v3.md`/`v2.md` are referenced but not present
as files here; their carried content is superseded by this delta.

**Doctrine (unchanged, now enforceable):** zero-cloud · zero-trust ·
zero-recovery-by-design · smart-over-more · honest limitations · no home-rolled
crypto · sync optional.

---

## V0.1 — Error Index (E1..E23 → correction → phase)

| ID | Severity | Finding (one line) | Correction section | Closure phase |
|----|----------|--------------------|--------------------|---------------|
| E1  | FATAL | Inheritance confuses calendar time with CPU time | §D1 | V5.3–V5.5 |
| E2  | FATAL | Backup codes cannot coexist with KDF-bound 2FA | §D2 | V3.1–V3.2 |
| E3  | FATAL | Duress salt leaks existence; spec self-contradicts | §D3 | V1.1 |
| E4  | FATAL | Decoy vault lives in a separate file | §D4 | V1.3 |
| E5  | HIGH | Duress shred undefined for Shamir-split DEKs | §D5 | V4.1 |
| E6  | HIGH | Shred/cancel propagation race | §D6 | V4.2–V4.3 |
| E7  | HIGH | Snapshot + conflict archive resurrect shredded material | §D7 | V4.5 |
| E8  | HIGH | Breach monitoring hash mismatch (SHA-256 vs HIBP SHA-1) | §D8 | V2.2 |
| E9  | HIGH | PQ-hybrid claimed, PQ stubbed | §D9 | V2.3, V7.4 |
| E10 | HIGH | Nothing native compiled/verified on target | §D10 | V7.1–V7.7 |
| E11 | MEDIUM | Time-lock enforcement claim false | §D11 | V5.1–V5.2 |
| E12 | MEDIUM | Outer GCM plaintext ambiguous | §D12 | V1.2 |
| E13 | MEDIUM | SSE threat model mis-stated; real leak is tag count | §D13 | V1.4 |
| E14 | MEDIUM | Hand-rolled HKDF violates doctrine | §D14 | V2.1 |
| E15 | MEDIUM | Behavioral stats unsound; FP figure fabricated | §D15 | V6.1 |
| E16 | MEDIUM | Adaptive rule 2 erodes usability on laptops | §D16 | V6.2 |
| E17 | MEDIUM | MP-change re-wrap spec'd lazily | §D17 | V3.3 |
| E18 | MEDIUM | Noise PSK offline dictionary on low-entropy PIN | §D18 | V2.4 |
| E19 | MEDIUM | Seccomp allow-list vs Dart VM = crash lottery | §D19 | V7.1 |
| E20 | MEDIUM | Biometric fast path removes duress signal | §D20 | V6.3 |
| E21 | MEDIUM | Cancellation code storage/rate-limit unspecified | §D21 | V4.4 |
| E22 | MEDIUM | Dead code: v3-file compatibility branch | §D22 | V1.5 |
| E23 | MEDIUM | Mutation testing mandated, never run | §D23 | V8.1 |

---

## D1 — Inheritance: signed epoch liveness tokens (E1, E11)

**Wrong (v4 §6.7/§5.2/§6.6):** lock duration encoded as a SHA-256 chain of
`N = duration × hashes/sec` (~104 days of CPU); every unlock recomputes a fresh
chain. Unimplementable — a hash chain encodes CPU-seconds, not wall-clock days.

**Correct (v5 §1.9):**
- **LIVENESS** = signed epoch tokens. Each normal unlock emits `(epoch++,
  timestamp)` signed under `TokenKey = HKDF(VRK, "GENESIS-LIVENESS-v5")`.
  Tokens propagate to heir custody automatically (paired heir devices) or via
  manual export file. No server.
- **ACTIVATION** = K-of-N Shamir shares + heir's latest token older than
  check-in interval + grace period (verified on heir device; heir-clock trust
  documented) + short friction-chain unwrap of the bundle key.
- **CHECK-IN** = normal vault usage; zero extra action.
- **REVOCATION** = destroy metadata + re-encrypt designated entries under fresh
  DEKs + epoch invalidation. Old shares + old tokens become useless.
- **CREATION COST** = seconds. No multi-month chain is ever computed.
- UX warns when inheritance is armed and the vault has been unlocked for a long
  time. Premature activation on long absence = stated honest limitation with
  generous-interval guidance.

**Deletes:** the "patched build cannot skip" claim; the "Wait. Correction."
artifact.

---

## D2 — Backup codes coherent with KDF-bound 2FA (E2)

**Wrong (v4 H.1 × H.3):** `MK_full = HKDF(Argon2id(MP,salt) || SFM)` makes the
second factor math, yet H.3 says backup codes are stored only as Argon2id
hashes — a hash proves possession but cannot reconstruct the TOTP seed. "Using a
valid code disables 2FA for that session" has no code path.

**Correct (v5 §1.3):**
- `SecondFactorMaterial` (SFM) is stored **encrypted under MK_base** (the
  pre-second-factor key) in a file **outside** the vault.
- A valid backup code (Argon2id-hashed, single-use, rate-limited) **authorizes
  release of SFM into the KDF**. The vault opens via the **real derivation
  path** — no bypass branch exists.
- On SFM release: **immediate forced 2FA re-setup**.
- MP change **re-encrypts the SFM file** (seed untouched).
- Delete "disables 2FA for that session".

---

## D3 — Single salt; dual derivation always (E3)

**Wrong (v4 §5.3 × §4.3 × §6.8):** duress salt stored "alongside" primary salt
(→ header shape detects feature); §6.8 claims indistinguishability; unlock text
"try primary first" contradicts constant-time.

**Correct (v5 §1.2/§1.3):**
- **ONE 16-byte salt.** `MK = Argon2id(MP, salt)` ·
  `MK_duress = Argon2id(duressMP, SAME salt)`.
- Unlock **always** performs both derivations + both GCM checks, then selects.
  Constant total time → no timing oracle for which vault opened.
- Per-derivation Argon2id calibrated to **half** the latency target so total
  unlock stays in envelope.

---

## D4 — Decoy vault inside slot 2, never a separate file (E4)

**Wrong (status.md Phase J):** decoy persisted to `vault.decoy` — two files
announce the feature to any directory listing.

**Correct (v5 §1.2):**
- **One file.** Slot 1 = primary vault. Slot 2 = decoy vault if deniability
  enabled, CSPRNG noise otherwise. Identical structure in both cases.
- **No separate decoy file exists on disk — ever.**
- Duress presence undetectable from the file: one salt either way, two slots
  either way, slot 2 noise-or-decoy, GCM fails on noise.
- Migration: absorb any loose `vault.decoy` into slot 2 at next unlock;
  secure-delete the loose file (fixtures only, no real users).

---

## D5 — Group shred for Shamir-split Critical DEKs (E5)

**Wrong (v4 §6.2 × v3 §19):** Critical DEKs Shamir-split (2-of-3); §6.2 shreds
"locally" and sends only an ALERT. Destroying one local share under 2-of-3
leaves the secret reconstructable from the other two.

**Correct (v5 §1.4):**
- Critical shred is a **group operation**: `SHRED_SCHEDULED` broadcasts to all
  share holders; each destroys its share at the deadline. Critical becomes
  unrecoverable when surviving shares < K. Default 2-of-3 → two destroyed
  shares suffice; all are scheduled.

---

## D6 — Shred/cancel propagation with deferral (E6)

**Wrong:** no `SHRED_SCHEDULED`/`SHRED_CANCELLED` messages; offline peer may
shred after a cancellation exists; cancellation via decoy session unspecified.

**Correct (v5 §1.4/§1.7):**
- Define `SHRED_SCHEDULED` / `SHRED_CANCELLED` (idempotent, vector-clock
  ordered) in the sync message set.
- **DEFERRAL RULE:** a device executes shred only after delay AND after
  confirming no unprocessed cancellation from the originator. Offline → DEFER
  until next successful Noise handshake or local cancellation-code entry.
  Delay always resolves toward preservation.
- **Cancellation is code-only** (8-digit code). The decoy session cannot
  cancel. No session-path cancellation exists.

---

## D7 — Purge + reseed snapshots/conflicts on shred (E7)

**Wrong (v4 §6.2 + F.2):** last-5 snapshots and `conflicts/` still hold wrapped
DEKs/shares after shred; restoring revives "destroyed" entries.

**Correct (v5 §1.4/§1.10):**
- Snapshots and conflict archive are **purged and reseeded** on any DEK/share
  destruction event. Shredded material is not restorable from local history.
- Documented in the shred confirmation UI.

---

## D8 — Breach monitoring uses HIBP SHA-1 (E8)

**Wrong (status.md Phase K):** "5-char SHA-256 prefix" — HIBP k-anonymity is
SHA-1; SHA-256 prefixes never match the API.

**Correct (v5 §1.10):**
- `BreachMonitor` uses **SHA-1** as the HIBP interop identifier (never for
  storage). 5-char prefix only, opt-in, off by default.
- Offline corpus mode is the preferred default within the opt-in; consent names
  exactly what leaves the device.
- Test asserts full hash never leaves the device (egress assertion).

---

## D9 — PQ badge gated on ML-KEM self-test (E9)

**Wrong:** docs mandate X25519 + ML-KEM-768; shipped classical-only while
claiming PQ.

**Correct (v5 §1.7):**
- PQ-hybrid Noise = X25519 + ML-KEM-768 (PQClean via FFI), both shared secrets
  combined into the handshake via **HKDF KDF-combiner** (not XOR).
- UI shows a PQ badge **only** when the ML-KEM round-trip self-test passes.
  Stub builds never claim PQ.

---

## D10 — On-device verification is the real debt (E10)

**Finding:** Kotlin Keystore/autofill/FLAG_SECURE uncompiled; seccomp never
executed; tray/hotkey native helpers uncompiled; real Noise unbuilt. 150 green
pure-Dart tests prove logic, not delivery.

**Correct:** Phase V7 (build-host pass, one host each). Every on-device
acceptance criterion checked off with a recorded result in `status.md`; no ⏸
remains. See V7.1–V7.7.

---

## D11 — Time-lock reclassified honestly (E11)

**Wrong (v4 §6.6):** "even a patched build cannot skip the time-lock" — false;
seed + iteration count sit next to the wrapped DEK.

**Correct (v5 §1.9):**
- **(a) CPU-friction hash chain:** sequential SHA-256 from a CSPRNG seed,
  calibrated on the creating device, capped at short durations (minutes to a
  few hours). Friction only. Never claimed to stop a patched build or faster
  hardware — spec says exactly that.
- **(b) Device-enforced cooldowns:** signed monotonic timestamps + app policy
  for tier-downgrade cooling. Honest limitation stated.

---

## D12 — Outer GCM semantics pinned (E12)

**Wrong (v4 §4.3 + A.10):** header as AAD; GCM message never defined.

**Correct (v5 §1.2):**
- Header MAC = **AES-256-GCM with EMPTY plaintext** over the entire header as
  AAD. The 16-byte tag **is** the header authentication. No ambiguity: two
  implementers cannot diverge. Entry payloads authenticate separately under
  DEK_i.

---

## D13 — SSE threat model corrected + tag-count padding (E13)

**Wrong (v4 §4.2/§5.1/§6.9):** claims file-only attacker can test candidate
domains — false (requires SearchKey). Real leaks are entry count and domain
length (tag count = len−2).

**Correct (v5 §1.8):**
- TRUE statement: without SearchKey (requires VRK, requires MP), tags are opaque
  pseudorandom blobs. A file-only attacker learns entry count and — before
  padding — domain length.
- Mitigation: per-entry tag lists padded to buckets (4/8/16/32/64) with random
  tags. Padding collisions → false-positive candidates, filtered at reveal time
  by decrypting the matched entry.
- Constant-time compare; SearchKey secure-memory only, wiped at lock; kill
  switch → full-decrypt search fallback.

---

## D14 — Native HKDF, no hand-rolled KDF (E14)

**Wrong (status.md Phase 0):** "libsodium lacks crypto_kdf_hkdf_sha256_*" — the
pinned libsodium 1.0.18 **exports** `crypto_kdf_hkdf_sha256_{keygen,extract,
expand}`. A no-home-rolled-crypto project hand-rolled a KDF.

**Correct (v5 §1.1):**
- Native HKDF-SHA256 via `crypto_kdf_hkdf_sha256_*`, **symbol-probed at
  startup**; RFC 5869 known-answer tests; no hand-rolled HKDF anywhere.
- If symbols are genuinely absent in a build env → **fail closed**, do not
  hand-roll.

---

## D15 — Behavioral biometrics: log-space, gated, honest (E15)

**Wrong (v4 §6.4):** flight times right-skewed but modeled Gaussian; 3–5 samples
per pair → σ is noise; "0.000027% false lock" fabricated.

**Correct (v5 §1.5):**
- Key-pair flight times in **log-space** (log-normal fit via Welford).
- Per-pair scoring activates only after **≥8 samples** for that pair; below the
  gate, a **global model with 3.5σ** threshold applies.
- 3 consecutive anomalous keystrokes → lock + re-auth. Disabled during duress;
  user kill switch; model encrypted under VRK; timing-only (never keystroke
  content).
- **Delete the fabricated FP figure.** Measure FP/FN empirically and report.

---

## D16 — Adaptive rule 2: strict roaming opt-in (E16)

**Wrong (v4 §6.3):** unknown-network → high posture on by default; a roaming
laptop lives in permanent high posture → users disable security.

**Correct (v5 §1.5):**
- Unknown-network escalation exists **only inside opt-in "strict roaming mode"**
  (off by default).
- Rule 1 (canary → lockdown), Rule 2 (≥2 failed MP in 5 min → HIGH), Rule 3
  (known network + no failures → LOW) unchanged otherwise.

---

## D17 — MP change is atomic re-wrap + re-tag (E17)

**Wrong (v4 §7.9):** search_tags recomputed "at next unlock" → mixed-state file
(old tags + new VRK) that cannot validate.

**Correct (v5 §1.3):**
- MP change = atomic: re-wrap all DEKs under new VRK, recompute all search_tags,
  rewrite header + all payloads in one **temp-file-then-rename** save. No lazy
  "fix on next unlock" state.
- MP change does not reset 2FA (seed untouched).

---

## D18 — Pairing passphrase ≥8 chars, Argon2id PSK (E18)

**Wrong (v3 §6.1):** PIN-as-PSK → captured handshake tested offline against PIN
guesses; 60s window only stops online attacks.

**Correct (v5 §1.7):**
- Pairing secret: **≥8-char alphanumeric passphrase**; PSK = Argon2id(passphrase,
  pairing salt committed in the invite) — raises offline dictionary cost.
- 60s window, attempt limit, cooldown, TOFU-then-pinned static keys preserved.
- Residual offline-dictionary note stated.

---

## D19 — Seccomp DENY-LIST (Dart-VM-safe) (E19)

**Wrong (v4 B.3 / 0.3):** syscall allow-list must cover the Dart VM (futex,
epoll, clone, exec-memory) — hand-written allow-list = crash lottery, never
executed.

**Correct (v5 §1.11):**
- Seccomp **DENY-LIST** of scraping/attach syscalls only: `ptrace`,
  `process_vm_readv`, `process_vm_writev`, `kcmp`, `perf_event_open`.
- Dart-VM-safe, with a runtime kill switch. Never an allow-list.

---

## D20 — Biometric × duress interaction (E20)

**Wrong (v4 §7.1):** duress requires typing; Android biometric fast path bypasses
typing → no duress signal under biometric coercion. Matrix omits the row.

**Correct (v5 §1.11):**
- Optional **"require MP on first unlock of the day"** so the duress path (which
  requires typing) stays reachable despite the biometric fast path.
- Biometric cannot signal duress — documented honestly.
- §7.1 interaction matrix adds the biometric×duress row.

---

## D21 — Cancellation code storage + rate limit (E21)

**Wrong (v4 §6.2):** 8-digit code shown once; storage format + verification +
brute-force rate limiting undefined.

**Correct (v5 §1.4):**
- Cancellation code stored **Argon2id-hashed**; **3 wrong attempts → full duress
  re-setup required**. No session-path cancellation.

---

## D22 — Delete v3-file compatibility branch (E22)

**Wrong (v4 §4.1 × Gate 3):** Gate 3 guarantees no v3 file ever shipped, yet
§4.1 specifies a v3-file reader.

**Correct (v5 §1.2):**
- **GEN4 or reject.** Single-pass, no dead reader code, no v3 compat branch.
  Delete it.

---

## D23 — Mutation campaign required + recorded (E23)

**Wrong:** roadmap/rules_heavy mandate ≥90% kill on crypto + state machines;
status.md records no campaign.

**Correct (v5 §1.12 / V8.1):**
- Mutation campaign over: crypto core, lock/posture FSMs, vector
  clocks/conflict resolver, replay counter, TOTP/SFM path. ≥90% kill or fix
  until reached; **record the number**. No release claim without a recorded
  campaign.

---

## Phase V0 Acceptance (this step)

- [x] `v5_delta.md` created with every patch marked by error ID (E1..E23).
- [x] Zero internal contradictions in the corrected text.
- [ ] (code phases V1–V8 follow; each ends with `status.md` update + closure
  evidence per §3.2 error→phase map.)

**Next step:** Phase V1 (file-format correctness: E3/E4/E12/E13/E22).
