# Final Master Plan: Local-First Password Manager (v3)

Zero-cloud. Zero-trust. Zero-recovery-by-design. Flutter (Android + Linux Mint), P2P LAN sync, single encrypted file per vault.

---

## 1. Threat Model — Attacker Profiles

| # | Attacker | Capability | Primary Goal | Primary Defense | Residual Risk |
|---|---|---|---|---|---|
| 1 | Remote, stolen vault file only | Has ciphertext (leaked backup, lost USB/phone export) | Offline brute-force MP | Argon2id adaptive-cost, header-authenticated | Weak MP still breakable eventually — MP strength gate on export |
| 2 | LAN attacker, pairing window | Same Wi-Fi during a pairing session | MITM the PIN exchange, impersonate a device | Noise Protocol w/ PIN-as-PSK, ≤60s window, attempt lockout | None known if Noise implemented correctly |
| 3 | LAN attacker, post-pairing | Same Wi-Fi, passive eavesdropper | Read/replay sync traffic | Per-session ephemeral Noise keys (forward secrecy), monotonic replay counter | Traffic-metadata (timing, size) still observable |
| 4 | Compromised trusted peer | Owns a previously-paired device now infected | Push malicious/rollback vault state | Vector-clock conflict resolution, not wall-clock | A fully compromised peer can still push garbage data — no cryptographic defense against a *legitimately authenticated* malicious peer; user must physically secure all paired devices |
| 5 | Local malware, same device, vault unlocked | Runs as another process/app while unlocked | RAM scrape, ptrace, clipboard sniff, accessibility read | Native secure memory (libsodium FFI), `PR_SET_DUMPABLE=0`, `mlockall()`, sensitive clipboard flag | Managed-runtime residue, accessibility-API read path (documented trade-off) |
| 6 | Evil-maid, brief physical access | Unattended unlocked device, minutes | Read/exfiltrate visible secrets | Auto-lock (idle/screen-off/minimize), per-entry reveal re-auth | Window between action and auto-lock trigger |
| 7 | Coerced or spoofed biometric | Forces owner's finger, or enrolls own print | Unlock via biometric gate | `invalidatedByBiometricEnrollment=true` (blocks silent print-add attack); coercion itself is a physical-safety issue outside app's control | Coercion of legitimate owner's own biometric — unsolvable at app layer |
| 8 | Rooted/jailbroken device | Full OS-level control | Bypass Keystore/sandbox guarantees | Advisory warning only, not blocking | Full compromise possible on rooted device — inherent OS trust boundary |
| 9 | Supply chain | Compromises a dependency or build pipeline | Inject backdoor | Pinned versions, audited crypto libs only (libsodium/boringssl-class), no home-rolled primitives | Zero-day in a trusted dependency — irreducible |
| 10 | User's own error | Weak MP, or loses only copy (no cloud) | N/A (self-inflicted) | MP strength gate, local versioned snapshots, backup reminders | Zero-recovery is a deliberate design choice — accepted, not a bug |

**Explicitly out of scope:** nation-state hardware implants, EM/power side-channel analysis, unpatched OS kernel 0-days, cryptographically-relevant quantum computers (see §9.6). These are unactionable at the application layer for a consumer local password manager.

---

## 2. Cryptographic Specification

- **KDF:** Argon2id. Adaptive calibration at first run, targeting ~500–1000ms derivation time on desktop, up to ~1500ms acceptable on mobile (single-shot cost at unlock). **Hard floor enforced by the application, independent of any value stored in the file header:** memory ≥ 64 MiB, iterations ≥ 3, parallelism = min(4, logical cores). Calibrated (or floor, whichever is higher) parameters are recorded in the header for reproducibility.
- **Key separation:** `MK = Argon2id(MP, salt, params)`. MK is **never** used directly as a cipher key. `HKDF-SHA256(MK) -> EncKey (32 bytes, AES-256-GCM)`. The P2P identity keypair (Noise static key) is a **separate, independently generated long-term key**, not derived from MP (see §6.1) — this decouples sync trust from MP lifecycle.
- **AEAD:** AES-256-GCM. Fresh CSPRNG 96-bit nonce on every encryption operation, verified unique per key (no counter-based nonce reuse risk accepted).
- **Header authentication (downgrade protection):** the header (magic, version, algorithm IDs, KDF params, salt, nonce) is passed as **Associated Data (AAD)** to AES-GCM. Any bit-level tampering with the header invalidates the GCM tag on decrypt. Combined with the app-enforced floor above, this closes the parameter-downgrade attack class entirely.
- **Padding / metadata minimization:** decrypted JSON payload is padded to a fixed size-bucket (e.g. next power-of-two-ish boundary: 4 KiB / 16 KiB / 64 KiB / 256 KiB) before encryption, reducing the precision with which file size reveals entry count.
- **Constant-time comparison** mandatory anywhere a secret or MAC/tag is compared.
- **No home-rolled crypto primitives.** Argon2id / AES-GCM / HKDF / Noise via audited bindings only (libsodium or BoringSSL-class libraries). Dependency versions pinned; changelog reviewed before any bump.

---

## 3. File Format (byte layout)

```
[ magic (4B) ][ format_version (1B) ][ kdf_algo_id (1B) ]
[ kdf_memory (4B) ][ kdf_iterations (4B) ][ kdf_parallelism (1B) ]
[ salt (16B) ][ nonce (12B) ]
[ AEAD ciphertext + 16B tag, padded to size-bucket, variable length ]
```

Header (everything before ciphertext) = AAD input to AES-GCM. `format_version` gates the crypto envelope; a **separate** `schema_version` field lives *inside* the encrypted JSON payload and gates the entry data model — the two must evolve independently (see §8.14).

---

## 4. Memory & Process Security

- All long-lived secrets (MK, EncKey, MP input buffer) allocated via **native secure memory through FFI** (`sodium_malloc` / `sodium_mlock` class APIs) — never as plain Dart `String` (immutable, lingers in managed heap) and never as an ordinary Dart `Uint8List` left to the GC. This eliminates the GC-compaction copy-leak class, not just the "zero after use" mitigation, which only handles the *last* copy, not prior compaction artifacts.
- Explicit zero-wipe triggered on: manual lock, auto-lock timeout, app background, app termination.
- **Linux:** `prctl(PR_SET_DUMPABLE, 0)` at startup (blocks external `ptrace` attach) + `mlockall()` (prevents decrypted pages from being swapped to disk in cleartext). Swap-encryption or swap-disable recommended to the user as a system-level setting, out of app's direct control.
- **Android:** relies on app sandboxing + hardware-backed Keystore (StrongBox where available). Android's `zram`/compression behavior for backgrounded app memory is kernel-managed and outside the app's control — accepted as an OS-level residual risk (§9).

---

## 5. Platform Integration

### 5.1 Android
- **Autofill Service:** verifies requesting app/origin via Digital Asset Links (`assetlinks.json`) before returning credentials — blocks lookalike-app phishing. Inline biometric/MP prompt gates every return.
- **Biometric Keystore gate:** `invalidatedByBiometricEnrollment = true` (mandatory — blocks the "attacker enrolls own fingerprint" attack), StrongBox when hardware supports it, MP always available as fallback.
- **Screen protection:** `FLAG_SECURE` on every screen displaying secrets — blocks screenshots, screen recording, and recent-apps thumbnail leakage.
- **Clipboard:** `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+) excludes copied passwords from clipboard history and cross-device clipboard sync; 30s auto-wipe timer regardless.
- **Accessibility surface:** secret fields excluded from the accessibility tree where feasible, documented as a trade-off against legitimate screen-reader accessibility needs — not fully solvable, both directions documented for the user.
- **Background/Doze:** session key wiped per auto-lock policy before the OS can reclaim/kill the process; re-unlock required on foreground return regardless of OS process lifecycle quirks.
- **Root detection:** advisory warning shown, never blocking — a rooted device weakens Keystore guarantees but the app remains usable for users who accept that trade-off.

### 5.2 Linux Desktop
- **Global hotkey:** X11 has no input-isolation model — any process can globally listen to keystrokes. This is documented as a **known, unfixable-at-app-layer limitation**, with a first-run warning. Wayland preferred where available (compositor portal `GlobalShortcuts` API), with X11 as an explicitly-flagged fallback.
- **Clipboard:** 30s auto-wipe; "sensitive" marking applied where the desktop clipboard manager supports it (best-effort only — X11 has no native sensitivity concept).
- **Process hardening:** same `PR_SET_DUMPABLE=0` + `mlockall()` as §4.
- **Tray icon:** binary locked/unlocked state only — never renders anything that could hint at vault contents.

---

## 6. P2P Sync Protocol

### 6.1 Identity & Pairing
Each device generates an independent long-term **Noise Protocol static keypair** at install time, stored in platform secure storage, **decoupled from the Master Password lifecycle** — an MP change never invalidates sync trust or requires re-pairing.

First pairing: mDNS discovery -> receiving device displays a 6-digit PIN -> PIN is used as the **pre-shared secret (PSK)** in a Noise handshake (PSK pattern), not compared in plaintext over the socket. Pairing session window ≤60s, attempt-limited, cooldown enforced before retry. On success, both sides pin the peer's static public key locally (TOFU-then-pinned trust model).

### 6.2 Session & Transport
Every subsequent sync opens a **fresh ephemeral Noise handshake** authenticated against the pinned static keys — forward secrecy per session, no PIN re-entry required. Every message on the wire carries a **monotonic per-session counter**; the receiver rejects any non-increasing value (replay protection). Peer identity is keyed to the static public key, not IP address or mDNS device name, so a device roaming to a new IP on the same LAN reconnects without re-pairing.

### 6.3 Conflict Resolution
Wall-clock timestamps are replaced with a **per-device monotonic counter / vector clock**. This closes the rollback-via-clock-skew attack from v1 of this plan. Simultaneous *online* edits on both devices at once (rare, requires both online concurrently) are handled the same as offline-then-sync conflicts: **coarse whole-vault conflict**, losing version auto-archived to a `conflicts/` folder, user prompted with a manual-merge UI. **Field-level CRDT merge is explicitly deferred out of v1 scope** — the complexity/risk is not justified until real usage data shows it's needed.

### 6.4 Availability & DoS
Discovery broadcasts are throttled; only one active pairing session permitted at a time; repeated pairing attempts from the same peer within a cooldown window are ignored. **Sync remains entirely optional — the app is 100% functional standalone, offline, forever.** This is re-confirmed as an architectural invariant (deletion test: removing the entire sync module leaves a fully working password manager with manual export/import).

---

## 7. Backup, Export, Import, Recovery

- **Manual export:** gated by an MP-strength check (warn, not block, before allowing export of a vault protected by a weak MP).
- **Local Versioned Snapshots (new):** the app automatically retains the last N (e.g. 5) successful encrypted save-states in app-private storage, independent of any manual export, with oldest-first rotation. This directly addresses the single-point-of-failure risk of "one file, no cloud, one bad write/bad sector = total loss."
- **Import — own format:** standard MP-gated decrypt.
- **Import — third-party CSV** (realistic scenario: migrating from LastPass/Bitwarden/etc.): the source file is plaintext on disk during the import window. Mitigation: read directly via file picker without persisting an extra copy beyond OS temp storage, prompt the user to securely delete the source file immediately after a successful import, and display an explicit warning about the plaintext exposure window — this cannot be fully eliminated, only minimized.
- **Recovery:** zero-recovery-by-design is the final, confirmed decision (§10). No backdoor, no server-side reset path exists or will be built.
- **Uninstall/reinstall risk:** because there is no cloud, uninstalling without a prior export is unrecoverable data loss. There is no reliable technical uninstall-hook on Android or Linux to intercept this. Mitigation is purely proactive: a non-dismissible prompt to complete at least one export before the reminder downgrades to periodic soft nudges.

---

## 8. Usage Scenario Walkthroughs

1. **First install / vault creation** — MP entered, strength-checked (warn only), Argon2id calibrated, empty vault created.
2. **Daily unlock** — biometric fast path (Android, Keystore-gated) or MP fallback; Linux always MP (no biometric hardware assumed) or OS-level equivalent if available later.
3. **Add/edit entry, generate password** — CSPRNG-backed generator, **rejection sampling** to avoid modulo bias when mapping random bytes to charset, passphrase mode uses a fixed vetted wordlist (EFF-large-wordlist class, ~7776 words, ~12.9 bits/word) with size disclosed to the user.
4. **Autofill from a third-party app** (Android) — origin-verified, biometric-gated, `FLAG_SECURE` throughout.
5. **Manual copy via desktop hotkey** — clipboard auto-wipe at 30s, sensitivity flag where supported.
6. **Auto-lock triggers** — idle timeout, screen-off, app minimize, manual lock; multiple independent triggers, not just one.
7. **Per-entry reveal re-auth** — unlocking the vault does not by itself expose every password; revealing a specific entry requires a short-lived re-prompt (configurable grace period), limiting evil-maid blast radius.
8. **Pairing two devices for the first time** — mDNS discovery, PIN-as-PSK Noise handshake, static keys pinned.
9. **Routine sync after both devices edited offline** — vector-clock conflict detection, conflicts archived, manual-merge UI if needed.
10. **Device lost or stolen** — auto-lock + `FLAG_SECURE` + Keystore-gated key + OS-level lock screen form the outer defense layers; no app-side "remote wipe" exists (would require a server — out of zero-cloud scope by design).
11. **Master password change** — MK re-derived with a fresh salt, vault re-encrypted; sync trust is **unaffected** since the Noise identity keypair is independent of MP (§6.1).
12. **Vault file corrupted** (bad sector, failed write, bad USB copy) — recoverable via the Local Versioned Snapshots feature (§7), not solely dependent on the single live file.
13. **Import from another password manager** — plaintext-CSV exposure window explicitly minimized and disclosed (§7).
14. **App update introduces new entry fields** (e.g. future TOTP support) — handled by the payload-level `schema_version` field, migrated forward at decrypt time, independent of the crypto `format_version` in the header (§3).
15. **Uninstall without prior backup** — accepted, unrecoverable, mitigated only by proactive reminders (§7), not a technical safeguard.
16. **Rooted/jailbroken device** — advisory warning, app remains usable (§5.1).
17. **Multiple vaults / profiles** — explicitly **out of scope for v1**. The single-encrypted-file architecture doesn't preclude it (multiple files = multiple vaults trivially), but no profile-switching UI is built in v1 — flagged as an open v2 decision.
18. **TOTP/2FA secret storage** — explicitly **out of scope for v1**, flagged as an open v2 decision requiring its own threat-model pass (TOTP seeds are a distinct high-value secret class).

---

## 9. Accepted Residual Risks (explicit, not oversights)

1. **Zero-recovery** — no backdoor exists anywhere in the design; a forgotten MP means permanent, total data loss. This is the deliberate trade-off underlying the entire zero-knowledge model.
2. **Managed-runtime zeroization is best-effort even with native secure memory FFI** — application-layer wiping cannot reach the hardware-enforced guarantee of a dedicated HSM.
3. **X11 has no input-isolation model** — hotkey/clipboard mitigations on X11 remain partial only; Wayland is the recommended path, X11 the explicitly-flagged fallback.
4. **Accessibility-tree exclusion for secret fields** trades off against legitimate screen-reader accessibility — documented, not solved, both directions disclosed to the user.
5. **Root/jailbreak weakens OS-level guarantees** — advisory-only by design choice (usability for power users over hard blocking).
6. **Post-quantum posture:** the Noise handshake uses X25519 (elliptic-curve Diffie-Hellman), which is *not* post-quantum-secure — a "harvest-now-decrypt-later" attacker recording LAN sync traffic today could theoretically decrypt it with a future cryptographically-relevant quantum computer. Judged **low priority** for this threat model (requires both LAN presence today *and* a quantum computer years later, against a local password manager's sync traffic specifically). AES-256 and Argon2id are unaffected by Shor's algorithm and retain ~128-bit security against Grover's algorithm — no action taken in v1, flagged for future review only if the threat landscape changes materially.
7. **Field-level concurrent-edit merge (CRDT)** is out of v1 scope — only coarse whole-vault conflict resolution is implemented.
8. **EM/power side-channel analysis, OS kernel 0-days, nation-state hardware implants** — out of scope, unactionable at the application layer.

---

## 10. Decisions Log

| Question | Decision | Rationale |
|---|---|---|
| Emergency Recovery Kit? | **Rejected.** Zero-recovery confirmed. | Any recovery mechanism is a new attack surface; contradicts the zero-knowledge guarantee. |
| Argon2id parameters? | **Adaptive calibration + hard floor**, not a fixed constant. | Maximizes cost on capable hardware while guaranteeing a security floor on weak devices. |
| PAKE choice for pairing? | **Noise Protocol Framework** (PSK pattern), not SPAKE2. | Mutual auth + forward secrecy + identity hiding in one audited, widely-deployed (WireGuard-class) framework. |
| Roadmap priority: local OS hardening vs. P2P sync first? | **Local security-critical tasks first.** | Unlocked-device local attack surface is a higher-probability, always-present risk than a LAN attacker requiring active network presence. |
| Header integrity? | **Header as AAD**, app-enforced parameter floor independent of header contents. | Closes the downgrade-attack class entirely. |
| Metadata (file-size) leak? | **Size-bucket padding** added. | Reduces entry-count inference from ciphertext length alone. |
| Sync identity lifecycle? | **Independent long-term Noise keypair**, decoupled from MP. | MP changes never break sync trust; separates concerns cleanly. |
| Conflict resolution basis? | **Vector clock**, not wall-clock timestamp. | Removes clock-skew/rollback attack vector. |
| Corruption resilience? | **New: Local Versioned Snapshots** added to scope. | Single-file-no-cloud architecture needed a corruption safety net. |
| Multi-vault/profiles, TOTP/2FA? | **Deferred to v2.** | Each needs its own dedicated design/threat-model pass; not core to v1 goal. |

---

## 11. Final Roadmap — Vertical Slices (execution order)

### Phase A — Crypto Core (foundation, blocks everything)
**Task: Crypto Core — Key Derivation & Vault Encryption**
- Type: AFK. Deep-module interface: `lockVault(json, MP) -> blob`, `unlockVault(blob, MP) -> json`.
- AC: header fields separated (magic/version/algo-ids/KDF-params/salt/nonce) · header passed as AAD, tamper -> tag mismatch · app-enforced KDF floor regardless of header content · MK never used directly as cipher key (HKDF split) · nonce uniqueness verified over 10k calls · payload padded to size-bucket · GCM failure is fail-closed, no partial plaintext · all secrets as native-backed buffers with verified zero-wipe.
- Blocked by: none.

### Phase B — Memory & Process Hardening
**Task: Native Secure Memory (libsodium FFI)** — secrets never in managed Dart heap; memory-dump test in debug build shows no residual plaintext post-lock. Blocked by: Phase A.
**Task: Linux Process Hardening** — `PR_SET_DUMPABLE=0`, `mlockall()`; ptrace-attach test blocked; `VmLck` verified via `/proc/<pid>/status`. Blocked by: Phase B (secure memory).

### Phase C — Lock Screen & Reveal UX
**Task: Lock Screen + Auto-lock Policy** — rate-limited MP entry (exponential backoff), multi-trigger auto-lock (idle + OS lifecycle events, not just one). Blocked by: Phase B.
**Task: Per-Entry Reveal Re-Auth** — configurable grace period, always required fresh after lock/reopen. Blocked by: Lock Screen.

### Phase D — Android Integration (security-critical, ahead of sync)
**Task: Android Biometric Keystore Integration** — `invalidatedByBiometricEnrollment=true` (mandatory), StrongBox where available, test: new-fingerprint-enrollment invalidates key. Blocked by: Phase A.
**Task: Android Autofill Service (Origin-Verified)** — Digital Asset Links check before returning credentials, `FLAG_SECURE` on all secret-bearing screens. Blocked by: Biometric Keystore task.
**Task: Clipboard Manager (Sensitive-Marked)** — `EXTRA_IS_SENSITIVE` on Android 13+, 30s auto-wipe verified by test. Blocked by: Phase A.

### Phase E — Linux Integration
**Task: Linux Global Hotkey + Tray** — Wayland-first, X11 fallback with explicit first-run limitation warning. Blocked by: Lock Screen.

### Phase F — Backup, Snapshots, Import/Export
**Task: Backup / Export with MP Strength Gate** — warn-not-block on weak MP before export. Blocked by: Phase A.
**Task: Local Versioned Snapshots** (new) — last-N rotation of successful save states in app-private storage. Blocked by: Phase A.
**Task: Third-Party CSV Import** — no persisted plaintext copy beyond OS temp, post-import secure-delete prompt, explicit exposure-window warning. Blocked by: Phase A.

### Phase G — P2P Sync
**Task: P2P Pairing Protocol (Noise, PSK pattern)** — PIN-as-PSK handshake, rate-limited pairing window, static-key pinning post-pairing. Test: passive and active MITM both fail without PIN. Blocked by: Phase A.
**Task: Sync Message Replay Protection** — monotonic per-session counter, non-increasing messages dropped. Blocked by: Pairing task.
**Task: Conflict Resolution via Monotonic Versioning** — vector clock replaces wall-clock; clock-skew simulation test does not allow old data to overwrite new. Blocked by: Pairing task.

### Phase H — Polish & Open v2 Items (explicitly deferred, not scheduled)
- Multi-vault/profile switching UI.
- TOTP/2FA secret storage (needs its own threat-model pass).
- Field-level CRDT merge for true concurrent-edit resolution.
- Optional min-app-version enforcement in header to resist app-downgrade attacks.

---

## 12. Second-Factor Authentication — Analysis & Design

### 12.1 Requested options vs. zero-cloud compatibility

| Requested option | Verdict | Why |
|---|---|---|
| **SMS confirmation** | **Rejected.** | Requires a telecom backend to send the code — there is no server in this architecture to trigger it, and even if there were, SMS is a well-documented weak factor: SIM-swap attacks let a remote attacker redirect codes without touching the device. Structurally incompatible with zero-cloud and weaker than the MP alone in a targeted-attack scenario. |
| **"Through Google"** — if this means **Sign-In-With-Google / OAuth** | **Rejected.** | Ties vault-unlock availability and security to a third-party account and Google's servers — the opposite of the app's core promise ("your vault works even if every server on earth is down"). |
| **"Through Google"** — if this means the **Google Authenticator app** | **Compatible, and recommended as one option.** | Despite the name, Google Authenticator is a generic **RFC 6238 TOTP** client — it computes codes locally from a shared secret and the device clock, no network call, no Google account involved. Any standard TOTP app (Google Authenticator, Aegis, FreeOTP, Authy in offline mode) works identically here. |
| **OTP / "temporary numbers"** | **This is TOTP** — the correct primitive for this architecture. | Purely local: `code = HMAC-SHA1(secret, current_time_step)`, truncated to 6 digits. Verifying it needs nothing but the shared secret and a clock — exactly what a zero-cloud app can do. |

**Conclusion:** the only requested mechanism that actually fits a zero-cloud architecture is **TOTP**. SMS and OAuth are dropped, not because they're hard to implement, but because they reintroduce the exact server dependency this whole project exists to avoid.

### 12.2 Critical design principle: binding, not gating

A naive implementation checks the TOTP code as a UI-level `if (code != expected) refuse` gate *after* the vault is already decrypted, or before decryption is even attempted. **This is bypassable** by anyone who can run a patched build of the app, attach a debugger, or call the decrypt function directly — the check is just a conditional in code, not a cryptographic requirement.

**Mandatory design rule:** the second factor must be an **input to key derivation**, not a separate check:

```
MK = HKDF( Argon2id(MP, salt)  ||  SecondFactorMaterial )
```

Without the correct second-factor material, the derived key is simply wrong and `unlockVault` fails on the GCM tag — there is no code path that skips this, because it isn't a check, it's math.

### 12.3 Chosen mechanism: TOTP bound into key derivation

- Standard **RFC 6238 TOTP**, HMAC-SHA1 (kept for interoperability with the existing ecosystem of authenticator apps, all of which assume SHA1 — using SHA256/512 would break QR-code portability to third-party apps for no real security gain at this key length).
- 160-bit CSPRNG-generated seed at 2FA setup, encoded as Base32 for QR display.
- Because a raw TOTP value changes every 30 seconds, it cannot be fed into KDF as a single unlock-time input **and** allow the vault to be re-opened at an arbitrary later moment — instead, the TOTP seed itself (static, never leaves the device) is the HKDF input, and the *live 6-digit code* is used only as the user-facing proof that the person entering it currently possesses that seed (i.e., possesses the phone/authenticator). Concretely: the app locally holds the seed only inside secure memory (§4) after the user has proven live possession via a correct code at unlock time; the seed material is then combined into HKDF as in §12.2. This keeps the "something you have, right now" property while still allowing deterministic key derivation.
- This directly strengthens **attacker profile #1** (stolen vault file only, no device): without the device-held seed, offline brute-force of MP alone is no longer sufficient — the attacker also needs whatever is holding the seed material.

### 12.4 Companion-device push approval (built on the existing Noise pairing — recommended primary UX)

The P2P sync infrastructure (§6) already gives two paired devices a mutually-authenticated, forward-secure channel. Reusing it for 2FA avoids asking the user to type a 6-digit code every unlock:

- Unlocking the **desktop** app (which has no biometric hardware) sends an authenticated request over the existing Noise session to the paired **phone**.
- The phone shows an approval prompt with explicit context: requesting device name, approximate timestamp, and — critically — a **number-matching challenge** (the desktop displays a 2-digit number the user must select on the phone among 3 decoys), not a single blind "Approve" button.
- Approval is itself signed with the phone's TOTP seed material (§12.3) transmitted only over the already-authenticated channel — so this is a UX convenience layer over the same cryptographic primitive, not a separate weaker mechanism.
- **This never becomes a hard dependency for unlocking:** if the paired device is unreachable (off, out of range, not yet paired), the manual TOTP code (§12.5) always works. Sync availability must never gate the core "app works 100% offline" invariant (§6.4).

### 12.5 Fallback: manual TOTP code entry

Always available, no connectivity required — the user reads the 6-digit code off any authenticator app (this app itself, or a third-party one if the seed was exported/shared at setup) and types it in. This is the baseline mechanism; push approval (§12.4) is strictly additive.

### 12.6 MFA-fatigue / push-bombing defense

An attacker who has the MP (phished, shoulder-surfed, or brute-forced from a leak elsewhere) but not the second factor can repeatedly trigger unlock attempts, hoping the user reflexively approves a push notification out of habit ("push bombing" — a well-documented real-world breach pattern). Mitigations, all mandatory together (any single one alone is known to be insufficient in the industry):
- Number-matching (§12.4), not a single-tap approve button.
- Rate limiting: no more than N push requests per cooldown window; excess requests silently dropped rather than re-prompting.
- Explicit context shown on every prompt (requesting device identity, not just "Approve login?").

### 12.7 Backup codes — recovery path that doesn't reopen the zero-recovery hole

If 2FA is bound into key derivation (§12.2), losing the second-factor device (phone destroyed, seed lost) with a *correctly remembered MP* must not become an unrecoverable state — that would silently convert "zero recovery only for a forgotten MP" (accepted, §9.1) into "zero recovery for a lost phone too," a real usability regression the user has not asked for and should not get by accident.

- At 2FA setup, generate **10 single-use backup codes**, shown once, user is prompted to save them outside the app (paper, separate secure location — the app cannot store its own escape hatch inside the very vault it protects, that would be circular).
- The app stores only **Argon2id-hashed** versions of these codes in a small local file *separate from the vault* (doesn't require the vault to already be unlockable to check a code — otherwise the recovery path can't function).
- Using a valid backup code **disables the KDF-bound 2FA requirement** for that vault (falls back to MP-only unlock, same as before 2FA was enabled) and immediately prompts the user to set up 2FA again with a fresh seed. The used code is invalidated; if all 10 are consumed the app forces regeneration.

### 12.8 TOTP as a stored credential (app generates codes for the user's *other* accounts)

This is the "authenticator app" feature, distinct from §12.3–12.7 (which protect access to *this app*). Previously deferred to v2 as an unscoped placeholder — now specified:

- Import via QR scan (`otpauth://` URI, camera permission, Android) or manual Base32 entry.
- Stored inside the same encrypted vault entry as the corresponding password (convenience), **with an explicit, undismissable warning at setup**: co-locating a password and its own 2FA seed in one vault means a single vault compromise defeats both factors for that account simultaneously — the security industry's standard caution against "putting all your 2FA in your password manager" applies directly. Offer a per-entry toggle to keep the TOTP seed **out** of this vault (i.e., deliberately keep using a separate authenticator app for that specific account) for users who want genuine channel separation.
- Codes displayed with the standard 30s countdown ring; copy-to-clipboard uses the same sensitive-flag + 30s-wipe path as passwords (§5).

### 12.9 Clock-skew tolerance

TOTP validity depends on the device clock being roughly accurate. An offline-first app cannot assume network time sync (airplane mode, no SIM, no NTP). Design: accept codes within a **±1 time-step window** (i.e., the previous, current, and next 30s window), and surface a non-blocking warning if the system clock appears to have drifted significantly since the last successful validation, prompting the user to check their clock settings.

### 12.10 New attacker profile: patched/modified binary attempting to bypass the 2FA check

| Attacker | Capability | Defense | Residual Risk |
|---|---|---|---|
| Modified/patched app build | Runs a version of the app with the 2FA gate code path removed | Not solvable by the check itself — solved structurally by §12.2 (KDF-binding: there's no gate to remove, wrong seed material simply produces a wrong key). Additionally, a runtime integrity check (e.g. Android Play Integrity API class) can warn the user if the running build doesn't match the expected signature. | Determined attacker with full reverse-engineering capability and the vault file could still attempt brute-force against a version with the KDF-binding stripped and rebuilt from source (if open-source) — but this requires source-level compromise, not a runtime bypass, and doesn't help against a stolen-file-only attacker who lacks the second-factor material regardless of which binary they run. |

### 12.11 Roadmap — Phase I (2FA, optional but recommended before general release)

**Task: TOTP Vault-Unlock 2FA (KDF-bound)**
- Type: AFK. Objective: implement §12.2–12.3 — TOTP seed generation, HKDF binding, unlock flow requiring a live code.
- AC: vault opened with correct MP but wrong/absent TOTP code fails at the GCM-tag stage, not at a separate `if` check (verified by code-review + a test that directly calls the low-level decrypt function bypassing UI, confirming it still fails) · seed lives only in native secure memory (§4) · setup QR display protected by `FLAG_SECURE`.
- Blocked by: Phase A (Crypto Core).

**Task: Backup Codes**
- Type: HITL (needs UX review for the "save these now" flow). Objective: §12.7.
- AC: 10 single-use codes generated, shown exactly once · stored only as Argon2id hashes in a file separate from the vault · successful use disables 2FA and forces re-setup · exhausting all 10 forces regeneration before 2FA can be re-armed.
- Blocked by: TOTP Vault-Unlock 2FA.

**Task: Companion-Device Push Approval**
- Type: AFK. Objective: §12.4, reusing the Phase G Noise session.
- AC: number-matching challenge required (no single-tap approve) · request context (device name, timestamp) shown on the approving device · rate-limited per cooldown window · unavailable-peer case falls back cleanly to manual TOTP entry with no error implying sync is required.
- Blocked by: TOTP Vault-Unlock 2FA, Phase G (P2P Pairing).

**Task: Stored TOTP for Third-Party Accounts**
- Type: HITL. Objective: §12.8.
- AC: `otpauth://` QR import + manual Base32 entry both supported · co-location warning shown and requires explicit acknowledgment on first use · per-entry "keep 2FA seed out of this vault" opt-out available.
- Blocked by: Phase A.

**Task: Runtime Integrity Check (Android)**
- Type: AFK. Objective: §12.10 — detect and warn on a build that doesn't match the expected signature.
- AC: modified-signature test build triggers a visible warning; does not silently proceed as if unmodified.
- Blocked by: none (independent hardening task).

### 12.12 Decisions Log — additions

| Question | Decision | Rationale |
|---|---|---|
| SMS as a second factor? | **Rejected.** | Requires a telecom/server dependency this architecture doesn't have; SIM-swap risk makes it weaker than MP alone against a targeted attacker. |
| OAuth / "Sign in with Google"? | **Rejected.** | Ties local vault security/availability to a third-party account and server — contradicts zero-cloud by definition. |
| TOTP-compatible apps (incl. Google Authenticator)? | **Accepted as a supported client.** | Purely local RFC 6238 computation despite the name; no server dependency. |
| Should the 2FA check be a UI gate or KDF-bound? | **KDF-bound, mandatory.** | A UI gate is bypassable by a patched build; a wrong-key failure is not. |
| Primary 2FA UX? | **Companion-device push approval with number-matching**, manual TOTP as always-available fallback. | Avoids typing a code on every unlock while resisting MFA-fatigue/push-bombing; never makes offline unlock depend on connectivity. |
| Lost-second-factor recovery? | **One-time backup codes**, hashed, stored outside the vault. | Prevents 2FA from silently expanding the zero-recovery surface beyond "forgotten MP" (§9.1), which was never the intent. |
| Store other accounts' TOTP seeds in the same vault as their passwords? | **Optional, opt-out per entry, with a mandatory warning.** | Preserves user choice on the well-known "don't put all your 2FA in one basket" trade-off rather than deciding it silently either way. |

---

## 13. Additional Critical Items (this pass)

- **Linux has no hardware-backed secret storage equivalent to Android's Keystore mentioned anywhere in this plan so far.** Add: on Linux desktops with a **TPM 2.0** present, seal the device-bound second-factor material (§12.3) to the TPM (analogous role to Android StrongBox); on machines without a TPM, fall back to the OS secret store (`libsecret`/GNOME Keyring or KDE Wallet) rather than an app-private file, so at minimum OS-level access control applies. This closes an asymmetry where Android got hardware-backed protection and Linux got none.
- **App-downgrade attack, extended.** §9 already flagged app-store version enforcement as a v2 idea for the crypto envelope; with 2FA now KDF-bound, explicitly note that a **downgraded or patched build cannot simply skip 2FA** either (§12.2/§12.10), closing what would otherwise have been a fresh bypass path introduced by adding 2FA in the first place.
- **2FA interaction with Master Password change (§8.11).** Changing MP re-derives MK with a new salt; the TOTP seed itself is untouched and does not need to be re-provisioned unless the user explicitly resets 2FA — call this out explicitly so the MP-change flow doesn't get quietly re-specified as "reset everything" by whoever implements it.
- **2FA interaction with Local Versioned Snapshots (§7).** Snapshots must remain decryptable under the *current* second-factor material, not whatever was active at snapshot time — if 2FA is reset (fresh seed) after a snapshot was taken, older snapshots become unopenable with the new seed. Document as accepted behavior (same category as an MP change invalidating old exports encrypted under the old key) rather than a bug to "fix" — attempting to keep old snapshots readable across a 2FA reset would mean keeping old key material around, which is itself a security regression.
- **Setup-time-only exposure window.** The TOTP seed and the 10 backup codes are only ever displayed once, in full, at setup — this is a natural high-value shoulder-surfing / screen-recording moment. Reuse the same `FLAG_SECURE` protection already mandated for other secret-bearing screens (§5.1), explicitly extended to cover this specific screen, since it's easy to overlook a one-time setup screen when auditing "all screens showing secrets."

---

## 14. Risk-Tiered Access Control (per-entry sensitivity)

Not every entry deserves the same friction. A streaming-service password and a primary bank login are not the same risk class, and treating them identically either annoys the user into disabling security features altogether, or under-protects the entry that actually matters. Formalized as three tiers, assignable per entry:

| Tier | Example | Reveal re-auth | Autofill behavior | Push-approval (§12.4) | Quick-copy / lock-screen widget |
|---|---|---|---|---|---|
| **Standard** | streaming service, forum account, low-value newsletter login | Standard grace period (§8.7 default) | Automatic, no extra prompt | Single-approver, standard number-matching | Allowed |
| **Sensitive** | primary email, work accounts, e-commerce with saved payment | Short grace period, re-prompt more often | Requires one-tap confirm before fill | Single-approver, number-matching | Allowed, but excluded from any lock-screen "recent" quick-list |
| **Critical** | banking, primary crypto exchange, domain registrar, primary email recovery address | Fresh re-auth every time, no grace period | Manual reveal only, never silent autofill | **M-of-N approval** if more than one device is paired (see §15.3) — a single paired device cannot silently approve access to a Critical entry alone | Never exposed via any quick-access surface |

- **Default tier heuristics:** the app suggests Sensitive/Critical for domains that pattern-match known banking/financial/crypto-exchange/registrar categories at entry-creation time, always user-overridable — this is a starting suggestion, not an enforced classification.
- **Tier-downgrade cooldown:** lowering an entry's tier (e.g. Critical -> Standard) takes effect only after a short mandatory delay (e.g. a few minutes), with a notification surfaced on any other paired device. This mirrors the industry pattern of delaying security-relevant account changes so an attacker who gained brief unauthorized access can't immediately strip protections and walk away clean (see §15.9 for the direct analogue). Raising a tier (Standard -> Critical) takes effect immediately — tightening security is never delayed, only loosening it is.

---

## 15. Ideas Adapted From Crypto Wallet Security

Crypto wallets protect a bearer-asset with no recovery path and no institution to call if something goes wrong — structurally the closest existing consumer product to this vault's own zero-cloud, zero-recovery model. Several of their solved problems map directly.

### 15.1 Clear-signing / transaction simulation -> Autofill preview
Modern wallets no longer let a user blindly approve a raw transaction hash; they simulate the transaction and show a human-readable preview of its actual effect before signing, specifically to defeat "blind signing" drainer attacks. Direct analogue here: before autofilling into a page, show a one-line preview — *"Filling saved login for **paypal.com** into **paypal.com**"* — and make any mismatch between the saved entry's domain and the page's actual domain a **hard stop requiring explicit confirmation**, not a silent fill. This is the autofill origin-check already specified in §5.1, now explicitly framed as the same defense class as wallet transaction simulation.

### 15.2 Address-poisoning detection -> Look-alike domain detection
Wallets now flag recipient addresses that closely resemble a previously-used one but differ subtly, a scam pattern called address poisoning. The direct password-manager analogue is typosquatting: warn before autofilling into a domain that closely resembles (edit-distance, homoglyph, or subdomain-trick match) a domain already saved under a *different* entry — e.g. `paypa1.com` or `paypal.com.secure-login.net` against a saved `paypal.com` entry. This closes a real phishing-autofill gap that plain origin-verification (§5.1) alone doesn't catch, since a typosquat domain can still legitimately "own" itself for Digital Asset Links purposes — origin-verification proves the app-domain pairing is real, not that the domain is the *right* one.

### 15.3 MPC-style key sharding -> Optional multi-device key split (advanced, v2)
Some wallets now split a private key into shards distributed across multiple devices, so no single device ever holds the complete key and high-value actions require several devices' cooperation. Default design here (§2) keeps a single device able to derive the full vault key from MP + local second factor, for simplicity — but as an **opt-in advanced mode**, offer splitting the Encryption Key itself (not MP) across N paired devices via a threshold scheme, such that unlocking on any *new* device, or approving a Critical-tier reveal (§14), requires M-of-N devices to cooperate. This is strictly additive complexity for users who explicitly want it (e.g. shared family vault, or a user who owns 3+ devices and wants no single one to be a total point of compromise) — not a default, and not required for the core v1 threat model.

### 15.4 Shamir Secret Sharing (SLIP-39) -> Optional self-custodied recovery kit
Trezor's Shamir backup standard splits a wallet's backup secret into multiple shares with a configurable threshold (e.g. 3-of-5), so no single share — lost, stolen, or destroyed — compromises or blocks recovery, and no single point of failure exists. This directly resolves the tension flagged in §12.7: **§10's "Recovery Kit -> Rejected" decision is refined, not reversed.** By default, there is still no recovery mechanism (zero-knowledge preserved, nothing to attack or subpoena). But as an **explicit, off-by-default, self-custodied opt-in**, offer: split a recovery artifact (capable of reconstructing MK) into N Shamir shares, threshold K-of-N, entirely generated and reconstructed locally with no server involvement at any point — the vendor never sees a share, sees whether the feature is enabled, or can assist in reconstruction. This gives risk-tolerant users a way to avoid "one forgotten password = total loss" without reintroducing a backdoor, because reconstruction requires the user's *own* K shares, not anything the app or its developer holds.

### 15.5 Hidden wallet via passphrase -> Decoy vault (coercion mitigation)
A passphrase-protected wallet can derive an entirely different, plausible wallet from an alternate passphrase — giving the owner a real answer to give under duress without exposing the actual holdings, since the passphrase-derived secret is a separate, independently-encrypted value from the base secret. Direct analogue: support an **alternate Master Password that unlocks a separate, deliberately unremarkable decoy vault** (a handful of low-stakes entries, populated by the user in advance) instead of the real one. This is the first concrete mitigation for **attacker profile #7 (coerced/forced unlock)** in this plan, previously flagged as unsolvable at the app layer (§1) — it doesn't prevent coercion, but it gives the user something plausible to hand over. Opt-in, off by default (the feature's mere *existence* being widely known somewhat weakens its deniability value in the abstract, a known limitation of this technique in the wallet world too — documented, not solved).

### 15.6 Hardware secure-element certification tiers -> honest framing of Android/Linux hardware backing
Dedicated hardware wallets increasingly ship secure elements certified to Common Criteria EAL6+ or even EAL7, tested against physical extraction and fault-injection attacks. Android Keystore/StrongBox and a Linux TPM 2.0 (§13) are meaningfully better than software-only key storage, but as general-purpose device components they are not certified to, and don't claim, the same assurance level as a dedicated single-purpose hardware wallet chip. This is an **honest, documented limitation**, not a gap to "fix" — a phone or laptop is fundamentally a larger, more general attack surface than a purpose-built offline signing device, and this plan should never imply equivalence.

### 15.7 Burner-identity pattern -> reinforces the Risk-Tiered model
Wallets recommend isolating exposure to new/unverified counterparties in a separate "burner" wallet, keeping main holdings untouched by that specific risk. This is conceptually the same reasoning behind the **Standard** tier in §14 — low-value, low-consequence entries deliberately carry less protection *and* less friction, keeping the friction budget concentrated on what actually matters, rather than applying uniform maximum friction everywhere (which historically causes users to disable security features entirely).

### 15.8 "Revoke unused approvals" -> Paired-device review & revocation
Wallet security guidance consistently recommends periodically reviewing and revoking stale token/contract approvals that are no longer needed, since each live approval is a standing risk. Direct analogue: a **Paired Devices** settings screen listing every device with a pinned Noise static key (§6.1), each with a last-synced timestamp, and a one-tap revoke. A device that hasn't synced in, say, 6+ months (lost, replaced, factory-reset without unpairing) is a stale trust relationship worth surfacing proactively, not something the user has to remember to clean up unprompted.

### 15.9 "Test small amount before large transfer" -> Preview-before-commit for bulk operations
Wallet guidance recommends sending a small test transaction before moving a large amount, to verify the path is correct before committing irreversibly. Direct analogue for two irreversible-feeling bulk operations already in this plan: **(a)** accepting a remote vault during sync conflict resolution (§6.3) and **(b)** completing a third-party CSV import (§7) should both show a **diff/preview** — "12 entries will be added, 3 will be overwritten, 1 will be archived to conflicts/" — before the user commits, rather than the operation completing silently and only being inspectable after the fact.

### 15.10 Post-quantum migration starting in hardware wallets -> revisit trigger for §9.6
At least one major hardware wallet vendor shipped a post-quantum cryptographic architecture in late 2025, ahead of most consumer software. §9.6 currently treats the non-post-quantum Noise handshake as an accepted low-priority residual risk — that judgment should not be treated as permanent. **Action:** add a standing note to revisit §9.6 if/when post-quantum key-exchange primitives (e.g. a Noise pattern using a PQ KEM) reach the same maturity/audit level as the classical primitives currently specified, rather than waiting for an incident to force the reconsideration.

---

## 16. Roadmap — Phase J (wallet-inspired hardening)

**Task: Risk-Tiered Access Control (Standard/Sensitive/Critical)**
- Type: HITL (needs UX design for tier assignment and cues). Objective: §14.
- AC: three tiers implemented with the reveal/autofill/quick-copy policy differences specified · tier-downgrade enforces the notification+cooldown, tier-upgrade is immediate · default heuristics are suggestions only, never silently override a user's explicit choice.
- Blocked by: Lock Screen (Phase C), Companion-Device Push Approval (Phase I) for the Critical-tier M-of-N path.

**Task: Look-alike Domain Detection**
- Type: AFK. Objective: §15.2.
- AC: autofill into a domain within a configurable edit-distance/homoglyph threshold of a *different* saved entry's domain triggers a hard-stop warning, not a silent fill · exact-match domains are unaffected (no added friction for the common case).
- Blocked by: Android Autofill Service (Phase D).

**Task: Autofill Preview**
- Type: HITL. Objective: §15.1 — one-line "filling X into Y" confirmation surfaced before any autofill completes for Sensitive/Critical-tier entries.
- Blocked by: Risk-Tiered Access Control, Android Autofill Service.

**Task: Preview-Before-Commit (Sync & Import)**
- Type: HITL. Objective: §15.9 — diff view before accepting a remote vault or completing a CSV import.
- Blocked by: Conflict Resolution (Phase G), Third-Party CSV Import (Phase F).

**Task: Paired-Device Review & Revocation**
- Type: HITL. Objective: §15.8 — settings screen listing paired devices, last-sync timestamp, one-tap revoke, stale-device surfacing.
- Blocked by: P2P Pairing Protocol (Phase G).

**Task: Decoy Vault (opt-in)**
- Type: HITL, off by default. Objective: §15.5 — alternate MP derives a separate, independently-encrypted decoy vault.
- AC: decoy vault is cryptographically indistinguishable from a real vault at the file-format level (same header structure, same envelope) · feature is opt-in and clearly explains its own limitations (§15.5) at setup, not marketed as a guarantee.
- Blocked by: Phase A.

**Task: Shamir-Based Optional Recovery Kit (opt-in)**
- Type: HITL, off by default. Objective: §15.4 — local SLIP-39-class K-of-N share generation/reconstruction for MK, zero server involvement.
- AC: reconstruction works entirely offline from K shares with no network call at any point · default remains zero-recovery unless the user explicitly enables and completes this setup.
- Blocked by: Phase A.

**Task: Optional Multi-Device Key Split (MPC-style, advanced)**
- Type: HITL, off by default, lowest priority in this phase. Objective: §15.3.
- Blocked by: Phase A, P2P Pairing Protocol.

---

## 17. Decisions Log — refinement

| Question | Original decision | Refined decision |
|---|---|---|
| Recovery Kit | Rejected outright | **Rejected as a default.** Available as an explicit, off-by-default, self-custodied Shamir-split opt-in (§15.4) that preserves zero-knowledge (vendor sees nothing, holds nothing). |
| Coerced-unlock attacker (#7) | Flagged unsolvable at app layer | **Partially mitigated, opt-in.** Decoy vault (§15.5) gives the user a plausible alternative to hand over; coercion of the *real* MP itself remains unsolvable, as before. |

---

## 18. 2026 Threat Landscape & Breach-Awareness Design

Direct answer to the core question first: **can a leak on a website's own server be stopped from exposing your password?** Not retroactively — how a third-party site stores its side of the credential is entirely outside this app's control. But there is a structural fix the industry has converged on (§18.2), and there is a way to find out it happened without ever exposing anything further (§18.3). Both are addressed below, grounded in current data rather than assumption.

### 18.1 The infostealer reality — this plan's architecture already defeats the #1 current vector, with one gap

Credential theft in 2025–2026 is dominated by **infostealer malware** (RedLine, Lumma, Vidar, StealC, AMOS and others), not classic server-side breaches — industry trackers report roughly 1.8 billion credentials stolen via infostealers in 2025 alone, with password managers explicitly called out by security vendors as high-value targets ("gaining access to a password manager is like hitting the jackpot" — Ping Identity). The single most-cited root cause is browsers storing passwords in **predictable, unencrypted-at-rest locations** — which is precisely why security researchers now recommend moving away from browser-built-in password storage toward a dedicated encrypted vault. This plan's core design (§2–§4: everything at rest is AES-256-GCM-encrypted behind an Argon2id-derived key, nothing sits in a predictable plaintext location) **already structurally defeats the dominant 2026 attack pattern** — an infostealer that grabs this app's vault file gets an encrypted blob it cannot use without the MP.

The gap infostealers exploit that encryption-at-rest doesn't cover: **keylogging and form-grabbing while the app is being used.** Modern infostealers routinely include keylogging and browser form-grabbing modules. If the Master Password is typed on an infected device, no amount of vault encryption protects that specific keystroke sequence. This reinforces two decisions already in this plan and adds one new consideration:
- **Reinforces (not new):** biometric/Keystore-gated unlock (§5.1) that minimizes how often the MP is actually typed is a *keylogger-mitigation*, not just a convenience feature — worth stating explicitly, since it changes how "optional" that feature should be considered.
- **New:** consider supporting a **hardware security key (FIDO2, e.g. YubiKey-class)** as an alternative unlock factor for advanced users, since a physical key's cryptographic operation cannot be keylogged — it never involves typing a secret at all. This is the same reasoning the industry now applies to phishing-resistant authentication generally (§18.2).
- **Explicitly rejected as a mitigation:** an on-screen/virtual keyboard for MP entry. This is a common but weak folk-remedy — modern infostealers with screen-scraping or clipboard-hooking capability defeat it just as easily, and it would give a false sense of protection. Not implementing it, and documenting why, is itself the correct decision here.

### 18.2 Passkeys (FIDO2/WebAuthn) — the actual structural answer to "server leak exposes my password"

This is the direct answer to the original question. **A passkey means the site's server only ever stores a public key.** There is nothing secret on the server side to leak — a full server breach yields nothing an attacker can use to authenticate as the user, because the private key never left the user's device (or this app's vault) in the first place. This is now mainstream, not experimental: FIDO Alliance reports **over 5 billion active passkeys worldwide in 2026**, and standards bodies (NIST SP 800-63B, CISA) classify correctly-implemented hardware-bound FIDO2/WebAuthn as the only tier of authentication classified as genuinely phishing-resistant — notably, this is a stronger property than even TOTP, which real-time adversary-in-the-middle (AiTM) phishing proxies can intercept and replay before the code expires; a passkey's origin-binding makes that class of attack structurally impossible, not just harder.

**Design decision:** this app should aim to become a **WebAuthn platform credential provider** (the same role 1Password and Bitwarden already play), storing passkey private keys inside the same encrypted vault, protected by the same KDF/AEAD machinery already specified (§2), and — critically, as this project's actual differentiator — **synced between the user's own devices over the existing local P2P Noise channel (§6), not through a vendor's cloud.** Apple's iCloud Keychain and Google Password Manager both sync passkeys through their own cloud infrastructure; a password manager whose entire premise is zero-cloud offering genuinely local passkey sync is a real, currently-unfilled niche, not a copy of an existing feature.

This is flagged as a **major, dedicated v2 initiative**, not squeezed into v1: implementing a platform authenticator correctly (Android Credential Manager API integration, a Linux-side FIDO2 authenticator implementation, relying-party origin verification, resident-key storage format, attestation handling) is security-critical enough to need its own threat-model pass, the same way P2P sync got one in §6 before being scoped into the roadmap.

### 18.3 Breach monitoring — local, privacy-preserving, opt-in

The requested "warn me if I've been breached" feature has a well-established, privacy-preserving pattern already used by the exact category of product this plan is building: Have I Been Pwned's **Pwned Passwords** service (the same backend 1Password Watchtower, Bitwarden's reports, and Firefox Monitor already use) checks a password against ~850 million breach-exposed passwords using **k-anonymity**: the password is hashed locally (SHA-1), only the **first 5 characters** of the hash are sent to the API, the service returns every hash sharing that prefix (hundreds of candidates), and the actual match happens locally — the real password, and even its full hash, never leaves the device.

Two implementation modes, **both strictly opt-in and off by default**, since this is the one deliberate, clearly-bounded exception to the zero-cloud default in the entire architecture:
- **Online k-anonymity mode:** a single small HTTPS request per checked password (hash-prefix only), freshest data, matches the industry-standard pattern exactly.
- **Offline corpus mode:** the full Pwned Passwords dataset is explicitly downloadable for local, fully offline querying with zero network calls after the initial download — the maximally zero-cloud-consistent option, trading freshness and local disk space for never touching a network at check time. Offered as the preferred default *within* the opt-in, for users who want breach-awareness without any recurring network dependency.

**Scope for v1:** password-reuse checking only (the Pwned Passwords corpus), not account/email-level breach notification (the broader "has my account appeared in a breach" service is a much larger, continuously-updated dataset that isn't realistically offline-mirrorable and would reintroduce a real, ongoing cloud dependency) — flagged as a separate, larger v2/future consideration if pursued at all, evaluated on its own for how much it compromises the zero-cloud principle relative to the value it adds.

### 18.4 Duplicate & weak password detection (fully local, no network involved)

A feature deliberately separated from §18.3 because it needs **no external data at all**: scan the vault's own entries for password reuse across different domains and for weak/short passwords, surfaced in a local **Security Dashboard** — the same category of feature as 1Password Watchtower or Bitwarden's health reports, but implementable with zero network dependency since it only needs the vault's own contents. This directly reduces the blast radius of any future server-side leak the app can't otherwise prevent: if every entry has a unique password, one compromised site can never be used to pivot into another account via credential stuffing.

### 18.5 AI-scaled phishing — the plan's existing defenses, reframed as a first-class property

Security researchers report AI is now being used specifically to **scale phishing distribution** (IBM X-Force), and AiTM phishing kits that steal live session cookies are increasingly common — both defeat MP-only and even TOTP-only protections, since a stolen session cookie grants access without needing either. This doesn't call for new mechanisms so much as it reframes ones already specified as more load-bearing than initially scoped:
- The strict, cryptographically-verified origin check behind autofill (§5.1, §15.1, §15.2) means this app's resistance to phishing doesn't depend on a page *looking* legitimate — an AI-generated pixel-perfect clone of a banking site gets nothing from this app if its origin doesn't match, exactly the same structural property that makes passkeys phishing-resistant (§18.2). Worth stating explicitly in user-facing documentation as a core guarantee, not just an implementation detail.
- The number-matching push-approval design (§12.4, §12.6) was already built to resist automated/repeated-prompt abuse; AI-scaled attack volume is simply a reason that design choice was correct, not a reason to add anything further at this stage.

### 18.6 Roadmap — Phase K

**Task: Local Security Dashboard (duplicate/weak password detection)**
- Type: AFK. Objective: §18.4 — zero network dependency.
- AC: correctly flags reused passwords across entries, flags entries below a configurable strength threshold, updates incrementally as entries change rather than requiring a full manual re-scan.
- Blocked by: Phase A.

**Task: Breach Monitoring (Pwned Passwords, k-anonymity + offline corpus)**
- Type: HITL (consent/UX flow is the critical part). Objective: §18.3.
- AC: default state is **off**; enabling requires explicit, clearly-worded consent naming exactly what leaves the device (a 5-character hash prefix, never the password) · offline-corpus mode available and clearly marked as the zero-network-at-check-time option · a checked password is never logged or cached in a way that would let a later device compromise reconstruct which entries were checked.
- Blocked by: Phase A, Local Security Dashboard.

**Task: Hardware Security Key (FIDO2) as an unlock factor**
- Type: AFK. Objective: §18.1 — a keylogger-immune alternative/additional unlock factor for advanced users.
- Blocked by: Phase A, Lock Screen (Phase C).

**Task: Passkey / WebAuthn Credential Provider (major v2 initiative)**
- Type: HITL, requires its own dedicated threat-model pass before scoping into concrete acceptance criteria — not detailed here for the same reason P2P sync wasn't speced until §6 got a full pass first.
- Objective: §18.2 — platform authenticator role, passkeys stored in-vault, synced via the existing local P2P channel rather than a vendor cloud.
- Blocked by: Phase A, Phase G (P2P sync infrastructure it would reuse).

### 18.7 Decisions Log — additions

| Question | Decision | Rationale |
|---|---|---|
| Can server-side leaks be prevented from exposing a password? | **Not retroactively for password-based auth — this is outside the app's control.** Structural fix is passkeys (§18.2), where the server never holds anything worth leaking. | Honest scoping: the app can't change how a third-party site stores its own data; it can change which authentication primitive gets used going forward. |
| Breach-warning feature? | **Added, opt-in, off by default: Pwned Passwords k-anonymity, online and offline-corpus modes.** | Matches the established, privacy-preserving industry pattern; explicitly bounded exception to zero-cloud, not a silent one. |
| On-screen keyboard as anti-keylogger measure? | **Rejected.** | False sense of protection against modern screen-scraping/clipboard-hooking infostealers; biometric/Keystore-gated unlock (already planned) is the real mitigation for MP-typing frequency. |
| Passkey support? | **Accepted in principle, scoped as a major v2 initiative requiring its own threat-model pass.** | High implementation/security complexity; genuinely differentiated value (local P2P passkey sync vs. vendor-cloud sync) justifies the investment, but not at the expense of rushing it into v1. |

---

## 19. Architectural Revision: Per-Entry Key Hierarchy (supersedes the flat-blob model in §2–3)

**What changes:** §2 specified a single `EncKey` encrypting the entire vault as one AEAD blob. This section replaces that with a hierarchy:

```
MK = Argon2id(MP, salt, params)                    [unchanged from §2]
VRK (Vault Root Key) = HKDF-SHA256(MK)              [renamed from EncKey — now wraps, not encrypts directly]
DEK_i (per-entry Data Encryption Key) = CSPRNG-generated at entry creation, wrapped (AES-256-GCM) under VRK
entry_i ciphertext = AES-256-GCM(entry_i JSON, DEK_i, fresh nonce)
```

The header (§3) is extended, not replaced: it now carries a compact wrapped-DEK table (`entry_id -> AES-256-GCM(DEK_i, VRK)`) alongside the existing KDF/salt/nonce fields, still covered as AAD end-to-end. Standard and Sensitive tier entries (§14) each get one DEK, generated once, wrapped under VRK directly. Critical-tier entries get their DEK Shamir-split (SLIP-39-class, threshold configurable, default 2-of-3 across paired devices) instead of a single VRK-wrapping — reconstructing it requires cooperating devices, natively, with no separate mechanism bolted on.

**Honest framing:** this is a foundational change to Phase A's target architecture. It is proposed now, before any implementation has begun (§ status line throughout this document has consistently read "no code written"), which is the cheapest possible moment to make it — there is nothing to migrate yet. This section is marked as superseding §2–3 rather than rewritten in place there, to keep this edit auditable against the plan's own history rather than silently rewriting earlier decisions.

---

## 20. What The Key Hierarchy Enables

### 20.1 True cryptographic deletion ("crypto-shredding")
Deleting an entry becomes discarding its DEK, not attempting to overwrite its ciphertext on disk — a much smaller, more reliably-erasable artifact than trying to guarantee an SSD's wear-leveling firmware actually overwrote a multi-KB ciphertext region. Once `DEK_i` is destroyed, `entry_i`'s ciphertext — wherever it physically still exists (an old Local Versioned Snapshot, an old export) — is permanently unrecoverable, without needing to touch those older files at all.

**Honest limitation:** this only covers copies still under the app's own encryption. A plaintext CSV export, a value the user manually copied elsewhere, or a device that already displayed the plaintext before deletion, are unaffected — crypto-shredding erases the *encrypted-at-rest* copies, not anything that already left the vault's protection. This should be stated plainly to the user in the deletion-confirmation UI, not implied to be a stronger guarantee than it is.

### 20.2 Fine-grained P2P sync (replaces the whole-vault conflict model in §6.3)
Because each entry is independently encrypted and addressable, sync can operate per-entry: each entry carries its own vector-clock version, and a conflict on one entry doesn't force a whole-vault conflict resolution — only that entry gets archived-and-flagged while every other entry syncs cleanly. This achieves the practical benefit that field-level CRDT merge was meant to provide (§6.3, §9.7) without implementing actual CRDT merge logic — granularity comes from the key structure itself, not from a separate conflict-resolution algorithm. §9.7's "field-level CRDT is out of v1 scope" residual risk is substantially narrowed by this change (per-entry granularity ships in v1; merging *within* a single entry's fields still does not).

### 20.3 Native threshold access for the Critical tier (replaces the bolt-on in §15.3)
§14's Critical tier and §15.3's "optional multi-device key split" were previously two separate mechanisms pointing at the same goal. With the key hierarchy, they're the same mechanism: only a Critical-tier entry's DEK gets Shamir-split; Standard and Sensitive entries never pay that complexity cost. This makes the risk-tiering system (§14) architecturally cheap rather than requiring parallel plumbing.

### 20.4 Capability-based scoped sharing (new)
Sharing a single entry with another paired device — a family member's streaming password, a shared utility account — no longer means transmitting a plaintext copy the recipient keeps forever. Instead, the sender can transmit a **time-boxed or single-reveal-boxed copy of just that entry's DEK** over the already-authenticated Noise channel (§6), never the VRK, never any other entry's key. The receiving app is instructed to discard the DEK after the time window or after one reveal.

**Honest limitation, stated without hedging:** this is receiving-client-enforced, not cryptographically unbreakable. Once a DEK has been transmitted, the recipient's device has it; a modified/malicious client on their end could retain it past the intended window. This is the same fundamental limitation every such scheme has — DRM has the identical "analog hole" problem, and no cryptographic trick removes it, because the recipient's device must be able to decrypt the entry to show it to them at all. What this design *does* provide is a large improvement over the current default (a plaintext copy the recipient keeps forever, no time-boxing, no single-reveal option, and no way to tell them "this access should have expired") — a meaningfully better norm, honestly described as best-effort trusted-client enforcement rather than oversold as unbreakable revocation.

---

## 21. Additional Directions — Evaluated and Tiered by Confidence

### 21.1 Post-quantum-hybrid Noise handshake now, not deferred (revises §9.6's "revisit later" stance)
§9.6 accepted the non-post-quantum X25519 Noise handshake as low-priority, to be revisited later. On reflection, that deferral doesn't hold up: the reason most systems delay post-quantum migration is **interoperability cost** — a PQ-hybrid handshake has to work across every client and server version in a broad ecosystem. This app's P2P sync is a **closed two-party protocol between the app's own instances** — there's no legacy client to stay compatible with, no third party to negotiate with. The interop cost that justifies deferral elsewhere is close to zero here. **Revised decision:** specify the Noise handshake as a classical/PQ **hybrid** from the start (e.g. X25519 combined with a PQ KEM such as ML-KEM/Kyber, combined per current hybrid-construction best practice), closing §9.6 as "addressed" rather than "accepted risk, revisit later." This is a genuinely low-cost, high-signal position for this specific product to take.

### 21.2 Social P2P recovery (extends §15.4's self-only Shamir split)
§15.4 scoped the opt-in Shamir recovery kit to the user's own devices. A natural extension: allow K-of-N shares to be distributed to **trusted contacts' own instances of this app**, transmitted P2P (encrypted, over a one-time pairing-style exchange, the same pattern as §6.1), rather than only across devices the same person owns. Recovering requires contacting K of those people and having each transmit their share back, again P2P — no server ever coordinates or sees a share. This mirrors the "social recovery" pattern seen in some self-custodial crypto wallets, without needing any blockchain or central coordinator. Each share is authenticated (signed) so a malicious contact can't submit a forged one; below the threshold, a share-holder's fragment reveals nothing about the vault (a core Shamir property, unchanged). Scoped as an extension of the already-opt-in §15.4 feature, same off-by-default posture.

### 21.3 Ambient continuous trust (experimental, opt-in, honestly caveated)
Every unlock model in this plan so far is point-in-time: correct at the moment of unlock, then either trusted until lock or re-challenged at fixed triggers (§8.6, §14). A more advanced, fully on-device (no cloud, no telemetry) idea: a lightweight local model that scores ambient signals (typing cadence, interaction pattern) and can trigger an *early* re-challenge if the signal looks anomalous, without waiting for a fixed timeout. **This is flagged as experimental and clearly not v1/v2 material as specified** — behavioral signals are noisy, a cold-start problem exists for any new user or new device, and false positives (interrupting a legitimate user) directly erode trust in the product. Worth a research spike, not a committed roadmap item; including it here so it's a deliberate, documented "not now" rather than a silently-never-considered idea.

### 21.4 Local integrity heartbeat (cheap, detective not preventive)
Borrowing the "warrant canary" idea and applying it locally rather than server-side: each app session can append a locally-signed, chained statement ("opened at T, version V") to a small local log. A gap or a broken chain-link found during later forensic inspection of a device is evidence of tampering or a rollback/downgrade attempt (§12.10, §13) — this is detective, not preventive, and low-cost to add. Mentioned briefly, not over-invested — it's a nice-to-have supporting artifact for incident investigation, not a headline feature.

### 21.5 Explicitly rejected: autonomous credential-rotation bot
A tempting-sounding idea — since the app already generates strong passwords, why not have it periodically log into supported sites and rotate them automatically? **Deliberately not pursued**, and the reasoning matters more than the rejection: this would mean building browser/site automation into a trusted local security tool — a fragile bot that breaks every time a site changes its login flow, is likely to trip anti-bot/anti-fraud defenses on exactly the sites (banks, financial services) where reliability matters most, and — most importantly — **is functionally identical in shape to a credential-stuffing bot**, just aimed at the user's own accounts instead of someone else's. The security surface added (an agent that logs into your bank on its own initiative) is large; the benefit (not having to occasionally change a password yourself) is small. Naming this and explaining why it's out is more useful than silently omitting it — "revolutionary" is not the same evaluation criterion as "good idea," and this plan should say so plainly when the two diverge.

---

## 22. Product Vision Expansion — From Password Manager to Personal Sovereign Secret Fabric

Everything built across this conversation — passwords, TOTP (§12), passkeys (§18.2), risk tiers (§14), per-entry capability sharing (§20.4) — points toward a broader framing than "password manager": a **local-first, zero-cloud root of trust for a person's entire digital identity**, positioned explicitly against the default industry pattern of renting that root of trust from a platform (Google Password Manager, iCloud Keychain, an enterprise IdP). Candidate additional secret types for this broader scope, **vision-tier only, not scheduled**: SSH private keys, GPG/PGP keys, developer API tokens/secrets, encrypted secure notes, identity-document scans (defaulting to Critical tier, §14). None of these change the core architecture (§19's per-entry key hierarchy already generalizes to any secret type, not just passwords) — they're a scope decision, not a technical one.

**Explicit reconciliation with rules_light.txt's own discipline:** §4 of rules_light.txt is direct — no speculative features or abstractions that weren't explicitly requested, once implementation starts. This section exists because the user explicitly asked to expand the planning horizon in *this* turn, not because the roadmap discipline established in earlier sections is being quietly abandoned. To keep that discipline intact as this document keeps growing, every item in this plan now carries an implicit tier, and Phase L below makes the tiers explicit: **Core v1** (Phases A–C, unmodified in scope by this turn) · **v2** (Phases D–K, already flagged in earlier turns) · **Vision / v3+** (§21, §22 — evaluated and documented, not committed). Nothing in this section authorizes writing code beyond what was already scoped into Phase A.

---

## 23. Roadmap — Phase L (Key Hierarchy Migration)

**Task: Per-Entry Key Hierarchy**
- Type: AFK. Objective: §19 — replace Phase A's flat-blob target architecture with VRK + per-entry DEKs before any Phase A implementation begins.
- AC: each entry independently encrypted under its own DEK · DEK table wrapped under VRK, covered as AAD · Critical-tier DEKs Shamir-split (default 2-of-3) instead of single-wrapped · a test verifies that destroying one DEK renders only that entry's ciphertext unrecoverable, with all other entries unaffected.
- Blocked by: none — this revises Phase A itself, takes priority over it.

**Task: Fine-Grained Sync (per-entry vector clocks)**
- Type: AFK. Objective: §20.2 — replaces the whole-vault conflict granularity in the original Conflict Resolution task (Phase G).
- Blocked by: Per-Entry Key Hierarchy, P2P Pairing Protocol.

**Task: Capability-Based Scoped Sharing**
- Type: HITL. Objective: §20.4 — time-boxed/single-reveal DEK transmission over the Noise channel, with the limitation (§20.4) stated plainly in the sharing-confirmation UI, not glossed over.
- Blocked by: Per-Entry Key Hierarchy, P2P Pairing Protocol.

**Task: PQ-Hybrid Noise Handshake**
- Type: AFK. Objective: §21.1 — closes §9.6 as addressed rather than deferred.
- Blocked by: P2P Pairing Protocol.

**Task: Social P2P Recovery (opt-in extension of §15.4)**
- Type: HITL, off by default. Objective: §21.2.
- Blocked by: Shamir-Based Optional Recovery Kit (Phase J), P2P Pairing Protocol.

**Vision backlog (§21.3, §21.4, §22) — deliberately not scheduled into a phase.** Documented so they're a recorded, considered "not yet," not an absence.

---

## 24. Decisions Log — this pass

| Question | Decision | Rationale |
|---|---|---|
| Flat single-blob encryption (§2) or per-entry key hierarchy? | **Per-entry hierarchy (§19), revising Phase A before implementation starts.** | Unifies fine-grained sync, native tiered threshold access, and true crypto-shredding under one primitive instead of three separate bolted-on mechanisms. |
| PQ-hybrid handshake now or later? | **Now (§21.1).** | For a closed two-party local protocol, the interop cost that normally justifies deferring PQ migration doesn't apply — cheap to do early here specifically. |
| Autonomous credential-rotation bot? | **Rejected, explicitly.** | Functionally equivalent in shape to a credential-stuffing bot; fragile against site changes; large new attack surface for small convenience gain. |
| Product scope beyond passwords (SSH/GPG/API tokens/notes)? | **Accepted as vision-tier, not scheduled.** | Architecture already generalizes (§19); scope expansion is a product decision, deliberately not conflated with a technical one. |
| Does "revolutionary" override rules_light's no-speculative-features discipline? | **No.** | This turn's expansions are documented and tiered (Core v1 / v2 / Vision), not silently folded into implementation scope. |

---

**Status: analysis and specification complete. No implementation started. Phase A's target architecture is now the §19 key hierarchy (Phase L), not the original flat-blob design in §2–3 — this revision landed before any code exists, so there is nothing to migrate. Awaiting explicit go-ahead to begin implementation under the rules_light.txt tracer-bullet TDD process (one test -> one minimal implementation, caveman-mode technical communication).**
