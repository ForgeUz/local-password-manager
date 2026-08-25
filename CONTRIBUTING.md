# Contributing to Vault Crypto

Thank you for considering contributing to Vault Crypto. This project has strict engineering discipline because it handles secrets. Contributions must meet the same bar as the core.

---

## 1. Doctrine (Read First)

Vault Crypto is a **zero-cloud, zero-trust, zero-recovery** password manager. Every contribution must respect this:

- **Zero-Cloud** - no network egress except opt-in breach monitoring (5-char SHA-1 prefix). Do not add cloud features.
- **Zero-Trust** - treat all input as hostile. Validate at boundaries, fail closed.
- **Zero-Recovery-by-design** - no backdoors, no vendor reset, no recovery that weakens security.
- **No home-rolled crypto** - use libsodium via FFI only. Never implement primitives.
- **Sync optional** - removing sync must leave a working offline manager.

If your contribution violates any doctrine, it will be rejected. Discuss design changes via issue first.

---

## 2. Development Discipline

This project follows strict engineering rules. Contributors must comply.

### 2.1 Atomic Patches Only

- **Never rewrite entire files.** Submit minimal `git diff` patches.
- Touch only lines necessary for the change.
- No drive-by refactoring, no formatting changes, no dead-code removal unless explicitly requested.
- One logical change per PR.

### 2.2 Test-Driven Development (TDD)

- Write ONE test -> write ONE minimal implementation to pass it.
- Red-Green-Refactor loop.
- Do not write all tests then all code (no horizontal slices).
- Write only minimal code to pass the current test. No speculative features.

### 2.3 Verification Gates

No code is complete until it passes, in order:

1. **Type checker** - `flutter analyze` (0 errors)
2. **Unit tests** - `flutter test`
3. **Mutation tests** - for crypto/security logic, mutation score must stay at 100%

Run before submitting:

```bash
flutter analyze
flutter test
dart run tool/mutation_campaign.dart
```

### 2.4 Property-Based Testing (PBT)

For logic with mathematical invariants (crypto, parsers, state machines):

- Define invariants explicitly.
- Use fuzzing/PBT to test edge cases.
- Static unit tests alone are insufficient.

### 2.5 Immutability & Fail Fast

- Prefer `const` and `final` data structures.
- Raise exceptions immediately when preconditions violated.
- No silent fallbacks for security errors.

---

## 3. Code Documentation Standard

Every module and non-trivial function must have semantic doc comments. Use these tags:

```dart
// Intent: [why this exists]
// Invariants: [conditions always true before/after]
// State Transition: [Initial -> Trigger -> New State]
// Dependencies: [external logic relied on]
```

Document the **WHY** before the **WHAT**. Terse fragment sentences. Causal arrows (`->`) welcome.

Example:

```dart
// Intent: Derive VRK from master password + optional TOTP.
// Invariants: VRK never persisted; IKM zeroed after HKDF.
// State Transition: Locked -> derive(MP) -> Unlocked(VRK held in SecureBuffer).
// Dependencies: Argon2id, HKDF, SecureBuffer.
```

---

## 4. Architecture Rules

### 4.1 State / View Separation

- UI files only dispatch intent.
- State machines process intent and emit new state.
- Render functions strictly reflect current state.

### 4.2 Pure Core / Imperative Shell

- Crypto, validation, data transformation = 100% pure functions (no side effects, no I/O).
- I/O lives at the shell (platform channels, file system).

### 4.3 Do Not Touch Verified Core Without Discussion

The crypto core is mutation-tested (51/51 kill). Files under `lib/src/crypto/` are **protected**.

- Do not modify crypto core without opening an issue first.
- Changes to crypto require: new invariant, new test, mutation coverage, maintainer approval.
- V6.5 features must not alter verified crypto paths.

---

## 5. Project Structure

```
lib/
  main.dart
  screens/              # Top-level Flutter screens
  src/
    crypto/             # VERIFIED CORE (protected)
      v4/               # Vault format, GCM, key hierarchy
      native/           # FFI wrappers (libsodium)
    security/           # Security tiers, dashboard, lookalike detection
    autofill/           # Autofill enforcement logic
    totp/               # RFC 6238 TOTP generator + import
    sync/               # P2P sync (optional module)
    vault/              # Vault service layer
    ui/                 # Widgets
android/                # Android platform layer (Kotlin)
linux/                  # Linux platform layer (C++)
test/                   # Tests, mirrors lib/ structure
tool/                   # Mutation campaign, build scripts
```

Tests mirror `lib/` structure: `lib/src/totp/totp_generator.dart` -> `test/totp/totp_generator_test.dart`.

---

## 6. Contribution Workflow

### Step 1: Open an Issue

- Bug report, feature request, or design question.
- Security vulnerabilities: do NOT open a public issue. See `SECURITY.md` for private reporting.

### Step 2: Fork & Branch

```bash
git clone https://github.com/<you>/local-password-manager.git
cd local-password-manager
git checkout -b feature/your-change   # or fix/your-bug
```

### Step 3: Implement (TDD)

- Write failing test first.
- Implement minimal code to pass.
- Keep changes atomic.

### Step 4: Verify

```bash
flutter pub get
flutter analyze          # must be 0 errors
flutter test             # all tests pass
dart run tool/mutation_campaign.dart   # if touching security logic
```

### Step 5: Commit

Commit message format:

```
<type>: <short summary>

<why this change, not just what>

Invariant: <what property is preserved/added>
```

Types: `fix`, `feat`, `test`, `docs`, `refactor`, `security`.

Example:

```
fix: reject lookalike domains in autofill enforcer

Homoglyph substitution (0/o, 1/l) could bypass domain match.
Added confusable detection before exact-match check.

Invariant: critical tier never autofills on non-exact domain.
```

### Step 6: Open Pull Request

- Reference the issue (`Fixes #123`).
- Describe the change and the invariant it preserves.
- List tests added.
- Confirm all verification gates pass.

### Step 7: Review

- Maintainer reviews for doctrine compliance, security, test coverage.
- Security-sensitive PRs require explicit maintainer approval.
- Expect requests for more tests or invariant documentation.

---

## 7. Security Checklist (for PRs touching security)

Before submitting a PR that touches crypto, auth, or secret handling:

- [ ] All secrets zeroed before scope exit (native + Dart)
- [ ] Constant-time comparison for secret material
- [ ] Bounds checking on all parser input
- [ ] No information leakage via error types (no oracle)
- [ ] Domain separation for any new HKDF use
- [ ] AES-GCM nonce never reused with same key
- [ ] New security invariant has a test
- [ ] New security invariant has a mutation (if in TCB)
- [ ] Doc comments include Intent/Invariants/State Transition/Dependencies
- [ ] No secrets in logs, errors, or UI

---

## 8. V6.5 Feature Guidelines

If contributing to V6.5 features:

### Security Tiers
- Never allow critical tier to autofill.
- Never allow critical tier export.
- Downgrades must require confirmation.

### TOTP
- Secrets must stay in `SecureBuffer`.
- Never log or display secrets after import.
- Follow RFC 6238 test vectors.

### P2P Sync
- No cloud relay. Local only.
- Passphrase validation must stay strong.
- Conflict resolution must block sync until resolved.

### Android
- No INTERNET permission in manifest.
- `allowBackup` must stay `false`.
- Domain must come from `AssistStructure.webDomain` (trusted).

---

## 9. Local Setup

### Linux

```bash
sudo apt install -y clang cmake ninja-build pkg-config \
  libgtk-3-dev liblzma-dev libstdc++-12-dev \
  libsodium-dev libseccomp-dev \
  libx11-dev libxtst-dev libayatana-appindicator3-dev libportal-dev

flutter pub get
flutter run -d linux
```

### Android

```bash
sudo apt install openjdk-17-jdk
# Install Android SDK, NDK, platform-tools
flutter pub get
flutter build apk --debug
```

See `android/` for full Android setup. See `linux/DEPS.md` for Linux details.

---

## 10. What We Will Reject

- Cloud sync or any network egress feature
- Home-rolled crypto
- Weakening zero-recovery doctrine
- Rewriting verified crypto core without discussion
- PRs without tests for security logic
- PRs that fail `flutter analyze`
- Marketing language in docs (honest limitations only)

---

## 11. Recognition

Contributors are credited in release notes. Security researchers who find vulnerabilities are credited in security advisories (see `SECURITY.md`).

---

## 12. Questions?

Open an issue for discussion. For security matters, use the private channel in `SECURITY.md`.

---