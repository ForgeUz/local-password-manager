# Vault Crypto — Zero-Cloud, Zero-Trust, Zero-Recovery Password Manager

A local-first password manager for Linux (and Android, in progress). **No cloud,
no server, no telemetry.** Your vault is a single encrypted file on your device;
nothing ever leaves it unless you explicitly opt in to prefix-only breach
monitoring.

> **Zero-Recovery by design:** if you lose your master password AND your Shamir
> recovery shares, your data is gone. There is no backdoor, no vendor reset, no
> cloud copy. This is a feature, not a bug.

## Doctrine

- **Zero-Cloud** — the only egress is opt-in breach monitoring (5-char SHA-1
  prefix, or an offline corpus). No server, no relay, no telemetry.
- **Zero-Trust** — every input (MP, TOTP, backup code, PIN, peer, clock, file)
  is treated as hostile until math proves otherwise.
- **Zero-Recovery-by-design** — no backdoor. Inheritance is opt-in and fully
  self-custodied.
- **No home-rolled crypto** — audited bindings only (libsodium FFI).
- **Sync optional** — removing the entire sync module leaves a fully working
  offline password manager.

## Features (V4/V5)

- **Per-entry DEK hierarchy** — each entry has its own CSPRNG DEK wrapped under
  a VRK derived from your master password. Destroying one DEK shreds exactly one
  entry.
- **Single-file GEN4 format** — one encrypted file, two slots (primary + decoy),
  structurally deniable. No separate decoy file exists on disk, ever.
- **Duress vault** — a secondary password opens an isolated, plausible-looking
  vault. The UI never reveals the mechanism.
- **KDF-bound 2FA** — TOTP is folded into the key derivation (math, not a
  check). Backup codes release the second-factor material through the real KDF
  path.
- **Companion-device push approval** — 2-digit number-matching challenge with 3
  options, rate-limited (defeats relay/phishing).
- **FIDO2 hardware-key factor** — a P-256 signature is folded into the KDF
  (keylogger-immune; wrong key fails at GCM).
- **Shamir recovery kit** — split your master key into N shares; any K
  reconstruct it. Fully offline.
- **True SSE search** — searchable symmetric encryption with bucket-padded tags;
  no domain decryption during search.
- **Honeypot canaries** — realistic fake entries that trigger lock + lockdown on
  access.
- **Risk tiers** — Standard / Sensitive / Critical with per-tier reveal
  re-auth.
- **Atomic MP change** — re-wraps all DEKs + recomputes all search tags in one
  temp-file-then-rename save.
- **Group shred + deferral** — duress shred is a group operation across paired
  devices, with cancellation propagation and offline deferral.
- **Liveness/inheritance** — signed epoch tokens + K-of-N shares + friction
  chain for opt-in inheritance.
- **Autofill preview + capability sharing** — domain match + lookalike
  hard-stop before filling; scoped to the matched entry.
- **Sensitive clipboard MIME** — Linux copies set `text/plain;charset=utf-8;sensitive=true` so clipboard managers (CopyQ/Diodon/Klipper) don't log password history.
- **Local security dashboard** — duplicate/weak/old password analysis, fully
  local.
- **Seccomp deny-list** — blocks only the scraping/attach syscalls
  (ptrace, process_vm_*, kcmp, perf_event_open); Dart-VM-safe.

## Build & Run (Linux Mint)

Install dependencies (see [`linux/DEPS.md`](linux/DEPS.md)):

```bash
sudo apt update && sudo apt install -y \
  clang cmake ninja-build pkg-config \
  libgtk-3-dev liblzma-dev libstdc++-12-dev \
  libsodium-dev libseccomp-dev \
  libx11-dev libxtst-dev libayatana-appindicator3-dev libportal-dev
```

Run:

```bash
flutter pub get
flutter run -d linux
```

Release build with integrity hash:

```bash
./build_linux.sh   # builds --release + writes build_hash.txt
```

## Tests

```bash
flutter test        # 203 tests
flutter analyze
dart run tool/mutation_campaign.dart   # mutation kill score (100%)
```

## Honest limitations

- A knowledgeable attacker can *suspect* deniability exists but cannot prove it.
- A coercer holding BOTH passwords defeats the scheme.
- Wayland global-shortcut portal is a documented limitation (X11 grab is the
  working path).
- Behavioral biometrics is an anomaly deterrent, never authentication; FP/FN
  are measured empirically, not fabricated.

## License

MIT — see [LICENSE](LICENSE). See [SECURITY.md](SECURITY.md) for the security
model and vulnerability reporting, [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for
the native-memory + clipboard audit, and [CONTRIBUTING.md](CONTRIBUTING.md) for
the development discipline.
