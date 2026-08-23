# Security Policy

## Local-first, no servers

This is a **local-first** application. There are no servers, no cloud sync, no
telemetry, and no vendor-controlled infrastructure. The only network egress is
**opt-in** breach monitoring, which sends a 5-character SHA-1 prefix of a
password hash to the HIBP k-anonymity API (or uses a fully offline corpus).

## Zero-Recovery warning

**If you lose your master password AND your Shamir recovery shares, your data
is permanently gone.** There is no backdoor, no reset, no cloud copy, and no
vendor assistance path. This is by design (zero-recovery-by-design). Back up
your Shamir shares physically and keep them separate from the device.

## Threat model

- **File-only attacker:** learns entry count and (before padding) domain
  length. Tags are opaque pseudorandom blobs without the SearchKey (requires
  the VRK, requires the MP).
- **Memory attacker:** mitigated by native secure memory (sodium_malloc/mlock),
  zero-wipe on lock, and a seccomp deny-list blocking ptrace/process_vm_*.
- **Coercion:** duress vault + honeypot canaries + group shred. A coercer
  holding BOTH passwords defeats the scheme (stated honestly in the UI).
- **Patched build:** device-enforced policies (cooldowns, time-locks) are
  honest-path enforcement, not math. A patched build can bypass them.

## Reporting a vulnerability

Please report security vulnerabilities privately via **GitHub private
advisories** (Security → Advisories → New draft advisory) or by emailing the
maintainer (address in the repository profile).

Please include:

1. Affected version / commit.
2. A minimal reproduction (steps, inputs).
3. Impact assessment (what an attacker gains).

We will acknowledge within 5 business days and aim for a fix + advisory within
30 days. **Do not** open a public issue for a security vulnerability.

## Responsible disclosure

- No public disclosure until a fix is released.
- No exploitation beyond demonstrating the vulnerability.
- We credit reporters in the advisory (unless anonymity is requested).

## Supported versions

| Version | Status |
|---------|--------|
| v1.0.0 (current) | Supported |
| Older | Not supported |

## Build integrity

Release builds publish `build_hash.txt` (SHA-256 of the release binary). The
`IntegrityHeartbeat` can verify the running binary against this manifest at
runtime (advisory). Community members can rebuild from source and compare
hashes (see [`tool_versions`](tool_versions) for the pinned toolchain).

## Security audit

See [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) for the pre-release native-memory
audit (all secrets handled in `SecureBuffer`/FFI memory with immediate
`memzero`) and the Linux clipboard sensitive-MIME fix (password copies set
`text/plain;charset=utf-8;sensitive=true` so clipboard managers do not log
history).