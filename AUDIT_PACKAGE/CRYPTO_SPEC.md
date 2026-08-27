# Vault Crypto — Cryptographic Specification

**Version:** V6.5.1
**Status:** Internal verification complete; external audit pending.

This document specifies the exact cryptographic construction so an auditor can
review without reading code. Each spec point references the test file that
verifies it.

---

## 1. GEN4 File Format (Byte Layout)

```
vault := fixed_header(44) + entry_table + slot2(256) + outer_tag(16)

fixed_header:
  magic(4)  = 0x47454e34 ('GEN4')
  version(1)= 4
  algo(1)   = 1 (Argon2id)
  memory(4) = 65536 (KiB = 64 MiB)
  iterations(4) = 3
  parallelism(1) = 1
  salt(16)
  nonce(12)
  vault_count(1) = 2 (always, for deniability)

entry_table:
  entry_count(2)
  entry_record * entry_count

entry_record:
  id(16)
  tier(1)
  wrapped_dek_len(2)
  wrapped_dek(wrapped_dek_len)   # nonce(12) || AES-GCM(VRK, DEK)
  search_tag_count(2)
  search_tag(32) * search_tag_count
  vector_clock_len(2)
  vector_clock(vector_clock_len)
  ciphertext_len(4)
  ciphertext(ciphertext_len)     # nonce(12) || AES-GCM(DEK, padded)

slot2: decoy vault blob OR 256 bytes CSPRNG noise (not in outer AAD)
outer_tag(16): AES-GCM(VRK, nonce=zeros, AAD=header, empty plaintext)
```

**Verified by:** `test/security/format/test_gen4_parser.dart`,
`test/security/model/test_format_model.dart`.

---

## 2. Key Derivation Diagram

```
Master Password + Salt
        |
        v  Argon2id(m=65536, t=3, p=1)
       MK (32 bytes)
        |
        v  HKDF-SHA256(info="GENESIS-VRK-v4")
       VRK (32 bytes)
        |
        +-- AES-GCM(VRK, DEK_i) -> wrapped DEK_i   (per entry)
        |
        +-- HKDF(info="GENESIS-SEARCH-v4") -> SearchKey
        |
        +-- outer header MAC (AAD = header)
```

**Verified by:** `test/security/crypto/test_key_hierarchy.dart`,
`test/security/crypto/test_hkdf.dart`.

---

## 3. Domain Separation Strings

| Purpose | Info string |
|---------|-------------|
| VRK derivation | `GENESIS-VRK-v4` |
| Duress VRK | `GENESIS-VRK-DURESS` |
| Search key | `GENESIS-SEARCH-v4` |

All strings are prefix-free (no string is a prefix of another).

**Verified by:** `test/security/crypto/test_hkdf.dart`.

---

## 4. Argon2id Parameters

- Algorithm: Argon2id (id = 2 in libsodium)
- memory_cost: 65536 KiB (64 MiB)
- time_cost: 3
- parallelism: 1
- Output: 32 bytes

**Verified by:** `test/security/crypto/test_argon2id.dart`,
`test/security/differential/test_argon2_differential.dart`.

---

## 5. AES-GCM Usage

- Algorithm: AES-256-GCM (libsodium `crypto_aead_aes256gcm`)
- Key: 32 bytes
- Nonce: 12 bytes, CSPRNG-generated (never counter/timestamp)
- Tag: 16 bytes
- AAD: header bytes for the outer MAC; empty for entry ciphertext
- AES-NI required (fail-closed if unavailable)

**Verified by:** `test/security/crypto/test_aes_gcm.dart`,
`test/security/crypto/test_nonce.dart`.

---

## 6. Noise Protocol (Sync)

- Pattern: NNpsk0 (PSK-based pairing)
- PSK: derived via Argon2id(passphrase, salt, 64 MiB, 3)
- TOFU: peer static key pinned on first connection
- 60-second pairing window, max 3 attempts, cooldown

**Verified by:** `test/security/sync/test_noise.dart`,
`test/security/statemachine/test_sync_states.dart`.

---

## 7. Shamir Secret Sharing

- Field: GF(256), irreducible polynomial 0x11b
- Threshold K of N shares reconstruct the secret
- K-1 shares reveal nothing (information-theoretic)
- Share format: base64(x(1) || y)

**Verified by:** `test/security/recovery/test_shamir.dart`.

---

## 8. Search Tag (SSE)

- SearchKey = HKDF(VRK, "GENESIS-SEARCH-v4")
- search_tag = HMAC-SHA256(SearchKey, normalized domain)
- Prefix tags for length 3..full domain, bucket-padded (4/8/16/32/64)
- URL normalization: strip scheme, www, trailing slash

**Verified by:** `test/security/search/test_sse.dart`.

---

## 9. TOTP Folding into KDF

- TOTP secret (SFM) sealed under MK_base via AES-GCM
- On unlock, SFM is folded into the HKDF IKM: VRK = HKDF(MK || SFM)
- Backup codes: Argon2id-hashed, single-use, rate-limited (3 attempts)

**Verified by:** `test/security/auth/test_totp.dart`.
