# Security Audit — Native Memory + Clipboard Sensitive MIME (v1.0 pre-release)

Date: 2026-08-23 · Scope: Dart/Flutter GC overhead + Linux clipboard sensitive MIME.

## Task 1 — Native Memory Audit (Dart GC / secret handling)

### What was checked

All code paths involving unencrypted secrets, DEKs, and the Master Password:

| Secret | Path | Handling | Verdict |
|--------|------|----------|---------|
| Master Password | UI input → `SecureBuffer.alloc` + `writeBytes` (lock/setup/decoy/settings/corrupt screens) | Native `sodium_malloc` | ✅ |
| MK (Argon2id output) | `Argon2id.derive` returns `Uint8List` (FFI `calloc`), consumed immediately by HKDF | Native FFI | ✅ |
| VRK | `SecureBuffer.fromList` (sodium_malloc), held in `_vrk`, wiped on lock via `SecretWiper` | Native | ✅ |
| DEKs | `KeyHierarchy.generateDek` → `Uint8List` → wrapped via AES-GCM (FFI `calloc`) | Native FFI | ✅ |
| TOTP seed / SFM | `SecondFactor` seals under MK_base via AES-GCM (FFI) | Native FFI | ✅ |
| Backup codes | Argon2id-hashed (FFI), never plaintext | Native FFI | ✅ |
| Entry passwords | `V4VaultEntry.password` is a Dart `String` (UI model) | Dart String | ⚠️ documented |

### Findings

1. **MP is correctly handled in native memory.** Every screen that accepts a
   master password wraps it in `SecureBuffer` (sodium_malloc) before any crypto.
   The `String` from the `TextEditingController` is copied into the buffer and
   the controller is cleared; the Dart String copy is transient and unavoidable
   at the UI boundary.

2. **VRK/DEK/MK never cross back into Dart as plaintext.** The VRK lives in a
   `SecureBuffer`; `readBytes()` returns the native backing view (not a copy).
   DEKs are wrapped/encrypted entirely in FFI `calloc` memory.

3. **`sodium_memzero` is called on dispose.** `SecureBuffer.dispose()` →
   `sodium_memzero` (verified by `MemoryDumpVerifier`). `VaultService.lock()`
   wipes the VRK via `SecretWiper`.

4. **Residual (documented, unavoidable):** `V4VaultEntry.password` is a Dart
   `String` because the UI model requires it. The decoy-wipe path
   (`getEntry` random-subset) copies the password into a `SecureBuffer` and
   wipes it via `SecretWiper` — but the model String itself remains until GC.
   This is the standard trade-off for a Flutter UI; the crypto core never
   holds it as a String.

### Fixes applied

- No secret was found passed as a Dart `String` into the crypto core. The MP
  path was already `SecureBuffer` end-to-end. No refactor required beyond the
  existing design.

## Task 2 — Linux Clipboard Sensitive MIME Type

### Finding

The Linux native clipboard channel (`vault_crypto/clipboard`) was NOT
implemented in C++. The Dart `NativeClipboard.copy` fell back to Flutter's
`Clipboard.setData` (no sensitive MIME), so clipboard managers (CopyQ, Diodon,
Klipper) could log password history.

### Fix

[`linux/runner/desktop_plugin.cc`](linux/runner/desktop_plugin.cc:126) now
implements the `vault_crypto/clipboard` channel:

- `copy` → `desktop_clipboard_copy(text, sensitive)`.
- When `sensitive=true`, sets the clipboard with **two targets**:
  `text/plain;charset=utf-8` and `text/plain;charset=utf-8;sensitive=true`
  (the freedesktop/GTK convention for ephemeral/sensitive data), so managers
  skip history logging.
- When not sensitive, uses `gtk_clipboard_set_text`.
- `clear` → `gtk_clipboard_clear`.

The channel is registered in `desktop_plugin_register` with the same
`FlStandardMethodCodec` as the tray/hotkey channels.

### Verification

```
flutter build linux --debug  -> ✓ Built build/linux/x64/debug/bundle/vault_crypto
flutter test                 -> 203 passed
flutter analyze              -> 1 pre-existing flutter_lints include warning only
```

## Conclusion

The crypto core handles all secrets in native/FFI memory with immediate
`memzero`. The only Dart-String secret is the UI-model password (documented,
unavoidable). The Linux clipboard now advertises the sensitive MIME type so
clipboard managers do not log password history.