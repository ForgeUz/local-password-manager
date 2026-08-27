# Vault Crypto — Build Reproducibility

**Version:** V6.5.1

## How to verify a build

1. **Build twice, compare hashes:**
   ```bash
   ./build_linux.sh
   sha256sum build/linux/x64/release/bundle/vault_crypto
   ./build_linux.sh
   sha256sum build/linux/x64/release/bundle/vault_crypto
   ```
   The two hashes must be identical. If they differ, investigate
   non-determinism (timestamps, paths, build IDs).

2. **Verify libsodium provenance:**
   ```bash
   dart run tool/verify_libsodium.dart
   ```
   Compare the reported SHA-256 hashes against the official libsodium release
   for the documented version.

3. **Verify no debug symbols in release:**
   ```bash
   strings build/linux/x64/release/bundle/vault_crypto | grep -i "debug\|log\|password"
   ```
   Release builds must not contain debug logging or plaintext password strings.

4. **Verify dependencies are pinned:**
   ```bash
   dart run tool/verify_deps.dart
   ```

## libsodium version

- **Android:** `android/app/src/main/jniLibs/arm64-v8a/libsodium.so` and
  `armeabi-v7a/libsodium.so`
- **Version:** Must be documented here after verification against the official
  release. Run `dart run tool/verify_libsodium.dart` to get the current hashes.
- **Security advisories:** Check the libsodium security announcements for the
  documented version.

## Known-good hashes

| Binary | SHA-256 |
|--------|---------|
| arm64-v8a/libsodium.so | (record after official verification) |
| armeabi-v7a/libsodium.so | (record after official verification) |
