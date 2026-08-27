# Vault Crypto — Known Limitations

**Version:** V6.5.1

1. **`V4VaultEntry.password` is Dart `String` in UI model** (Flutter limitation). Crypto core never holds it as String.
2. **Mutation testing covers only encoded mutations.** Not a substitute for external audit.
3. **Wayland global-shortcut portal limitation** (X11 grab works).
4. **Behavioral biometrics is anomaly deterrent, not authentication.**
5. **P2P sync requires both devices online simultaneously** (no async).
6. **BLE 10m range physical, not software-enforced.**
7. **TOTP secrets in vault = single point of failure.**
8. **Security tiers advisory** (determined user can bypass UI).
9. **TOFU first-pairing vulnerable to MITM.**
10. **Cache timing:** Direct cache control not possible in Dart. Constant-time properties delegated to libsodium (AES-NI). See `tool/timing_cache.dart`.
11. **Statistical timing tools require the Flutter runtime** (FFI/AES-NI init); run via `flutter test`, not `dart run`.
12. **libsodium provenance:** Committed `.so` hashes must be compared against the official release; version documented in `BUILD_REPRODUCIBILITY.md`.
