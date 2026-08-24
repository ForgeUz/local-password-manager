# libsodium native library (Android)

The Dart crypto layer loads `libsodium.so` at startup via `dart:ffi`
(see `lib/src/crypto/native/sodium_ffi.dart`). On Android this .so MUST be
physically bundled in the APK — Android has no system libsodium.

Place the ABI-specific shared library here:

```
android/app/src/main/jniLibs/
├── arm64-v8a/libsodium.so      (most 2017+ phones/tablets)
└── armeabi-v7a/libsodium.so    (older 32-bit devices)
```

Gradle packages everything under `jniLibs/` automatically (default
`sourceSets.main.jniLibs.srcDirs`). No extra wiring is needed.

## Build it yourself (offline, uses installed NDK)

The system has Android NDK 28.2.13676358 + CMake 3.22.1. Build libsodium from
source and copy the outputs:

```bash
# 1. Fetch libsodium source (any tag; latest stable 1.0.20)
git clone --depth 1 -b 1.0.20 https://github.com/jedisct1/libsodium libsodium
cd libsodium

# 2. Cross-compile for arm64 + armv7 via NDK toolchain
for abi in arm64-v8a armeabi-v7a; do
  cmake -DCMAKE_TOOLCHAIN_FILE=/usr/lib/android-sdk/ndk/28.2.13676358/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=$abi -DANDROID_PLATFORM=android-31 -DBUILD_SHARED_LIBS=1 -B build-$abi
  cmake --build build-$abi
done

# 3. Copy outputs into jniLibs
cp build-arm64-v8a/libsodium.so ../android/app/src/main/jniLibs/arm64-v8a/
cp build-armeabi-v7a/libsodium.so ../android/app/src/main/jniLibs/armeabi-v7a/
```

## Quick path (online)

Grab prebuilt .so from a trusted source (e.g. the `sodium_libs` v3.x cached
artifacts or `libsodium-android` releases), or use the older
`sodium_libs: ^3.4.6+4` pub package which bundles the .so for these ABIs.

## Security note

The .so is loaded by `dart:ffi` and invoked via the audited
`sodium_*` C ABI. Do NOT substitute an unverified libsodium build; use an
official/audited release.