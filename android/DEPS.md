# Android Build Dependencies & Setup

**Target:** Android 13+ (API 33+) · **Package:** `com.example.vault_crypto`
**Build system:** Gradle (Kotlin DSL) · **Flutter:** >= 3.0.0

---

## 1. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Linux x86_64 (Ubuntu 22.04 / Mint 21) | Linux x86_64 |
| RAM | 8 GB | 16 GB |
| Disk | 20 GB free | 50 GB free |
| JDK | 17 | 17 (LTS) |
| Android SDK | API 33 | API 34 |
| Flutter | 3.0.0 | Latest stable |
| Disk for SDK | ~10 GB | ~15 GB |

**Note:** This project targets Android 13+ (API 33). BLE permissions use the new Android 12+/13+ model. Devices below API 33 may work but are not the primary target.

---

## 2. Install JDK 17

```bash
sudo apt update
sudo apt install -y openjdk-17-jdk

# Verify
java -version
# Expected: openjdk version "17.0.x"

javac -version
# Expected: javac 17.0.x
```

Set `JAVA_HOME`:

```bash
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64' >> ~/.bashrc
source ~/.bashrc

echo $JAVA_HOME
# Expected: /usr/lib/jvm/java-17-openjdk-amd64
```

---

## 3. Install Android SDK (Command-Line Tools)

### 3.1 Download command-line tools

```bash
mkdir -p ~/Android/Sdk/cmdline-tools
cd ~/Android/Sdk/cmdline-tools

# Download latest command-line tools from:
# https://developer.android.com/studio#command-tools
# (Linux file: commandlinetools-linux-XXXX_latest.zip)

wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip commandlinetools-linux-11076708_latest.zip

# SDK manager expects a specific directory layout:
mv cmdline-tools latest
```

### 3.2 Set environment variables

```bash
cat >> ~/.bashrc << 'EOF'
export ANDROID_HOME=$HOME/Android/Sdk
export ANDROID_SDK_ROOT=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
export PATH=$PATH:$ANDROID_HOME/platform-tools
export PATH=$PATH:$ANDROID_HOME/emulator
EOF

source ~/.bashrc

echo $ANDROID_HOME
# Expected: /home/<you>/Android/Sdk
```

### 3.3 Install SDK components

```bash
# Accept licenses first
sdkmanager --licenses

# Install required packages
sdkmanager "platform-tools" \
           "platforms;android-34" \
           "build-tools;34.0.0" \
           "ndk;26.1.10909125" \
           "cmdline-tools;latest"

# Verify
sdkmanager --list_installed
```

**Note:** NDK is required if native code (libsodium FFI) needs to be built for Android. If Flutter prebuilds the native library, NDK may be optional.

---

## 4. Install Android Studio (Optional but Recommended)

Android Studio provides a GUI for SDK management, emulator, and debugging.

```bash
# Option A: via snap
sudo snap install android-studio --classic

# Option B: via flatpak
flatpak install flathub com.google.AndroidStudio
```

After installing:
1. Open Android Studio
2. Complete Setup Wizard
3. Open **SDK Manager** → verify API 34, build-tools, platform-tools installed
4. Open **AVD Manager** → create a device (optional, real device preferred)

---

## 5. Install Flutter (if not installed)

```bash
# Via snap
sudo snap install flutter --classic

# Or via git
cd ~/dev
git clone https://github.com/flutter/flutter.git -b stable
echo 'export PATH="$PATH:$HOME/dev/flutter/bin"' >> ~/.bashrc
source ~/.bashrc

# Verify
flutter --version
```

---

## 6. Verify Environment

```bash
flutter doctor -v
```

Expected output (Android section):

```
[✓] Android toolchain - develop for Android devices
    • Android SDK at /home/<you>/Android/Sdk
    • Platform android-34, build-tools 34.0.0
    • Java binary at: /usr/lib/jvm/java-17-openjdk-amd64/bin/java
    • Java version OpenJDK Runtime Environment (build 17.0.x)
    • All Android licenses accepted.
```

If licenses not accepted:

```bash
flutter doctor --android-licenses
```

If `flutter doctor` reports missing items, follow its instructions.

---

## 7. Project Dependencies (pubspec.yaml)

Already declared in `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  ffi: ^2.1.0
  meta: ^1.9.0
  local_auth: ^2.2.0          # Biometric authentication
  path_provider: ^2.1.1
  flutter_riverpod: ^2.4.9    # State management (V6.5)
  mobile_scanner: ^5.2.3      # QR code scanner (TOTP import)
  crypto: ^3.0.3              # HMAC for TOTP
  base32: ^2.1.3              # TOTP secret encoding
  pointycastle: ^3.7.3        # HKDF for PSK derivation
  path: ^1.8.3
```

Install:

```bash
cd ~/Downloads/pass
flutter pub get
```

---

## 8. Android Gradle Dependencies

These should be in `android/app/build.gradle.kts`. Verify presence:

```kotlin
dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.fragment:fragment-ktx:1.6.2")
    implementation("com.google.android.gms:play-services-nearby:19.0.0")  // BLE sync
}
```

**Critical:** `play-services-nearby` is required for BLE P2P sync (Nearby Connections API). Without it, `BleTransportPlugin.kt` will not compile.

If missing, add to `android/app/build.gradle.kts` under `dependencies`.

Also verify `android/app/build.gradle.kts` has:

```kotlin
android {
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.vault_crypto"
        minSdk = 33          // Android 13+ target
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}
```

Also verify `android/build.gradle.kts` (project-level) has:

```kotlin
plugins {
    id("com.android.application") version "8.1.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.0" apply false
}
```

And `android/settings.gradle.kts` has Google Maven repository:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
```

---

## 9. Build

### 9.1 Debug build

```bash
cd ~/Downloads/pass
flutter build apk --debug
```

### 9.2 Release build

```bash
flutter build apk --release
```

Output: `build/app/outputs/flutter-apk/app-release.apk`

### 9.3 Install on device

```bash
# Enable USB debugging on Android device:
# Settings -> About Phone -> tap Build Number 7 times
# Settings -> Developer Options -> USB Debugging ON

adb devices              # verify device connected
adb install build/app/outputs/flutter-apk/app-release.apk
```

---

## 10. First-Run Setup (on device)

1. **Enable Autofill Service:**
   Settings → System → Languages & input → Autofill service → select **Vault Crypto**

2. **Grant permissions:**
   - Biometric (fingerprint/face)
   - Bluetooth (Nearby devices)
   - Camera (for TOTP QR import)

3. **Create vault:**
   - Master password (zxcvbn score ≥ 3 recommended)
   - Recovery setup (Shamir shares or encrypted backup)

---

## 11. Test Plan (for P5 — Android Device Verification)

### 11.1 Biometric Keystore

| Test | Steps | Expected |
|------|-------|----------|
| Enroll + unlock | Enroll fingerprint → unlock vault | Vault unlocks |
| Remove fingerprint | Remove fingerprint from device → try unlock | Keystore invalidated, requires master password |
| Add new fingerprint | Enroll new fingerprint → try unlock | Old key invalidated, requires re-setup |

### 11.2 Autofill Service

| Test | Steps | Expected |
|------|-------|----------|
| Basic autofill | Open example.com login → autofill | Credentials filled |
| Domain match | Save for `example.com`, autofill on `example.com` | Fills |
| Domain mismatch | Save for `example.com`, autofill on `evil.com` | Does not fill |
| Lookalike | Save for `example.com`, autofill on `examp1e.com` | Hard-stop, no fill |
| Critical tier | Set entry to Critical → autofill | Manual only, no autofill |

### 11.3 FLAG_SECURE

| Test | Steps | Expected |
|------|-------|----------|
| Lock screen | Lock vault → open recent apps | Black screen, no vault content |
| Screenshot | Lock vault → try screenshot | Black/blocked |

### 11.4 BLE Pairing

| Test | Steps | Expected |
|------|-------|----------|
| Pair two devices | Generate passphrase on A → enter on B | Paired, sync works |
| Weak passphrase | Enter < 12 char passphrase | Rejected |
| Range | Move devices > 10m apart | Discovery fails |
| Replay | Capture handshake, replay | Rejected (replay counter) |

### 11.5 Doze Mode

| Test | Steps | Expected |
|------|-------|----------|
| Idle 1+ hour | Leave device idle | Auto-lock, clipboard wipe |

---

## 12. Troubleshooting

### `flutter doctor` shows "Android licenses not accepted"

```bash
flutter doctor --android-licenses
```

Accept all (press `y`).

### Gradle build fails: "SDK location not found"

Create `android/local.properties`:

```properties
sdk.dir=/home/<you>/Android/Sdk
flutter.sdk=/home/<you>/dev/flutter
```

Or set environment variable:

```bash
export ANDROID_HOME=$HOME/Android/Sdk
```

### `sdkmanager` not found

Verify `cmdline-tools/latest/bin` is in PATH:

```bash
ls $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager
```

If missing, re-do Step 3.1 directory layout (`mv cmdline-tools latest`).

### NDK not found

```bash
sdkmanager "ndk;26.1.10909125"
```

Set NDK path in `android/local.properties`:

```properties
android.ndkVersion=26.1.10909125
```

### `play-services-nearby` not found

Verify `google()` repository in `android/settings.gradle.kts`. Verify internet access for Gradle to download dependencies.

### Build fails: "Duplicate class" or dependency conflict

```bash
cd android
./gradlew clean
cd ..
flutter clean
flutter pub get
flutter build apk --debug
```

### Emulator instead of real device

```bash
flutter devices           # list available
flutter emulators         # list emulators
flutter emulators --launch <emulator_id>
flutter run -d <emulator_id>
```

**Note:** BLE and biometric features do not work on emulators. Use real device for P5 verification.

---

## 13. Verification Checklist

Before declaring Android environment ready:

- [ ] JDK 17 installed, `JAVA_HOME` set
- [ ] Android SDK installed, `ANDROID_HOME` set
- [ ] `sdkmanager` works, licenses accepted
- [ ] platform-tools, platform API 34, build-tools 34 installed
- [ ] NDK installed (if needed)
- [ ] Flutter installed, `flutter doctor` clean
- [ ] `flutter pub get` succeeds
- [ ] `flutter build apk --debug` compiles with 0 errors
- [ ] APK installs on device
- [ ] App launches

Once all checked → update `status.md` P4 from 🟡 to ✅.

---

## 14. Related Documents

- `v6_delta.md` — D5 (Android build setup), D6 (device verification)
- `SECURITY.md` — Android threat model
- `CONTRIBUTING.md` — development discipline
- `status.md` — current platform status

---
