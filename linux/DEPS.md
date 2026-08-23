# Linux Mint build dependencies (v5 E10/E19)

One-shot setup for compiling the Flutter Linux desktop app on Linux Mint 21.x
(Ubuntu 22.04 base). All packages are from the standard Mint/Ubuntu repos.

## Flutter desktop toolchain

```bash
sudo apt update
sudo apt install -y \
  clang \
  cmake \
  ninja-build \
  pkg-config \
  libgtk-3-dev \
  liblzma-dev \
  libstdc++-12-dev
```

## libsodium FFI (crypto core)

```bash
sudo apt install -y libsodium-dev
```

## seccomp DENY-LIST (v5 E19)

The deny-list is installed with raw classic-BPF via `prctl(PR_SET_SECCOMP)` from
libc — no extra runtime package is required. Install the dev package for
headers + a test tool for on-device verification:

```bash
sudo apt install -y libseccomp-dev
```

## System tray + global hotkey (v5 E10)

- Tray: `GtkStatusIcon` (GTK3) works on Cinnamon/XFCE without extra packages.
  `libayatana-appindicator3-dev` is the modern appindicator route:
- Hotkey: X11 `XGrabKey` needs Xlib headers (Wayland portal is a documented
  limitation; `libportal-dev` is optional for the Wayland GlobalShortcuts path).

```bash
sudo apt install -y \
  libx11-dev \
  libxtst-dev \
  libayatana-appindicator3-dev \
  libportal-dev
```

## Full one-liner

```bash
sudo apt update && sudo apt install -y \
  clang cmake ninja-build pkg-config \
  libgtk-3-dev liblzma-dev libstdc++-12-dev \
  libsodium-dev libseccomp-dev \
  libx11-dev libxtst-dev libayatana-appindicator3-dev libportal-dev
```

## Verify

```bash
flutter doctor
flutter build linux --release
```
