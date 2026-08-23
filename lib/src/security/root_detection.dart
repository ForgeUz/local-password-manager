import 'dart:io';

// Intent: Android root detection (v4 §8 Phase D.6, v2 §5.1). Advisory only —
// a rooted device weakens Keystore guarantees but the app remains usable.
// Never blocking. Detects root by probing known marker files/directories.
// Invariants: flags rooted iff any marker exists; returns false for missing
// markers; marker list is non-empty.
// Dependencies: dart:io (File/Directory.exists).

class RootDetection {
  // Canonical Android root-indicator paths.
  static const List<String> defaultMarkers = [
    '/system/bin/su',
    '/system/xbin/su',
    '/sbin/su',
    '/system/app/Superuser.apk',
    '/data/local/bin/su',
    '/su/bin/su',
    '/system/bin/failsafe/su',
    '/system/etc/init.d/99SuperSUDaemon',
  ];

  // Advisory: returns true if any marker exists. Callers must treat this as a
  // warning, never a hard block.
  static bool isRooted(List<String> markers) {
    for (final m in markers) {
      if (File(m).existsSync() || Directory(m).existsSync()) return true;
    }
    return false;
  }
}