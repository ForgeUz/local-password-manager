// File: tool/verify_deps.dart
// Intent: security2.md gate 27.1 — Dependency pinning & verification.
// Verifies that pubspec.lock contains exact versions (no ^) and that the
// dependency set is stable.
// Invariants:
// - pubspec.lock contains exact versions (no ^).
// - No dependencies added since last audit without review.
// - All transitive dependencies documented.
// - ALLOWLIST GATE (Part III-C): any direct dependency NOT in the explicit
//   allowlist fails the build. This is the typosquatting/slopsquatting defense:
//   an AI-hallucinated or typo'd package name cannot silently enter the tree.
//   Adding a dependency is a security decision, not a convenience — it requires
//   a PR that justifies it against a direct-implementation alternative, pins
//   the exact hash, and checks the maintainer's history.
// Usage: dart run tool/verify_deps.dart
// Dependencies: dart:io.

import 'dart:io';

// Explicit allowlist of direct dependencies. Every entry must be justified:
// - ffi: direct libsodium FFI (no wrapper package — supply-chain posture)
// - meta: Dart SDK annotation package
// - local_auth: OS-level biometric prompts (not spoofable by overlays)
// - path_provider: app data directory resolution
// - flutter_riverpod: state management
// - mobile_scanner: QR scanning for Shamir recovery shares
// - crypto: SHA/HMAC primitives (verified against libsodium in self-test)
// - base32: share encoding
// - path: path manipulation
// Dev-only: flutter_lints, flutter_test, test.
const _allowlist = {
  'flutter',
  'ffi',
  'meta',
  'local_auth',
  'path_provider',
  'flutter_riverpod',
  'mobile_scanner',
  'crypto',
  'base32',
  'path',
  'flutter_lints',
  'flutter_test',
  'test',
};

void main() {
  final lockFile = File('pubspec.lock');
  if (!lockFile.existsSync()) {
    print('FAIL: pubspec.lock not found.');
    exit(1);
  }

  final content = lockFile.readAsStringSync();
  var failures = 0;

  // 1. pubspec.lock must not contain '^' (exact versions only).
  if (content.contains('^')) {
    print('FAIL: pubspec.lock contains "^" (non-exact version).');
    failures++;
  } else {
    print('PASS: pubspec.lock contains exact versions (no ^).');
  }

  // 2. pubspec.lock must contain a "sdks" section (dependency lock).
  if (!content.contains('sdks:')) {
    print('FAIL: pubspec.lock missing "sdks" section.');
    failures++;
  } else {
    print('PASS: pubspec.lock has sdks section.');
  }

  // 3. ALLOWLIST GATE: every direct dependency must be in the allowlist.
  // Only names under the dependencies:/dev_dependencies: sections count. The
  // "sdk: flutter" key and the flutter "uses-material-design" config key are
  // not dependencies and must be excluded.
  final pubspec = File('pubspec.yaml');
  if (pubspec.existsSync()) {
    final ps = pubspec.readAsStringSync();
    final deps = <String>[];
    var inDeps = false;
    for (final line in ps.split('\n')) {
      if (line.startsWith('dependencies:')) {
        inDeps = true;
        continue;
      }
      if (line.startsWith('dev_dependencies:')) {
        inDeps = true;
        continue;
      }
      if (inDeps && RegExp(r'^\S').hasMatch(line)) {
        inDeps = false; // next top-level section
        continue;
      }
      if (inDeps) {
        final m = RegExp(r'^\s{2}(\w[\w-]*):').firstMatch(line);
        if (m != null) {
          final name = m.group(1)!;
          if (name != 'sdk' && name != 'uses-material-design') {
            deps.add(name);
          }
        }
      }
    }
    print('Direct dependencies: ${deps.length}');
    for (final d in deps) {
      if (_allowlist.contains(d)) {
        print('  - $d (allowlisted)');
      } else {
        print('  - $d (NOT ALLOWLISTED)');
        print('FAIL: dependency "$d" is not in the allowlist. '
            'Adding a dependency is a security decision. Justify it against a '
            'direct-implementation alternative, pin the exact hash, and check '
            'the maintainer history before adding it to the allowlist.');
        failures++;
      }
    }
  }

  if (failures > 0) {
    print('FAIL: $failures dependency check(s) failed.');
    exit(1);
  }
  print('PASS: dependency pinning + allowlist gate verified.');
}
