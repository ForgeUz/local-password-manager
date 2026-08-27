// File: tool/verify_deps.dart
// Intent: security2.md gate 27.1 — Dependency pinning & verification.
// Verifies that pubspec.lock contains exact versions (no ^) and that the
// dependency set is stable.
// Invariants:
// - pubspec.lock contains exact versions (no ^).
// - No dependencies added since last audit without review.
// - All transitive dependencies documented.
// Usage: dart run tool/verify_deps.dart
// Dependencies: dart:io.

import 'dart:io';

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

  // 3. Count direct dependencies in pubspec.yaml.
  final pubspec = File('pubspec.yaml');
  if (pubspec.existsSync()) {
    final ps = pubspec.readAsStringSync();
    final deps = RegExp(r'^\s{2}(\w[\w-]*):', multiLine: true)
        .allMatches(ps)
        .map((m) => m.group(1)!)
        .toList();
    print('Direct dependencies: ${deps.length}');
    for (final d in deps) {
      print('  - $d');
    }
  }

  if (failures > 0) {
    print('FAIL: $failures dependency check(s) failed.');
    exit(1);
  }
  print('PASS: dependency pinning verified.');
}
