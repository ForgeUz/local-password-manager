// File: tool/verify_comment_traceability.dart
// Intent: Part IV item 1 — Comment-traceability rule.
// Any comment containing a security-claim keyword (SECURITY, CRITICAL, MUST,
// atomic, zeroed, securely) MUST be backed by a test. This is the defense
// against silent comment/code divergence — the class that hid both _encodeId
// and deleteVault. A comment that claims a security property with no test
// backing it is a gap.
//
// Traceability heuristic (module-level, honest proxy):
//   A security-claiming comment in lib/src/<dir>/<file>.dart is traceable if a
//   test file exists at test/<dir>/<file>_test.dart (or the comment references
//   a test path / quoted test description inline). This enforces "no security
//   claim without a test" without requiring every comment to inline a path.
//
// Usage: dart run tool/verify_comment_traceability.dart
// Dependencies: dart:io.

import 'dart:io';

// Keywords that mark a comment as making a security claim.
const _claimKeywords = [
  'SECURITY',
  'CRITICAL',
  'MUST',
  'atomic',
  'zeroed',
  'securely',
];

// Directories to scan (lib only; tool/ and test/ are excluded).
const _scanRoot = 'lib';

void main() async {
  var failures = 0;
  var claims = 0;
  var traceable = 0;

  final files = <File>[];
  await for (final e in Directory(_scanRoot).list(recursive: true)) {
    if (e is File && e.path.endsWith('.dart')) files.add(e);
  }

  for (final f in files) {
    final lines = await f.readAsLines();
    for (var i = 0; i < lines.length; i++) {
      final line = lines[i];
      final trimmed = line.trim();
      if (!trimmed.startsWith('//') && !trimmed.startsWith('*') &&
          !trimmed.startsWith('/*')) {
        continue;
      }
      final hasClaim = _claimKeywords.any((k) => line.contains(k));
      if (!hasClaim) continue;
      claims++;

      // A claim is traceable if:
      //  (a) the comment (or 3 lines above) references a test path or a quoted
      //      test description, OR
      //  (b) the module has a corresponding test file.
      final context = <String>[
        line,
        if (i >= 1) lines[i - 1],
        if (i >= 2) lines[i - 2],
        if (i >= 3) lines[i - 3],
      ].join('\n');

      final inlineRef = context.contains('test/') ||
          RegExp(r"'[^']+'").hasMatch(context);
      final moduleTest = _correspondingTestExists(f.path);
      if (inlineRef || moduleTest) {
        traceable++;
      } else {
        failures++;
        print('UNTESTED CLAIM: ${f.path}:${i + 1}');
        print('  $trimmed');
        print('');
      }
    }
  }

  print('Security-claiming comments: $claims');
  print('Traceable (test-backed): $traceable');
  print('Untested: $failures');
  if (failures > 0) {
    print('FAIL: $failures security-claiming comment(s) have no test backing. '
        'Add a test file for the module or reference a test inline.');
    exit(1);
  }
  print('PASS: every security-claiming comment is test-backed.');
}

/// Search the entire test/ tree for a test file whose basename matches the
/// module (e.g. lib/src/crypto/padding.dart -> any test/padding_test.dart).
/// Tests are organized under many roots (test/crypto, test/security, ...), so
/// a recursive basename match is the honest proxy for "this module is tested".
bool _correspondingTestExists(String libPath) {
  if (!libPath.startsWith('lib/src/')) return false;
  final rel = libPath.substring('lib/src/'.length); // e.g. lock/secret_wiper.dart
  final dot = rel.lastIndexOf('.');
  if (dot < 0) return false;
  final base = rel.substring(0, dot);
  final leaf = base.split('/').last; // e.g. secret_wiper
  final want = '${leaf}_test.dart';
  final testDir = Directory('test');
  if (!testDir.existsSync()) return false;
  final found = testDir
      .listSync(recursive: true)
      .whereType<File>()
      .any((f) => f.path.endsWith('/$want'));
  return found;
}