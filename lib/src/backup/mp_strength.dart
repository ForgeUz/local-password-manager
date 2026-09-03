// Intent: Heuristic check for Master Password strength. Warn-only.
import 'dart:typed_data';

class MpStrengthResult {
  final MpStrengthLevel strength;
  final String warning;

  MpStrengthResult(this.strength, this.warning);
}

enum MpStrengthLevel { weak, fair, strong }

class MpStrength {
  static MpStrengthResult check(String mp) {
    return checkBytes(Uint8List.fromList(mp.codeUnits));
  }

  // P0: strength check on the raw bytes so callers never materialize the master
  // password as an immutable Dart String (GC-nondeterministic, scraped by
  // infostealers). Enforced by test/app/vault_service_test.dart
  // 'exportCsv does not materialize the MP as a String'.
  static MpStrengthResult checkBytes(Uint8List mp) {
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSymbol = false;
    for (final c in mp) {
      if (c >= 0x41 && c <= 0x5A) {
        hasUpper = true;
      } else if (c >= 0x61 && c <= 0x7A) {
        hasLower = true;
      } else if (c >= 0x30 && c <= 0x39) {
        hasDigit = true;
      } else {
        hasSymbol = true;
      }
    }

    int classCount =
        [hasUpper, hasLower, hasDigit, hasSymbol].where((c) => c).length;

    // Weak: too short OR single class
    if (mp.length < 4 || classCount <= 1) {
      return MpStrengthResult(MpStrengthLevel.weak,
          'Weak password. Easily brute-forced. Use longer or more varied characters.');
    }

    // Strong: long AND multi-class
    if (mp.length >= 12 && classCount >= 3) {
      return MpStrengthResult(MpStrengthLevel.strong, 'Strong password.');
    }

    // Fair: everything in between
    return MpStrengthResult(MpStrengthLevel.fair,
        'Fair password. Consider making it longer or using more character classes.');
  }
}
