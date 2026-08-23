// Intent: Heuristic check for Master Password strength. Warn-only.
class MpStrengthResult {
  final MpStrengthLevel strength;
  final String warning;

  MpStrengthResult(this.strength, this.warning);
}

enum MpStrengthLevel { weak, fair, strong }

class MpStrength {
  static MpStrengthResult check(String mp) {
    bool hasUpper = mp.contains(RegExp(r'[A-Z]'));
    bool hasLower = mp.contains(RegExp(r'[a-z]'));
    bool hasDigit = mp.contains(RegExp(r'[0-9]'));
    bool hasSymbol = mp.contains(RegExp(r'[^a-zA-Z0-9]'));
    
    int classCount = [hasUpper, hasLower, hasDigit, hasSymbol].where((c) => c).length;
    
    // Weak: too short OR single class
    if (mp.length < 4 || classCount <= 1) {
      return MpStrengthResult(
        MpStrengthLevel.weak, 
        'Weak password. Easily brute-forced. Use longer or more varied characters.'
      );
    }
    
    // Strong: long AND multi-class
    if (mp.length >= 12 && classCount >= 3) {
      return MpStrengthResult(
        MpStrengthLevel.strong, 
        'Strong password.'
      );
    }
    
    // Fair: everything in between
    return MpStrengthResult(
      MpStrengthLevel.fair, 
      'Fair password. Consider making it longer or using more character classes.'
    );
  }
}