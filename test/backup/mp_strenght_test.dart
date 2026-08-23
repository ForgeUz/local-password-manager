import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/backup/mp_strength.dart';

void main() {
  test('Short passwords are Weak', () {
    expect(MpStrength.check('123').strength, equals(MpStrengthLevel.weak));
    expect(MpStrength.check('abc').strength, equals(MpStrengthLevel.weak));
  });

  test('Long but single-class passwords are Weak', () {
    expect(MpStrength.check('onlyletters').strength, equals(MpStrengthLevel.weak));
  });

  test('Mixed class but short passwords are Fair', () {
    expect(MpStrength.check('Aa1!').strength, equals(MpStrengthLevel.fair));
  });

  test('Long mixed class passwords are Strong', () {
    expect(MpStrength.check('Str0ng!Pass#2024').strength, equals(MpStrengthLevel.strong));
  });
}