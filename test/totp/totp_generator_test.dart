// File: test/totp/totp_generator_test.dart
// Intent: Kill-tests for TotpGenerator (M115-M120).
// Invariants:
// - RFC 6238 test vectors produce exact codes.
// - Zero-padding enforced.
// - +/-1 window validation.
// - Constant-time compare.
// - Big-endian counter encoding.
// Dependencies: totp_generator.dart, secure_buffer.dart, package:crypto.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/totp/totp_generator.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

// RFC 6238 Appendix B test secret: "12345678901234567890" (ASCII).
final Uint8List _rfcSecret =
    Uint8List.fromList(utf8.encode('12345678901234567890'));

TotpConfig _makeConfig({
  TotpAlgorithm algo = TotpAlgorithm.sha1,
  int digits = 6,
  int period = 30,
}) {
  return TotpConfig(
    issuer: 'Test',
    accountName: 'test@test.com',
    secret: SecureBuffer.fromList(_rfcSecret),
    digits: digits,
    periodSeconds: period,
    algorithm: algo,
  );
}

void main() {
  group('M115 + M119 + M120: RFC 6238 test vectors (SHA1, 6 digits)', () {
    // RFC 6238 Appendix B: SHA1 test vectors.
    // Time (sec) | TOTP (6 digits)
    final vectors = <int, String>{
      59: '287082',
      1111111109: '081804',
      1111111111: '050471',
      1234567890: '005924',
      2000000000: '279037',
      20000000000: '353130',
    };

    for (final entry in vectors.entries) {
      test('time=${entry.key} -> ${entry.value}', () {
        final config = _makeConfig();
        final code = TotpGenerator.generate(
          config: config,
          timestamp: entry.key,
        );
        expect(code, equals(entry.value));
      });
    }
  });

  group('M115: dynamic truncation offset varies', () {
    // If offset is fixed at 0, different time windows would produce
    // wrong codes. The RFC vectors above already cover this, but
    // we add a cross-check: two different times -> different codes.
    test('different times -> different codes', () {
      final config = _makeConfig();
      final code1 = TotpGenerator.generate(config: config, timestamp: 59);
      final code2 =
          TotpGenerator.generate(config: config, timestamp: 1111111109);
      expect(code1, isNot(equals(code2)));
    });
  });

  group('M116: zero-padding enforced', () {
    test('code with leading zero has correct length', () {
      final config = _makeConfig();
      // time=1111111109 -> "081804" (starts with 0)
      final code = TotpGenerator.generate(
        config: config,
        timestamp: 1111111109,
      );
      expect(code.length, equals(6));
      expect(code, equals('081804'));
    });

    test('8-digit code has correct length', () {
      final config = _makeConfig(digits: 8);
      final code = TotpGenerator.generate(config: config, timestamp: 59);
      expect(code.length, equals(8));
    });
  });

  group('M117: validate allows +/-1 window', () {
    test('current window code validates', () {
      final config = _makeConfig();
      final code = TotpGenerator.generate(config: config, timestamp: 59);
      expect(
        TotpGenerator.validate(
          config: config,
          userCode: code,
          timestamp: 59,
        ),
        isTrue,
      );
    });

    test('previous window code validates (clock drift)', () {
      final config = _makeConfig();
      // Generate code for window BEFORE current.
      final prevCode = TotpGenerator.generate(config: config, timestamp: 29);
      // Validate at time=59 (current window). Previous window = 29.
      expect(
        TotpGenerator.validate(
          config: config,
          userCode: prevCode,
          timestamp: 59,
        ),
        isTrue,
      );
    });

    test('next window code validates (clock drift)', () {
      final config = _makeConfig();
      // Generate code for window AFTER current.
      final nextCode = TotpGenerator.generate(config: config, timestamp: 89);
      expect(
        TotpGenerator.validate(
          config: config,
          userCode: nextCode,
          timestamp: 59,
        ),
        isTrue,
      );
    });

    test('code 2 windows away -> rejected', () {
      final config = _makeConfig();
      final farCode = TotpGenerator.generate(config: config, timestamp: 119);
      expect(
        TotpGenerator.validate(
          config: config,
          userCode: farCode,
          timestamp: 59,
        ),
        isFalse,
      );
    });
  });

  group('M118: constant-time compare (behavioral)', () {
    // Cannot directly test timing, but verify wrong code rejected.
    test('wrong code -> false', () {
      final config = _makeConfig();
      expect(
        TotpGenerator.validate(
          config: config,
          userCode: '000000',
          timestamp: 59,
        ),
        isFalse,
      );
    });

    test('empty code -> false', () {
      final config = _makeConfig();
      expect(
        TotpGenerator.validate(
          config: config,
          userCode: '',
          timestamp: 59,
        ),
        isFalse,
      );
    });
  });

  group('M119: big-endian counter encoding', () {
    // If counter were little-endian, RFC vectors would fail.
    // Covered by RFC vector tests above. Additional: verify counter
    // encoding for a known boundary.
    test('time=0 produces valid 6-digit code', () {
      final config = _makeConfig();
      final code = TotpGenerator.generate(config: config, timestamp: 0);
      expect(code.length, equals(6));
      // time=0, SHA1, secret="12345678901234567890" -> known vector: 755224
      expect(code, equals('755224'));
    });
  });

  group('M120: modulo 10^digits bounds', () {
    test('6-digit code in range [000000, 999999]', () {
      final config = _makeConfig();
      for (final t in [0, 59, 1000, 999999999, 2000000000]) {
        final code = TotpGenerator.generate(config: config, timestamp: t);
        final value = int.parse(code);
        expect(value, lessThan(1000000));
        expect(value, greaterThanOrEqualTo(0));
      }
    });

    test('8-digit code in range [00000000, 99999999]', () {
      final config = _makeConfig(digits: 8);
      for (final t in [0, 59, 1000, 999999999]) {
        final code = TotpGenerator.generate(config: config, timestamp: t);
        final value = int.parse(code);
        expect(value, lessThan(100000000));
      }
    });
  });

  test('SHA256 produces correct 8-digit code (RFC 6238)', () {
    // RFC 6238 requires 32-byte secret for SHA256
    final secret256 =
        Uint8List.fromList(utf8.encode('12345678901234567890123456789012'));
    final config = TotpConfig(
      issuer: 'Test',
      accountName: 'test',
      secret: SecureBuffer.fromList(secret256),
      digits: 8,
      algorithm: TotpAlgorithm.sha256,
    );
    final code = TotpGenerator.generate(config: config, timestamp: 59);
    expect(code, equals('46119246'));
  });

  test('SHA512 produces correct 8-digit code (RFC 6238)', () {
    // RFC 6238 requires 64-byte secret for SHA512
    final secret512 = Uint8List.fromList(utf8.encode(
        '1234567890123456789012345678901234567890123456789012345678901234'));
    final config = TotpConfig(
      issuer: 'Test',
      accountName: 'test',
      secret: SecureBuffer.fromList(secret512),
      digits: 8,
      algorithm: TotpAlgorithm.sha512,
    );
    final code = TotpGenerator.generate(config: config, timestamp: 59);
    expect(code, equals('90693936'));
  });

  group('secondsRemaining', () {
    test('at window start -> full period remaining', () {
      final config = _makeConfig(period: 30);
      final remaining = TotpGenerator.secondsRemaining(
        config: config,
        timestamp: 0,
      );
      expect(remaining, equals(30));
    });

    test('mid-window -> partial remaining', () {
      final config = _makeConfig(period: 30);
      final remaining = TotpGenerator.secondsRemaining(
        config: config,
        timestamp: 10,
      );
      expect(remaining, equals(20));
    });
  });
}
