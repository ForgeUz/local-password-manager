import 'dart:typed_data';
import 'package:test/test.dart';

import '../../lib/src/totp/totp_generator.dart';
import '../../lib/src/crypto/native/secure_buffer.dart';

void main() {
  group('RFC 6238 Compliance', () {
    // RFC 6238 Appendix B: different secret lengths per algorithm
    // SHA1: 20 bytes, SHA256: 32 bytes, SHA512: 64 bytes
    
    test('SHA1 at T=59 -> 287082 (6 digits)', () {
      final secret = SecureBuffer.fromList(
        Uint8List.fromList('12345678901234567890'.codeUnits)
      );
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test',
        secret: secret,
        digits: 6,
        algorithm: TotpAlgorithm.sha1,
      );
      final code = TotpGenerator.generate(config: config, timestamp: 59);
      expect(code, equals('287082'));
    });

    test('SHA256 at T=59 -> 46119246 (8 digits, 32-byte secret)', () {
      final secret = SecureBuffer.fromList(
        Uint8List.fromList('12345678901234567890123456789012'.codeUnits)
      );
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test',
        secret: secret,
        digits: 8,
        algorithm: TotpAlgorithm.sha256,
      );
      final code = TotpGenerator.generate(config: config, timestamp: 59);
      expect(code, equals('46119246'));
    });

    test('SHA512 at T=59 -> 90693936 (8 digits, 64-byte secret)', () {
      final secret = SecureBuffer.fromList(
        Uint8List.fromList(
          '1234567890123456789012345678901234567890123456789012345678901234'.codeUnits
        )
      );
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test',
        secret: secret,
        digits: 8,
        algorithm: TotpAlgorithm.sha512,
      );
      final code = TotpGenerator.generate(config: config, timestamp: 59);
      expect(code, equals('90693936'));
    });
  });

  group('Determinism', () {
    test('same secret + time always produces same code', () {
      final secret = SecureBuffer.fromList(
        Uint8List.fromList('test12345678901234'.codeUnits)
      );
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test',
        secret: secret,
      );
      final code1 = TotpGenerator.generate(config: config, timestamp: 1000000);
      final code2 = TotpGenerator.generate(config: config, timestamp: 1000000);
      expect(code1, equals(code2));
    });
  });

  group('Period Boundary', () {
    test('code changes at period boundary', () {
      final secret = SecureBuffer.fromList(
        Uint8List.fromList('test12345678901234'.codeUnits)
      );
      final config = TotpConfig(
        issuer: 'Test',
        accountName: 'test',
        secret: secret,
        periodSeconds: 30,
      );
      final code1 = TotpGenerator.generate(config: config, timestamp: 29);
      final code2 = TotpGenerator.generate(config: config, timestamp: 30);
      expect(code1, isNot(equals(code2)));
    });
  });
}
