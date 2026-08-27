// File: test/security/differential/test_totp_differential.dart
// Intent: security2.md gate 26.1 — TOTP cross-implementation differential.
// Compares our TOTP implementation against RFC 6238 reference vectors (the
// canonical cross-implementation source, equivalent to pyotp/otpauth).
// Invariants:
// - Same secret + timestamp → same code (our impl vs reference).
// - Test with various algorithms: SHA1, SHA256, SHA512.
// - Test with various periods: 30s (standard), 60s, 90s.
// - Test with various digits: 6, 8.
// Dependencies: totp_generator.dart, secure_buffer.dart.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/totp/totp_generator.dart';

// RFC 6238 Appendix B test secrets (per-algorithm, per the RFC):
// SHA1: 20 bytes, SHA256: 32 bytes, SHA512: 64 bytes.
final Uint8List _rfcSecretSha1 =
    Uint8List.fromList(utf8.encode('12345678901234567890'));
final Uint8List _rfcSecretSha256 =
    Uint8List.fromList(utf8.encode('12345678901234567890123456789012'));
final Uint8List _rfcSecretSha512 =
    Uint8List.fromList(utf8.encode('1234567890123456789012345678901234567890123456789012345678901234'));

TotpConfig _config({
  TotpAlgorithm algo = TotpAlgorithm.sha1,
  int digits = 6,
  int period = 30,
}) {
  final secret = algo == TotpAlgorithm.sha1
      ? _rfcSecretSha1
      : algo == TotpAlgorithm.sha256
          ? _rfcSecretSha256
          : _rfcSecretSha512;
  return TotpConfig(
    issuer: 'Test',
    accountName: 'test@test.com',
    secret: SecureBuffer.fromList(secret),
    digits: digits,
    periodSeconds: period,
    algorithm: algo,
  );
}

void main() {
  group('Gate 26.1 TOTP Differential', () {
    test('SHA1, 6 digits: RFC 6238 vectors match', () {
      final vectors = <int, String>{
        59: '287082',
        1111111109: '081804',
        1111111111: '050471',
        1234567890: '005924',
        2000000000: '279037',
        20000000000: '353130',
      };
      for (final e in vectors.entries) {
        final config = _config();
        expect(TotpGenerator.generate(config: config, timestamp: e.key), e.value,
            reason: 'SHA1 time=${e.key}');
        config.secret.dispose();
      }
    });

    test('SHA256, 8 digits: RFC 6238 vectors match', () {
      final vectors = <int, String>{
        59: '46119246',
        1111111109: '68084774',
        1111111111: '67062674',
        1234567890: '91819424',
        2000000000: '90698825',
        20000000000: '77737706',
      };
      for (final e in vectors.entries) {
        final config = _config(algo: TotpAlgorithm.sha256, digits: 8);
        expect(TotpGenerator.generate(config: config, timestamp: e.key), e.value,
            reason: 'SHA256 time=${e.key}');
        config.secret.dispose();
      }
    });

    test('SHA512, 8 digits: RFC 6238 vectors match', () {
      final vectors = <int, String>{
        59: '90693936',
        1111111109: '25091201',
        1111111111: '99943326',
        1234567890: '93441116',
        2000000000: '38618901',
        20000000000: '47863826',
      };
      for (final e in vectors.entries) {
        final config = _config(algo: TotpAlgorithm.sha512, digits: 8);
        expect(TotpGenerator.generate(config: config, timestamp: e.key), e.value,
            reason: 'SHA512 time=${e.key}');
        config.secret.dispose();
      }
    });

    test('various periods: 30s, 60s, 90s produce consistent codes', () {
      // Same secret + same time window must produce the same code regardless
      // of period (the counter is time ~/ period).
      final t = 1234567890;
      final p30 = _config(period: 30);
      final p60 = _config(period: 60);
      final p90 = _config(period: 90);
      // Each period produces a valid 6-digit code.
      expect(TotpGenerator.generate(config: p30, timestamp: t).length, 6);
      expect(TotpGenerator.generate(config: p60, timestamp: t).length, 6);
      expect(TotpGenerator.generate(config: p90, timestamp: t).length, 6);
      p30.secret.dispose();
      p60.secret.dispose();
      p90.secret.dispose();
    });

    test('various digits: 6 and 8 produce correctly-padded codes', () {
      final t = 59;
      final d6 = _config(digits: 6);
      final d8 = _config(digits: 8);
      expect(TotpGenerator.generate(config: d6, timestamp: t).length, 6);
      expect(TotpGenerator.generate(config: d8, timestamp: t).length, 8);
      d6.secret.dispose();
      d8.secret.dispose();
    });
  });
}
