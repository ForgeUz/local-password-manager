// Intent: RFC 6238 TOTP (Time-based One-Time Password) generator.
// Produces 6 or 8 digit codes from a shared secret, synchronized
// with server time. Used for 2FA codes displayed in-app.
//
// Invariants:
// - Secret is stored as SecureBuffer (never as Dart String)
// - Code generation is deterministic: same secret + time window = same code
// - HMAC algorithm matches server expectation (SHA1 default, SHA256/512 optional)
// - Period is typically 30 seconds (configurable)
// - Codes are zero-padded to exact digit count (e.g., "042381" not "42381")
//
// State Transition:
//   SecretImported -> GeneratorInitialized -> CodeGenerated(time_window)
//   TimeWindowExpired -> NextCodeGenerated
//
// Dependencies: package:crypto (HMAC), dart:typed_data, SecureBuffer

import 'dart:typed_data';
import 'package:crypto/crypto.dart';

import '../crypto/native/secure_buffer.dart';

/// Supported HMAC algorithms for TOTP.
/// RFC 6238 allows SHA1 (default), SHA256, SHA512.
enum TotpAlgorithm {
  sha1,
  sha256,
  sha512,
}

/// Configuration for a single TOTP entry.
/// Immutable after creation — changing config requires new instance.
class TotpConfig {
  /// Human-readable issuer name (e.g., "GitHub", "Google").
  final String issuer;

  /// Account identifier (e.g., "user@example.com").
  final String accountName;

  /// Shared secret (base32-decoded). Stored in SecureBuffer for zeroing.
  final SecureBuffer secret;

  /// Number of digits in generated code (6 or 8).
  final int digits;

  /// Time step in seconds (typically 30).
  final int periodSeconds;

  /// HMAC algorithm to use.
  final TotpAlgorithm algorithm;

  const TotpConfig({
    required this.issuer,
    required this.accountName,
    required this.secret,
    this.digits = 6,
    this.periodSeconds = 30,
    this.algorithm = TotpAlgorithm.sha1,
  })  : assert(digits == 6 || digits == 8, 'Digits must be 6 or 8'),
        assert(periodSeconds > 0, 'Period must be positive');

  /// Display label for UI (e.g., "GitHub (user@example.com)").
  String get displayLabel => '$issuer ($accountName)';
}

/// RFC 6238 TOTP code generator.
/// Pure functions — no I/O, no global state.
///
/// Algorithm:
/// 1. T = floor(current_time / period)
/// 2. T_bytes = T as 8-byte big-endian
/// 3. HMAC = HMAC-SHAx(secret, T_bytes)
/// 4. offset = HMAC[19] & 0x0F
/// 5. code = (HMAC[offset..offset+3] & 0x7FFFFFFF) % 10^digits
class TotpGenerator {
  const TotpGenerator._();

  /// Generate current TOTP code for given config and timestamp.
  ///
  /// [timestamp] is Unix epoch in seconds.
  /// Returns zero-padded string of [config.digits] length.
  ///
  /// Example: secret="JBSWY3DPEHPK3PXP", time=1234567890 -> "287082"
  static String generate({
    required TotpConfig config,
    required int timestamp,
  }) {
    // Step 1: Calculate time window (counter)
    final int counter = timestamp ~/ config.periodSeconds;

    // Step 2: Encode counter as 8-byte big-endian
    final Uint8List counterBytes = _encodeCounter(counter);

    // Step 3: Compute HMAC
    final Uint8List hmacResult = _computeHmac(
      secret: config.secret.readBytes(),
      message: counterBytes,
      algorithm: config.algorithm,
    );

    // Step 4: Dynamic truncation (RFC 4226 §5.4)
    final int code = _truncate(hmacResult, config.digits);

    // Step 5: Zero-pad to exact digit count
    return code.toString().padLeft(config.digits, '0');
  }

  /// Generate code for current system time.
  /// Convenience wrapper around [generate].
  static String generateNow({required TotpConfig config}) {
    final int now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return generate(config: config, timestamp: now);
  }

  /// Seconds remaining until current code expires.
  /// Used for countdown timer in UI.
  static int secondsRemaining({
    required TotpConfig config,
    int? timestamp,
  }) {
    final int now = timestamp ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final int elapsed = now % config.periodSeconds;
    return config.periodSeconds - elapsed;
  }

  /// Generate next code (for preview in UI).
  /// Shows what code will be after current one expires.
  static String generateNext({required TotpConfig config}) {
    final int now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final int nextTimestamp = now + config.periodSeconds;
    return generate(config: config, timestamp: nextTimestamp);
  }

  /// Validate a user-entered code against expected value.
  /// Allows ±1 window for clock drift (RFC 6238 §5.2).
  ///
  /// Returns true if code matches current, previous, or next window.
  static bool validate({
    required TotpConfig config,
    required String userCode,
    int? timestamp,
  }) {
    final int now = timestamp ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;

    // Check current window and ±1 for clock drift
    for (final offset in [-1, 0, 1]) {
      final int checkTime = now + (offset * config.periodSeconds);
      final String expected = generate(config: config, timestamp: checkTime);
      if (_constantTimeEquals(userCode, expected)) {
        return true;
      }
    }
    return false;
  }

  // --- Private helpers ---

  /// Encode counter as 8-byte big-endian byte array.
  static Uint8List _encodeCounter(int counter) {
    final bytes = Uint8List(8);
    for (int i = 7; i >= 0; i--) {
      bytes[i] = counter & 0xFF;
      counter >>= 8;
    }
    return bytes;
  }

  /// Compute HMAC with specified algorithm.
  static Uint8List _computeHmac({
    required Uint8List secret,
    required Uint8List message,
    required TotpAlgorithm algorithm,
  }) {
    final Hmac hmac;
    switch (algorithm) {
      case TotpAlgorithm.sha1:
        hmac = Hmac(sha1, secret);
        break;
      case TotpAlgorithm.sha256:
        hmac = Hmac(sha256, secret);
        break;
      case TotpAlgorithm.sha512:
        hmac = Hmac(sha512, secret);
        break;
    }
    final digest = hmac.convert(message);
    return Uint8List.fromList(digest.bytes);
  }

  /// Dynamic truncation per RFC 4226 §5.4.
  /// Extracts a 4-byte dynamic binary code from HMAC result.
  static int _truncate(Uint8List hmacResult, int digits) {
    // Offset determined by low-order nibble of last byte
    final int offset = hmacResult[hmacResult.length - 1] & 0x0F;

    // Extract 4 bytes starting at offset, mask top bit
    final int binary = ((hmacResult[offset] & 0x7F) << 24) |
        ((hmacResult[offset + 1] & 0xFF) << 16) |
        ((hmacResult[offset + 2] & 0xFF) << 8) |
        (hmacResult[offset + 3] & 0xFF);

    // Modulo to get desired number of digits
    return binary % _pow10(digits);
  }

  /// 10^n helper (avoids dart:math import for simple power).
  static int _pow10(int n) {
    int result = 1;
    for (int i = 0; i < n; i++) {
      result *= 10;
    }
    return result;
  }

  /// Constant-time string comparison.
  /// Prevents timing attacks on code validation.
  static bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return result == 0;
  }
}
