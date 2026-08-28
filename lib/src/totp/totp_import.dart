// Intent: Parse TOTP secrets from otpauth:// URIs and Google Authenticator
// export format. Supports QR code scan results and manual entry.
//
// Invariants:
// - Secret is decoded from base32 into SecureBuffer (never stored as String)
// - Invalid URIs produce typed errors (not exceptions)
// - Google Authenticator export format parsed only if it doesn't violate doctrine
//   (it's just a JSON/protobuf with base32 secrets — no cloud dependency)
// - All parsed secrets immediately wrapped in SecureBuffer
//
// State Transition:
//   RawInput(String) -> ParseAttempt -> Success(TotpConfig) | Failure(ParseError)
//   QRScanResult -> otpauth:// URI -> TotpConfig
//   GoogleAuthExport -> JSON parse -> List<TotpConfig>
//
// Dependencies: TotpConfig, TotpAlgorithm, SecureBuffer, base32 codec

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/native/secure_buffer.dart';
import 'totp_generator.dart';

/// Result of a TOTP import parse attempt.
/// Typestate: caller must handle both success and failure explicitly.
sealed class TotpImportResult {
  const TotpImportResult();
}

/// Successfully parsed one TOTP config.
final class TotpImportSuccess extends TotpImportResult {
  final TotpConfig config;
  const TotpImportSuccess(this.config);
}

/// Successfully parsed multiple TOTP configs (bulk import).
final class TotpBulkImportSuccess extends TotpImportResult {
  final List<TotpConfig> configs;
  const TotpBulkImportSuccess(this.configs);
}

/// Parse failed with specific error.
final class TotpImportError extends TotpImportResult {
  final TotpParseError error;
  const TotpImportError(this.error);
}

/// Specific parse error types.
enum TotpParseError {
  /// URI scheme is not otpauth://
  invalidScheme,

  /// URI type is not "totp" (hotp not supported yet)
  unsupportedType,

  /// Secret parameter missing or empty
  missingSecret,

  /// Secret is not valid base32
  invalidBase32,

  /// Label (issuer/account) missing
  missingLabel,

  /// Digits parameter invalid (not 6 or 8)
  invalidDigits,

  /// Period parameter invalid (not positive)
  invalidPeriod,

  /// Algorithm parameter unrecognized
  invalidAlgorithm,

  /// JSON parse failed (bulk import)
  invalidJson,

  /// Unexpected format
  unknownFormat,
}

/// Parser for otpauth:// URIs (RFC 6238 / Google Authenticator Key URI Format).
///
/// Format: otpauth://totp/ISSUER:ACCOUNT?secret=BASE32&issuer=ISSUER&digits=6&period=30&algorithm=SHA1
///
/// Example:
///   otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30
class TotpUriParser {
  const TotpUriParser._();

  /// Parse an otpauth:// URI string into TotpConfig.
  /// Returns typed result (success or specific error).
  static TotpImportResult parse(String uriString) {
    // Step 1: Validate scheme
    if (!uriString.startsWith('otpauth://')) {
      return const TotpImportError(TotpParseError.invalidScheme);
    }

    // Step 2: Parse URI components
    final Uri uri;
    try {
      uri = Uri.parse(uriString);
    } catch (_) {
      return const TotpImportError(TotpParseError.unknownFormat);
    }

    // Step 3: Validate type (only TOTP supported, not HOTP)
    final String type = uri.host; // "totp" or "hotp"
    if (type != 'totp') {
      return const TotpImportError(TotpParseError.unsupportedType);
    }

    // Step 4: Parse label (path component)
    // Format: /ISSUER:ACCOUNT or /ACCOUNT
    final String path =
        uri.path.startsWith('/') ? uri.path.substring(1) : uri.path;
    final labelParts = _parseLabel(path);
    if (labelParts == null) {
      return const TotpImportError(TotpParseError.missingLabel);
    }

    // Step 5: Parse query parameters
    final params = uri.queryParameters;

    // Secret (required)
    final String? secretB32 = params['secret'];
    if (secretB32 == null || secretB32.isEmpty) {
      return const TotpImportError(TotpParseError.missingSecret);
    }

    // Decode base32 secret into bytes -> SecureBuffer
    final Uint8List? secretBytes = _decodeBase32(secretB32.toUpperCase());
    if (secretBytes == null) {
      return const TotpImportError(TotpParseError.invalidBase32);
    }
    final SecureBuffer secret = SecureBuffer.fromList(secretBytes);

    // Issuer (optional, prefer query param over label prefix)
    final String issuer = params['issuer'] ?? labelParts.issuer;

    // Digits (optional, default 6)
    final int digits = _parseDigits(params['digits']);
    if (digits == -1) {
      return const TotpImportError(TotpParseError.invalidDigits);
    }

    // Period (optional, default 30)
    final int period = _parsePeriod(params['period']);
    if (period == -1) {
      return const TotpImportError(TotpParseError.invalidPeriod);
    }

    // Algorithm (optional, default SHA1)
    final TotpAlgorithm algorithm = _parseAlgorithm(params['algorithm']);

    // Step 6: Construct config
    final config = TotpConfig(
      issuer: issuer,
      accountName: labelParts.account,
      secret: secret,
      digits: digits,
      periodSeconds: period,
      algorithm: algorithm,
    );

    return TotpImportSuccess(config);
  }

  // --- Private helpers ---

  /// Parse label path: "ISSUER:ACCOUNT" or "ACCOUNT"
  static ({String issuer, String account})? _parseLabel(String path) {
    if (path.isEmpty) return null;

    // URL-decode the path
    final decoded = Uri.decodeComponent(path);

    if (decoded.contains(':')) {
      final parts = decoded.split(':');
      return (
        issuer: parts[0].trim(),
        account: parts.sublist(1).join(':').trim()
      );
    }
    return (issuer: '', account: decoded.trim());
  }

  /// Decode base32 string to bytes.
  /// Returns null if invalid characters found.
  static Uint8List? _decodeBase32(String input) {
    // Remove padding and whitespace
    final cleaned = input.replaceAll(RegExp(r'[=\s]'), '');

    // Base32 alphabet
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    // Validate characters
    for (final c in cleaned.split('')) {
      if (!alphabet.contains(c)) return null;
    }

    // Decode
    final List<int> bytes = [];
    int buffer = 0;
    int bitsLeft = 0;

    for (final c in cleaned.split('')) {
      final val = alphabet.indexOf(c);
      buffer = (buffer << 5) | val;
      bitsLeft += 5;

      if (bitsLeft >= 8) {
        bytes.add((buffer >> (bitsLeft - 8)) & 0xFF);
        bitsLeft -= 8;
      }
    }

    return Uint8List.fromList(bytes);
  }

  static int _parseDigits(String? value) {
    if (value == null) return 6; // default
    final n = int.tryParse(value);
    if (n == null || (n != 6 && n != 8)) return -1;
    return n;
  }

  static int _parsePeriod(String? value) {
    if (value == null) return 30; // default
    final n = int.tryParse(value);
    if (n == null || n <= 0) return -1;
    return n;
  }

  static TotpAlgorithm _parseAlgorithm(String? value) {
    if (value == null) return TotpAlgorithm.sha1; // default
    switch (value.toUpperCase()) {
      case 'SHA1':
        return TotpAlgorithm.sha1;
      case 'SHA256':
        return TotpAlgorithm.sha256;
      case 'SHA512':
        return TotpAlgorithm.sha512;
      default:
        return TotpAlgorithm.sha1; // fallback to SHA1
    }
  }
}

/// Parser for Google Authenticator export format.
/// Google Authenticator exports as a JSON array of account objects.
///
/// Doctrine check: This format contains NO cloud dependency.
/// It's a local export file with base32 secrets. Safe to support.
///
/// Format (JSON array):
/// [
///   {
///     "issuer": "GitHub",
///     "accountName": "user@example.com",
///     "secret": "JBSWY3DPEHPK3PXP",
///     "digits": 6,
///     "period": 30,
///     "algorithm": "SHA1"
///   },
///   ...
/// ]
class GoogleAuthExportParser {
  const GoogleAuthExportParser._();

  /// Parse Google Authenticator export JSON.
  /// Returns list of TotpConfig or error.
  static TotpImportResult parse(String jsonContent) {
    // Step 1: Parse JSON
    final List<dynamic> items;
    try {
      final decoded = json.decode(jsonContent);
      if (decoded is! List) {
        return const TotpImportError(TotpParseError.invalidJson);
      }
      items = decoded;
    } catch (_) {
      return const TotpImportError(TotpParseError.invalidJson);
    }

    // Step 2: Parse each item
    final List<TotpConfig> configs = [];
    for (final item in items) {
      if (item is! Map<String, dynamic>) {
        return const TotpImportError(TotpParseError.unknownFormat);
      }

      // SECURITY: Safe type extraction to prevent TypeError on malformed JSON.
      final String? issuer =
          item['issuer'] is String ? item['issuer'] as String : null;
      final String? accountName =
          item['accountName'] is String ? item['accountName'] as String : null;
      final String? secretB32 =
          item['secret'] is String ? item['secret'] as String : null;
      final int digits = item['digits'] is int ? item['digits'] as int : 6;
      final int period = item['period'] is int ? item['period'] as int : 30;
      final String algorithmStr =
          item['algorithm'] is String ? item['algorithm'] as String : 'SHA1';

      // Validate required fields
      if (accountName == null || secretB32 == null) {
        return const TotpImportError(TotpParseError.missingSecret);
      }

      // Decode secret
      final secretBytes = TotpUriParser._decodeBase32(secretB32.toUpperCase());
      if (secretBytes == null) {
        return const TotpImportError(TotpParseError.invalidBase32);
      }

      // Parse algorithm
      final TotpAlgorithm algorithm;
      switch (algorithmStr.toUpperCase()) {
        case 'SHA256':
          algorithm = TotpAlgorithm.sha256;
          break;
        case 'SHA512':
          algorithm = TotpAlgorithm.sha512;
          break;
        default:
          algorithm = TotpAlgorithm.sha1;
      }

      configs.add(TotpConfig(
        issuer: issuer ?? '',
        accountName: accountName,
        secret: SecureBuffer.fromList(secretBytes),
        digits: digits,
        periodSeconds: period,
        algorithm: algorithm,
      ));
    }

    return TotpBulkImportSuccess(configs);
  }
}
