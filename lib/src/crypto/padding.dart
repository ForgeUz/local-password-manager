import 'dart:math';
import 'dart:typed_data';
import 'errors.dart';

// Intent: Size-bucket padding to mask entry count via ciphertext length.
//
// SECURITY CRITICAL: All parsing errors throw CorruptBlobError (not FormatException)
// to prevent error oracle attacks.
//
// Dependencies: dart:math, dart:typed_data, errors.dart.

class Padding {
  static const List<int> _buckets = [
    4096,
    16384,
    65536,
    262144,
    1048576,
    4194304
  ];

  /// Select the smallest bucket size >= (length + 4 bytes for length prefix).
  static int pickBucket(int length) {
    final required = length + 4;
    if (required <= _buckets.first) return _buckets.first;

    for (var b in _buckets) {
      if (required <= b) return b;
    }

    // For very large data, round up to next 4 MiB boundary
    final mult = 4194304;
    final rem = required % mult;
    return rem == 0 ? required : required + (mult - rem);
  }

  /// Pad data to bucket size with random bytes.
  /// Format: [length(4 bytes, big-endian)][data][random padding]
  static Uint8List pad(Uint8List data, int bucketSize) {
    final result = Uint8List(bucketSize);
    final random = Random.secure();

    // Store original length in first 4 bytes (big-endian)
    result[0] = (data.length >> 24) & 0xFF;
    result[1] = (data.length >> 16) & 0xFF;
    result[2] = (data.length >> 8) & 0xFF;
    result[3] = data.length & 0xFF;

    // Copy data
    result.setRange(4, 4 + data.length, data);

    // Fill remainder with random bytes (CSPRNG)
    final padLen = bucketSize - 4 - data.length;
    final randBytes =
        Uint8List.fromList(List.generate(padLen, (_) => random.nextInt(256)));
    result.setRange(4 + data.length, bucketSize, randBytes);

    return result;
  }

  /// Unpad data, extracting original length from first 4 bytes.
  ///
  /// SECURITY: Throws CorruptBlobError on any parsing error (not FormatException)
  /// to prevent error oracle attacks.
  static Uint8List unpad(Uint8List padded) {
    try {
      if (padded.length < 4) throw StateError('Invalid padded length');

      final length =
          (padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3];

      // SECURITY: Validate extracted length
      if (length < 0 || length > padded.length - 4) {
        throw StateError('Invalid embedded length');
      }

      return padded.sublist(4, 4 + length);
    } catch (_) {
      // SECURITY: All errors become CorruptBlobError to prevent oracle
      throw CorruptBlobError();
    }
  }
}
