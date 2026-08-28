import 'dart:convert';
import 'dart:typed_data';
import '../native/constant_time.dart';
import '../native/hkdf.dart';
import '../native/hmac_sha256.dart';
import 'constants.dart';

// Intent: v5 E1 — signed epoch liveness tokens (replaces the calendar hash
// chain). TokenKey = HKDF(VRK, "GENESIS-LIVENESS-v5"). Every normal unlock
// emits a token (epoch++, timestamp) signed under TokenKey. Tokens propagate
// to heir custody (paired devices or manual export). No server.
// Invariants: token deterministic for (epoch, timestamp, vrk); forged or
// newer-epoch tokens rejected; epoch strictly increments.
// State Transition: emit(epoch, ts, vrk) -> token; verify(token, vrk) ->
// (epoch, ts) | throws.
// Dependencies: Hkdf, HmacSha256, ConstantTime, dart:convert, dart:typed_data.

class LivenessToken {
  final int epoch;
  final int timestampMillis;
  final Uint8List signature;

  const LivenessToken({
    required this.epoch,
    required this.timestampMillis,
    required this.signature,
  });
}

class Liveness {
  static const String _tokenKeyInfo = 'GENESIS-LIVENESS-v5';

  // TokenKey = HKDF(VRK, "GENESIS-LIVENESS-v5").
  static Uint8List deriveTokenKey(Uint8List vrk) {
    final salt = Uint8List(32);
    return Hkdf.derive(vrk, salt, _tokenKeyInfo, V4Constants.keySize);
  }

  // Emit a signed liveness token for (epoch, timestamp) under the VRK.
  // The signature is HMAC-SHA256(TokenKey, epoch || timestamp).
  static LivenessToken emit(Uint8List vrk, int epoch, int timestampMillis) {
    final tokenKey = deriveTokenKey(vrk);
    final payload = _payload(epoch, timestampMillis);
    final sig = HmacSha256.compute(tokenKey, payload);
    return LivenessToken(
        epoch: epoch, timestampMillis: timestampMillis, signature: sig);
  }

  // Verify a token under the VRK. Returns the (epoch, timestamp) on success.
  // Throws LivenessForgeryError on a bad signature, and
  // LivenessNewerEpochError if the token's epoch is not the expected next one
  // (forged/newer token rejected).
  static (int epoch, int timestampMillis) verify(
      Uint8List vrk, LivenessToken token, int expectedEpoch) {
    final tokenKey = deriveTokenKey(vrk);
    final payload = _payload(token.epoch, token.timestampMillis);
    final sig = HmacSha256.compute(tokenKey, payload);
    if (!ConstantTime.equals(sig, token.signature)) {
      throw LivenessForgeryError();
    }
    if (token.epoch != expectedEpoch) {
      throw LivenessNewerEpochError();
    }
    return (token.epoch, token.timestampMillis);
  }

  // Serialize a token to bytes for export to heir custody.
  static Uint8List toBytes(LivenessToken token) {
    final json = jsonEncode({
      'epoch': token.epoch,
      'ts': token.timestampMillis,
      'sig': _toHex(token.signature),
    });
    return Uint8List.fromList(utf8.encode(json));
  }

  // Parse a token from bytes.
  static LivenessToken fromBytes(Uint8List bytes) {
    final m = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
    return LivenessToken(
      epoch: m['epoch'] as int,
      timestampMillis: m['ts'] as int,
      signature: _fromHex(m['sig'] as String),
    );
  }

  static Uint8List _payload(int epoch, int timestampMillis) {
    final out = Uint8List(12);
    final bd = ByteData.sublistView(out);
    bd.setUint64(0, epoch, Endian.big);
    bd.setUint32(8, timestampMillis, Endian.big);
    return out;
  }

  static String _toHex(Uint8List b) {
    return b.fold<String>(
        '', (a, x) => a + x.toRadixString(16).padLeft(2, '0'));
  }

  static Uint8List _fromHex(String hex) {
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }
}

class LivenessForgeryError implements Exception {}

class LivenessNewerEpochError implements Exception {}
