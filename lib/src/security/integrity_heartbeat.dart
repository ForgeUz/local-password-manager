import 'dart:convert';
import 'dart:typed_data';
import '../crypto/native/sha256.dart';

// Intent: Local integrity heartbeat (v3 §21.4 / Phase P). A hash-chained log:
// each session appends {t, version, binaryHash, prevHash}. prevHash is the
// SHA-256 of the previous entry. A broken chain (prevHash mismatch) is evidence
// of tampering/rollback. Detective, not preventive. Stored in app-private
// storage (the caller persists the serialized log).
// Dependencies: Sha256, dart:convert, dart:typed_data.

class HeartbeatEntry {
  final int t; // epoch millis
  final String version;
  final String binaryHash; // hex
  final String prevHash; // hex of previous entry ('' for first)
  HeartbeatEntry({
    required this.t,
    required this.version,
    required this.binaryHash,
    required this.prevHash,
  });

  Map<String, dynamic> toJson() => {
        't': t,
        'version': version,
        'binaryHash': binaryHash,
        'prevHash': prevHash,
      };

  factory HeartbeatEntry.fromJson(Map<String, dynamic> j) => HeartbeatEntry(
        t: j['t'] as int,
        version: j['version'] as String,
        binaryHash: j['binaryHash'] as String,
        prevHash: j['prevHash'] as String,
      );

  // Canonical serialization for hashing.
  String canonical() => jsonEncode(toJson());
}

class IntegrityHeartbeat {
  final List<HeartbeatEntry> _log = [];

  List<HeartbeatEntry> get log => List.unmodifiable(_log);

  // Append a session entry. prevHash = SHA256(previous entry canonical).
  void append(
      {required int t, required String version, required String binaryHash}) {
    final prev =
        _log.isEmpty ? '' : _hex(Sha256.hash(_utf8(_log.last.canonical())));
    _log.add(HeartbeatEntry(
      t: t,
      version: version,
      binaryHash: binaryHash,
      prevHash: prev,
    ));
  }

  // Verify the chain is intact. Returns true if every entry's prevHash matches
  // the SHA-256 of the previous entry. A broken chain -> false (tamper evidence).
  bool verify() {
    for (var i = 1; i < _log.length; i++) {
      final expected = _hex(Sha256.hash(_utf8(_log[i - 1].canonical())));
      if (_log[i].prevHash != expected) return false;
    }
    return true;
  }

  // v5 P.3: verify the recorded binary hash against a manifest hash file
  // (e.g. build_hash.txt emitted by build_linux.sh). Pure Dart: reads the
  // manifest, compares to the latest heartbeat entry's binaryHash. A mismatch
  // -> the running binary does not match the published build (advisory).
  bool verifyBinaryHash(String manifestHashHex) {
    if (_log.isEmpty) return false;
    final recorded = _log.last.binaryHash;
    return recorded.toLowerCase() == manifestHashHex.trim().toLowerCase();
  }

  // Serialize the whole log for app-private storage.
  String serialize() => jsonEncode(_log.map((e) => e.toJson()).toList());

  void load(String json) {
    _log.clear();
    final list = jsonDecode(json) as List;
    _log.addAll(
        list.map((e) => HeartbeatEntry.fromJson(e as Map<String, dynamic>)));
  }

  static Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));
  static String _hex(Uint8List b) =>
      b.fold<String>('', (a, x) => a + x.toRadixString(16).padLeft(2, '0'));
}
