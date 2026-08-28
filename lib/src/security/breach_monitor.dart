import 'dart:convert';
import 'dart:typed_data';
import '../crypto/native/sha1.dart';

// Intent: Breach monitoring (v3 §18 / Phase K.2, v5 E8 HIBP SHA-1). Only the
// 5-char SHA-1 prefix of a password hash is ever exposed (sent to a remote
// corpus or looked up offline) — never the full hash. HIBP Pwned Passwords keys
// on SHA-1 prefixes; SHA-1 is an interop identifier, never for storage.
// Opt-in, off by default.
// Invariants: prefix is exactly 5 hex chars; full hash never returned.
// Dependencies: Sha1 (interop-only), dart:convert, dart:typed_data.

class BreachResult {
  final bool breached;
  final String prefix; // 5-char k-anonymity prefix
  final String? fullHash; // always null — never exposed

  const BreachResult(
      {required this.breached, required this.prefix, this.fullHash});
}

class BreachMonitor {
  final Set<String> _corpus; // 5-char prefixes of known-breached hashes

  BreachMonitor({Set<String> corpus = const {}}) : _corpus = corpus;

  // Compute the 5-char k-anonymity prefix of a password's SHA-1 hash.
  static String prefixOf(String password) {
    final hash = _hex(Sha1.hash(_utf8(password)));
    return hash.substring(0, 5);
  }

  // Check a password against the corpus using only its 5-char prefix.
  BreachResult check(String password) {
    final prefix = prefixOf(password);
    return BreachResult(
      breached: _corpus.contains(prefix),
      prefix: prefix,
      // fullHash deliberately omitted — k-anonymity invariant.
    );
  }

  static Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

  static String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
