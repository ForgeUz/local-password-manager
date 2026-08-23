import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import '../native/hkdf.dart';
import '../native/hmac_sha256.dart';
import 'constants.dart';

// Intent: Searchable symmetric encryption search tags (v4 §5.1 / §6.9).
//   SearchKey = HKDF(VRK, "GENESIS-SEARCH-v4")
//   search_tag = HMAC-SHA256(SearchKey, normalized domain)
//   prefix tags for length 3..full domain (instant prefix search)
// Normalization: lowercase, strip leading "www.", strip trailing slash, punycode.
// Invariants: tag deterministic; prefix tags match; SearchKey never on disk.
// Dependencies: Hkdf, HmacSha256, dart:convert, dart:typed_data.

class SearchTag {
  static const String _searchKeyInfo = 'GENESIS-SEARCH-v4';

  static Uint8List deriveSearchKey(Uint8List vrk) {
    final salt = Uint8List(32);
    return Hkdf.derive(vrk, salt, _searchKeyInfo, V4Constants.keySize);
  }

  // Tag for an arbitrary input string under the given SearchKey.
  static Uint8List tagFor(Uint8List searchKey, String input) {
    final normalized = _normalize(input);
    return HmacSha256.compute(searchKey, Uint8List.fromList(utf8.encode(normalized)));
  }

  static Uint8List compute(Uint8List vrk, String domain) {
    final searchKey = deriveSearchKey(vrk);
    return tagFor(searchKey, domain);
  }

  // Returns tags for every prefix of length 3..full domain length, padded to a
  // size bucket (4/8/16/32/64) with random tags (v5 E13). Padding hides domain
  // length: a file-only attacker sees only the bucket, not len-2.
  static List<Uint8List> computePrefixes(Uint8List vrk, String domain) {
    final searchKey = deriveSearchKey(vrk);
    final normalized = _normalize(domain);
    final tags = <Uint8List>[];
    for (var len = 3; len <= normalized.length; len++) {
      final prefix = normalized.substring(0, len);
      tags.add(HmacSha256.compute(searchKey, Uint8List.fromList(utf8.encode(prefix))));
    }
    // Pad to the next bucket with random tags (false-positive candidates,
    // filtered at reveal time by decrypting the matched entry).
    final bucket = _bucketFor(tags.length);
    final r = Random.secure();
    while (tags.length < bucket) {
      tags.add(Uint8List.fromList(
          List.generate(V4Constants.searchTagSize, (_) => r.nextInt(256))));
    }
    return tags;
  }

  // Smallest bucket >= count from {4, 8, 16, 32, 64}.
  static int _bucketFor(int count) {
    for (final b in const [4, 8, 16, 32, 64]) {
      if (count <= b) return b;
    }
    return 64;
  }

  static String _normalize(String domain) {
    var d = domain.toLowerCase();
    if (d.startsWith('www.')) d = d.substring(4);
    while (d.endsWith('/')) d = d.substring(0, d.length - 1);
    return d;
  }

  // Reveal-filter (v5 E13): confirm a candidate entry actually matches the
  // query by checking the query is a prefix of the entry's normalized domain.
  // Padding tags can collide with a query tag -> false positive; this filters
  // them out at reveal time (the matched entry is decrypted anyway).
  static bool matchesDomain(String domain, String query) {
    final d = _normalize(domain);
    final q = query.toLowerCase().trim();
    if (q.length < 3) return false;
    return d.startsWith(q);
  }
}