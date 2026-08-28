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
//
// Normalization: lowercase, strip scheme (http://, https://, ftp://),
// strip leading "www.", strip trailing slash and path.
// TODO: Add Punycode conversion for IDN domains.
//
// SECURITY CRITICAL: SearchKey is zeroed after use in computePrefixes.
//
// Invariants: tag deterministic; prefix tags match; SearchKey never on disk.
// Dependencies: Hkdf, HmacSha256, dart:convert, dart:typed_data.

class SearchTag {
  static const String _searchKeyInfo = 'GENESIS-SEARCH-v4';

  /// Derive SearchKey from VRK using HKDF.
  ///
  /// SECURITY: Returned SearchKey MUST be zeroed by caller after use.
  static Uint8List deriveSearchKey(Uint8List vrk) {
    final salt = Uint8List(32);
    return Hkdf.derive(vrk, salt, _searchKeyInfo, V4Constants.keySize);
  }

  /// Compute tag for an arbitrary input string under the given SearchKey.
  static Uint8List tagFor(Uint8List searchKey, String input) {
    final normalized = _normalize(input);
    return HmacSha256.compute(
        searchKey, Uint8List.fromList(utf8.encode(normalized)));
  }

  /// Compute tag for a domain under a derived SearchKey.
  static Uint8List compute(Uint8List vrk, String domain) {
    final searchKey = deriveSearchKey(vrk);
    try {
      return tagFor(searchKey, domain);
    } finally {
      // CRITICAL: Zero SearchKey after use
      searchKey.fillRange(0, searchKey.length, 0);
    }
  }

  /// Returns tags for every prefix of length 3..full domain length, padded to a
  /// size bucket (4/8/16/32/64) with random tags (v5 E13).
  ///
  /// SECURITY: SearchKey is zeroed after use.
  static List<Uint8List> computePrefixes(Uint8List vrk, String domain) {
    final searchKey = deriveSearchKey(vrk);
    try {
      final normalized = _normalize(domain);
      final tags = <Uint8List>[];

      for (var len = 3; len <= normalized.length; len++) {
        final prefix = normalized.substring(0, len);
        tags.add(HmacSha256.compute(
            searchKey, Uint8List.fromList(utf8.encode(prefix))));
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
    } finally {
      // CRITICAL: Zero SearchKey after use
      searchKey.fillRange(0, searchKey.length, 0);
    }
  }

  /// Smallest bucket >= count from {4, 8, 16, 32, 64}.
  static int _bucketFor(int count) {
    for (final b in const [4, 8, 16, 32, 64]) {
      if (count <= b) return b;
    }
    return 64;
  }

  /// Normalize domain for consistent tag computation.
  /// Strips: scheme (http://, https://, ftp://), leading "www.", trailing slash/path.
  /// TODO: Add Punycode conversion for IDN domains (münchen.de -> xn--mnchen-3ya.de)
  static String _normalize(String domain) {
    var d = domain.toLowerCase().trim();

    // Strip scheme
    if (d.startsWith('https://')) {
      d = d.substring(8);
    } else if (d.startsWith('http://'))
      d = d.substring(7);
    else if (d.startsWith('ftp://')) d = d.substring(6);

    // Strip www.
    if (d.startsWith('www.')) d = d.substring(4);

    // Strip trailing slash and path
    final slashIndex = d.indexOf('/');
    if (slashIndex != -1) d = d.substring(0, slashIndex);

    // Strip trailing dots (FQDN notation)
    while (d.endsWith('.')) {
      d = d.substring(0, d.length - 1);
    }

    return d;
  }

  /// Reveal-filter (v5 E13): confirm a candidate entry actually matches the
  /// query by checking the query is a prefix of the entry's normalized domain.
  /// Padding tags can collide with a query tag -> false positive; this filters
  /// them out at reveal time (the matched entry is decrypted anyway).
  static bool matchesDomain(String domain, String query) {
    final d = _normalize(domain);
    final q = query.toLowerCase().trim();

    // SECURITY: Reject queries shorter than 3 chars to prevent excessive false positives
    if (q.length < 3) return false;

    return d.startsWith(q);
  }
}
