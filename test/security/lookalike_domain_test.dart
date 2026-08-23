import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/lookalike_domain.dart';

// Intent: Verify look-alike domain detection (Phase I.5).
// Invariants: edit-distance within threshold -> hard-stop; exact match -> no
// warning; homoglyph -> warning.
void main() {
  group('LookalikeDomain', () {
    test('edit-distance within threshold -> warning', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'paypa1.com',
        savedDomains: ['paypal.com'],
      );
      expect(r, isNotNull);
      expect(r!.savedDomain, 'paypal.com');
    });

    test('exact match -> no warning', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'paypal.com',
        savedDomains: ['paypal.com'],
      );
      expect(r, isNull);
    });

    test('homoglyph (0 vs o) -> warning', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'g00gle.com',
        savedDomains: ['google.com'],
      );
      expect(r, isNotNull);
    });

    test('unrelated domain -> no warning', () {
      final r = LookalikeDomain.detect(
        targetDomain: 'news.example.com',
        savedDomains: ['paypal.com'],
      );
      expect(r, isNull);
    });
  });
}