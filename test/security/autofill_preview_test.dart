import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/security/autofill_preview.dart';

// Intent: v5 I.7 — autofill preview + capability sharing. Exact/suffix match ->
// fill; lookalike of another saved domain -> hard-stop warn; no match -> block.
void main() {
  group('v5 I.7 autofill preview', () {
    test('exact domain match -> fill', () {
      final d = AutofillPreview.decide(
        entryDomain: 'bank.com',
        targetDomain: 'bank.com',
        savedDomains: ['news.com'],
      );
      expect(d, AutofillDecision.fill);
    });

    test('subdomain of the entry domain -> fill', () {
      final d = AutofillPreview.decide(
        entryDomain: 'bank.com',
        targetDomain: 'login.bank.com',
        savedDomains: ['news.com'],
      );
      expect(d, AutofillDecision.fill);
    });

    test('lookalike of a DIFFERENT saved domain -> hard-stop warn', () {
      // target "bankc.com" is edit-distance-1 from saved "bank.com" (different
      // from the entry domain "news.com") -> warn.
      final d = AutofillPreview.decide(
        entryDomain: 'news.com',
        targetDomain: 'bankc.com',
        savedDomains: ['bank.com'],
      );
      expect(d, AutofillDecision.warn);
    });

    test('unrelated domain -> block (never autofill)', () {
      final d = AutofillPreview.decide(
        entryDomain: 'bank.com',
        targetDomain: 'evil.com',
        savedDomains: ['news.com'],
      );
      expect(d, AutofillDecision.block);
    });
  });
}
