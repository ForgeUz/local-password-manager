import 'lookalike_domain.dart';

// Intent: v5 I.7 — autofill preview + capability sharing. Before filling a
// credential into a target domain, verify the target matches the entry's
// domain (exact or subdomain) AND is not a look-alike of a DIFFERENT saved
// domain (hard-stop). Returns a preview decision: fill, warn (lookalike), or
// block (no match). Capability sharing is scoped: only the matched entry's
// credential is offered.
// Invariants: exact/suffix match -> fill; lookalike of another saved domain ->
// hard-stop warn; no match -> block.
// Dependencies: LookalikeDomain.

enum AutofillDecision { fill, warn, block }

class AutofillPreview {
  // Decide whether to autofill the entry's credential into the target domain.
  //   entryDomain: the domain the credential belongs to.
  //   targetDomain: the domain the user is filling into.
  //   savedDomains: all other saved entry domains (for lookalike detection).
  static AutofillDecision decide({
    required String entryDomain,
    required String targetDomain,
    required List<String> savedDomains,
  }) {
    final e = entryDomain.toLowerCase();
    final t = targetDomain.toLowerCase();

    // Hard-stop: if the target is a lookalike of a DIFFERENT saved domain,
    // warn regardless of whether it matches the entry (phishing defense).
    final lookalike = LookalikeDomain.detect(
      targetDomain: t,
      savedDomains: savedDomains.where((d) => d.toLowerCase() != e).toList(),
    );
    if (lookalike != null) return AutofillDecision.warn;

    // Exact or suffix match (target is the entry domain or a subdomain).
    if (t == e || t.endsWith('.$e')) {
      return AutofillDecision.fill;
    }

    // No match -> block (never autofill into an unrelated domain).
    return AutofillDecision.block;
  }
}