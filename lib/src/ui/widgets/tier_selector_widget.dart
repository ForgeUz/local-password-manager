// Intent: Flutter widget for selecting security tier per entry.
// User manually assigns tier (per user decision). Shows color-coded
// options with descriptions of what each tier enforces.
//
// Invariants:
// - Always shows all 3 tiers (no hidden options)
// - Downgrade requires explicit confirmation dialog
// - Suggested tier shown as hint (advisory only, never auto-applied)
// - Widget is stateless — state managed by Riverpod provider
//
// State Transition:
//   EntryEditorOpened -> TierSelectorRendered(currentTier)
//   UserTapsTier -> validation -> if upgrade: apply immediately
//   UserTapsTier -> validation -> if downgrade: show confirmation
//   ConfirmationAccepted -> tier applied -> entry re-encrypted
//
// Dependencies: Flutter, Riverpod, SecurityTier, TierUiHelper, TierValidator

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../security/security_tier.dart';
import '../../security/security_tier_ui_helper.dart';

/// Provider for currently selected tier in entry editor.
/// Scoped to entry editor lifecycle (disposed when editor closes).
final selectedTierProvider = StateProvider<SecurityTier>((ref) {
  return SecurityTier.standard; // Default, overridden by entry data
});

/// Provider for suggested tier based on domain (advisory only).
final suggestedTierProvider = Provider<SecurityTier?>((ref) {
  // This would be set by the entry editor when domain is known
  return null;
});

/// Tier selector widget for entry editor.
/// Displays 3 options with color coding and descriptions.
/// Handles downgrade confirmation internally.
class TierSelectorWidget extends ConsumerWidget {
  /// Current tier of the entry being edited.
  final SecurityTier currentTier;

  /// Callback when tier is changed (after validation).
  final ValueChanged<SecurityTier> onTierChanged;

  /// Domain of the entry (for suggestion).
  final String? domain;

  const TierSelectorWidget({
    super.key,
    required this.currentTier,
    required this.onTierChanged,
    this.domain,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Get suggestion if domain provided
    final suggestion =
        domain != null ? TierUiHelper.suggestTierForDomain(domain!) : null;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Section header
        const Text(
          'Security Level',
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),

        // Advisory suggestion (if applicable)
        if (suggestion != null && suggestion != currentTier)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              children: [
                Icon(Icons.lightbulb_outline,
                    size: 16, color: Colors.amber[700]),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    'Suggested: ${TierUiHelper.getUiInfo(suggestion).labelKey} '
                    '(based on domain)',
                    style: TextStyle(
                      fontSize: 12,
                      color: Colors.amber[700],
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ),
              ],
            ),
          ),

        // Tier options
        ...SecurityTier.values.map((tier) => _TierOption(
              tier: tier,
              isSelected: tier == currentTier,
              onTap: () => _handleTierTap(context, tier),
            )),
      ],
    );
  }

  /// Handle tier selection tap.
  /// Upgrades apply immediately. Downgrades require confirmation.
  void _handleTierTap(BuildContext context, SecurityTier newTier) {
    if (newTier == currentTier) return; // No change

    final validation = TierValidator.validateChange(
      current: currentTier,
      proposed: newTier,
    );

    switch (validation) {
      case TierValid(:final tier):
        // Upgrade or same level — apply immediately
        onTierChanged(tier);

      case TierDowngradeConfirm(:final from, :final to, :final warning):
        // Downgrade — show confirmation dialog
        _showDowngradeConfirmation(context, from, to, warning);
    }
  }

  /// Show confirmation dialog for tier downgrade.
  void _showDowngradeConfirmation(
    BuildContext context,
    SecurityTier from,
    SecurityTier to,
    String warning,
  ) {
    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Downgrade Security Level?'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(warning),
            const SizedBox(height: 16),
            Text(
              'Changing from ${from.name.toUpperCase()} to ${to.name.toUpperCase()}',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Colors.red[700],
            ),
            onPressed: () {
              Navigator.of(dialogContext).pop();
              onTierChanged(to);
            },
            child: const Text('Downgrade'),
          ),
        ],
      ),
    );
  }
}

/// Single tier option row.
class _TierOption extends StatelessWidget {
  final SecurityTier tier;
  final bool isSelected;
  final VoidCallback onTap;

  const _TierOption({
    required this.tier,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final uiInfo = TierUiHelper.getUiInfo(tier);
    final color = Color(
        int.parse(uiInfo.colorHex.substring(1, 7), radix: 16) + 0xFF000000);
    final actions = TierUiHelper.getActionDescriptions(tier);

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          border: Border.all(
            color: isSelected ? color : Colors.grey[300]!,
            width: isSelected ? 2 : 1,
          ),
          borderRadius: BorderRadius.circular(8),
          color: isSelected ? color.withValues(alpha: 0.05) : null,
        ),
        child: Row(
          children: [
            // Color indicator
            Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
              ),
            ),
            const SizedBox(width: 12),

            // Label + description
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    _tierLabel(tier),
                    style: TextStyle(
                      fontWeight: FontWeight.w600,
                      color: isSelected ? color : null,
                    ),
                  ),
                  const SizedBox(height: 4),
                  // Show key enforcement rules
                  ...actions.take(2).map((a) => Text(
                        '• $a',
                        style: TextStyle(
                          fontSize: 12,
                          color: Colors.grey[600],
                        ),
                      )),
                ],
              ),
            ),

            // Selection indicator
            if (isSelected) Icon(Icons.check_circle, color: color, size: 20),
          ],
        ),
      ),
    );
  }

  String _tierLabel(SecurityTier tier) {
    switch (tier) {
      case SecurityTier.standard:
        return 'Standard';
      case SecurityTier.sensitive:
        return 'Sensitive';
      case SecurityTier.critical:
        return 'Critical';
    }
  }
}
