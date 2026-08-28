// Intent: Display TOTP code with countdown timer, copy button,
// and next-code preview. Respects security tier for auto-copy.
//
// Invariants:
// - Code updates exactly when period boundary crossed (not on every frame)
// - Countdown timer is circular progress (visual urgency)
// - Copy to clipboard auto-clears after 30 seconds
// - Critical tier: no auto-copy, user must tap explicitly
// - Widget handles time drift gracefully (±1 window)
//
// State Transition:
//   EntryDetailViewed -> TotpWidgetMounted -> CodeDisplayed(current)
//   PeriodBoundaryCrossed -> CodeRegenerated -> CodeUpdated
//   UserTapsCopy -> ClipboardWrite -> AutoClearScheduled(30s)
//
// Dependencies: TotpGenerator, TotpConfig, SecurityTier, Flutter Clipboard

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../totp/totp_generator.dart';
import '../../security/security_tier.dart';

/// TOTP code display widget with countdown and copy functionality.
/// Self-managing timer — starts on mount, cancels on dispose.
class TotpDisplayWidget extends StatefulWidget {
  /// TOTP configuration for this entry.
  final TotpConfig config;

  /// Security tier of the entry (affects auto-copy behavior).
  final SecurityTier tier;

  const TotpDisplayWidget({
    super.key,
    required this.config,
    required this.tier,
  });

  @override
  State<TotpDisplayWidget> createState() => _TotpDisplayWidgetState();
}

class _TotpDisplayWidgetState extends State<TotpDisplayWidget>
    with SingleTickerProviderStateMixin {
  /// Current TOTP code displayed.
  String _currentCode = '';

  /// Next code (preview for user).
  String _nextCode = '';

  /// Seconds remaining in current period.
  int _secondsRemaining = 0;

  /// Timer for periodic updates.
  Timer? _timer;

  /// Animation controller for circular progress.
  late AnimationController _progressController;

  /// Whether code was just copied (for visual feedback).
  bool _justCopied = false;

  @override
  void initState() {
    super.initState();
    _progressController = AnimationController(
      vsync: this,
      duration: Duration(seconds: widget.config.periodSeconds),
    );
    _generateCodes();
    _startTimer();
  }

  @override
  void didUpdateWidget(TotpDisplayWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    // If config changed, regenerate
    if (oldWidget.config != widget.config) {
      _generateCodes();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _progressController.dispose();
    super.dispose();
  }

  void _generateCodes() {
    setState(() {
      _currentCode = TotpGenerator.generateNow(config: widget.config);
      _nextCode = TotpGenerator.generateNext(config: widget.config);
      _secondsRemaining = TotpGenerator.secondsRemaining(config: widget.config);
    });
    // Reset progress animation
    _progressController.reset();
    _progressController.forward();
  }

  void _startTimer() {
    // Update every second for countdown display
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      final remaining = TotpGenerator.secondsRemaining(config: widget.config);

      if (remaining != _secondsRemaining) {
        setState(() {
          _secondsRemaining = remaining;
        });
      }

      // When period expires, regenerate codes
      if (remaining == widget.config.periodSeconds) {
        // Just wrapped around — new period started
        _generateCodes();
      }
    });
  }

  Future<void> _copyToClipboard() async {
    // Critical tier: no auto-copy (already enforced by UI placement)
    // But still check tier policy
    if (!TierPolicy.allowsAutoCopyTotp(widget.tier)) {
      // For critical: show confirmation before copy
      final confirmed = await _showCopyConfirmation();
      if (!confirmed) return;
    }

    await Clipboard.setData(ClipboardData(text: _currentCode));

    // Visual feedback
    setState(() => _justCopied = true);

    // Auto-clear clipboard after 30 seconds
    // (doctrine: minimize secret exposure time)
    Future.delayed(const Duration(seconds: 30), () async {
      // Only clear if our code is still there
      final data = await Clipboard.getData(Clipboard.kTextPlain);
      if (data?.text == _currentCode) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });

    // Reset visual feedback after 2 seconds
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) {
        setState(() => _justCopied = false);
      }
    });
  }

  Future<bool> _showCopyConfirmation() async {
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Copy Critical TOTP Code?'),
        content: const Text(
          'This entry is marked CRITICAL. Copying the code to clipboard '
          'temporarily exposes it. The clipboard will auto-clear after 30 seconds.\n\n'
          'Proceed?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Copy'),
          ),
        ],
      ),
    );
    return result ?? false;
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header: issuer + account
          Row(
            children: [
              Icon(Icons.security,
                  size: 18, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  widget.config.displayLabel,
                  style: TextStyle(
                    fontSize: 13,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),

          // Code display + countdown
          Row(
            children: [
              // Current code (large, monospace)
              Expanded(
                child: GestureDetector(
                  onTap: _copyToClipboard,
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 8,
                    ),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.surface,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: _justCopied ? Colors.green : Colors.transparent,
                        width: 2,
                      ),
                    ),
                    child: Text(
                      _formatCode(_currentCode),
                      style: TextStyle(
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                        fontFamily: 'monospace',
                        letterSpacing: 4,
                        color: _justCopied
                            ? Colors.green[700]
                            : Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 16),

              // Circular countdown
              SizedBox(
                width: 48,
                height: 48,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    CircularProgressIndicator(
                      value: _secondsRemaining / widget.config.periodSeconds,
                      strokeWidth: 3,
                      backgroundColor: Colors.grey[300],
                      valueColor: AlwaysStoppedAnimation<Color>(
                        _secondsRemaining <= 5
                            ? Colors.red // Urgency indicator
                            : Theme.of(context).colorScheme.primary,
                      ),
                    ),
                    Text(
                      '$_secondsRemaining',
                      style: TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.bold,
                        color: _secondsRemaining <= 5
                            ? Colors.red
                            : Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),

          const SizedBox(height: 8),

          // Next code preview + copy button
          Row(
            children: [
              // Next code (smaller, preview)
              Text(
                'Next: ${_formatCode(_nextCode)}',
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.grey[500],
                  fontFamily: 'monospace',
                ),
              ),
              const Spacer(),

              // Copy button
              IconButton(
                onPressed: _copyToClipboard,
                icon: Icon(
                  _justCopied ? Icons.check : Icons.copy,
                  color: _justCopied ? Colors.green : null,
                ),
                tooltip: 'Copy code',
                iconSize: 20,
              ),
            ],
          ),
        ],
      ),
    );
  }

  /// Format code with space in middle for readability.
  /// "287082" -> "287 082", "12345678" -> "1234 5678"
  String _formatCode(String code) {
    if (code.length == 6) {
      return '${code.substring(0, 3)} ${code.substring(3)}';
    } else if (code.length == 8) {
      return '${code.substring(0, 4)} ${code.substring(4)}';
    }
    return code;
  }
}
