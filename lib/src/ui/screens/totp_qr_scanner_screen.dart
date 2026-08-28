// Intent: Camera-based QR scanner for importing TOTP secrets.
// Scans otpauth:// URI, parses via TotpUriParser, shows preview,
// user confirms to add. Rejects invalid QR before saving.
//
// Invariants:
// - Secret never logged, never shown in plaintext after parse
// - Invalid otpauth:// URI -> typed error shown, no partial save
// - User must explicitly confirm before TotpConfig persisted
// - Camera permission requested at runtime, graceful denial handling
//
// State Transition:
//   ScannerOpened -> CameraPermissionRequest -> granted -> Scanning
//   Scanning -> QRDetected -> ParseAttempt -> Success -> PreviewShown
//   PreviewShown -> UserConfirms -> TotpConfigSaved -> PopWithResult
//   PreviewShown -> UserCancels -> Scanning (retry)
//
// Dependencies: mobile_scanner (camera + ML Kit), TotpUriParser,
//   TotpConfig, Riverpod

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../totp/totp_generator.dart';
import '../../totp/totp_import.dart';

/// Result returned when scanner successfully imports a TOTP config.
/// Caller receives this via Navigator.pop(result).
class TotpScanResult {
  final TotpConfig config;
  const TotpScanResult(this.config);
}

/// QR scanner screen for TOTP import.
/// Returns TotpScanResult on success, null on cancel.
class TotpQrScannerScreen extends ConsumerStatefulWidget {
  const TotpQrScannerScreen({super.key});

  @override
  ConsumerState<TotpQrScannerScreen> createState() =>
      _TotpQrScannerScreenState();
}

class _TotpQrScannerScreenState extends ConsumerState<TotpQrScannerScreen> {
  /// Scanner controller (manages camera lifecycle).
  final MobileScannerController _scannerController = MobileScannerController(
    // Only scan QR codes, not barcodes (perf + accuracy)
    formats: const [BarcodeFormat.qrCode],
  );

  /// Whether a QR has been processed (prevent double-processing).
  bool _processing = false;

  /// Last parse error (for display).
  TotpParseError? _lastError;

  /// Successfully parsed config awaiting user confirmation.
  TotpConfig? _pendingConfig;

  @override
  void dispose() {
    _scannerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan TOTP QR Code'),
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: () => Navigator.of(context).pop(null),
        ),
      ),
      body: _pendingConfig != null
          ? _buildPreview(_pendingConfig!)
          : _buildScanner(),
    );
  }

  /// Camera scanner view.
  Widget _buildScanner() {
    return Column(
      children: [
        // Camera preview
        Expanded(
          child: Stack(
            children: [
              MobileScanner(
                controller: _scannerController,
                onDetect: _handleBarcodeDetected,
              ),

              // Scan frame overlay
              Center(
                child: Container(
                  width: 250,
                  height: 250,
                  decoration: BoxDecoration(
                    border: Border.all(color: Colors.green, width: 3),
                    borderRadius: BorderRadius.circular(16),
                  ),
                ),
              ),

              // Instruction
              Positioned(
                bottom: 24,
                left: 0,
                right: 0,
                child: Text(
                  'Point camera at the QR code from your 2FA setup',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 14,
                    shadows: [Shadow(blurRadius: 4, color: Colors.black)],
                  ),
                ),
              ),

              // Error display
              if (_lastError != null)
                Positioned(
                  top: 16,
                  left: 16,
                  right: 16,
                  child: Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.red[700],
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.error, color: Colors.white, size: 20),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            _errorMessage(_lastError!),
                            style: const TextStyle(color: Colors.white),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),

        // Manual entry fallback
        Padding(
          padding: const EdgeInsets.all(16),
          child: OutlinedButton.icon(
            onPressed: _showManualEntry,
            icon: const Icon(Icons.keyboard),
            label: const Text('Enter code manually'),
          ),
        ),
      ],
    );
  }

  /// Preview of parsed TOTP config (before user confirms).
  Widget _buildPreview(TotpConfig config) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Icon(Icons.check_circle, color: Colors.green, size: 64),
          const SizedBox(height: 16),
          const Text(
            'TOTP Account Detected',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 24),

          // Parsed details (NO secret shown — security)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _infoRow('Issuer',
                      config.issuer.isEmpty ? '(none)' : config.issuer),
                  const Divider(),
                  _infoRow('Account', config.accountName),
                  const Divider(),
                  _infoRow('Digits', '${config.digits}'),
                  const Divider(),
                  _infoRow('Period', '${config.periodSeconds}s'),
                  const Divider(),
                  _infoRow('Algorithm', config.algorithm.name.toUpperCase()),
                  const Divider(),
                  _infoRow('Secret', '•••••••• (hidden)'),
                ],
              ),
            ),
          ),

          const Spacer(),

          // Confirm button
          FilledButton(
            onPressed: _confirmImport,
            style: FilledButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            child: const Text('Add to Vault'),
          ),
          const SizedBox(height: 8),

          // Cancel / rescan
          OutlinedButton(
            onPressed: _cancelImport,
            style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            child: const Text('Scan Again'),
          ),
        ],
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          SizedBox(
            width: 100,
            child: Text(label,
                style: TextStyle(color: Colors.grey[600], fontSize: 13)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(fontWeight: FontWeight.w500)),
          ),
        ],
      ),
    );
  }

  /// Handle a detected barcode.
  void _handleBarcodeDetected(BarcodeCapture capture) {
    // Prevent double-processing of the same frame burst.
    if (_processing) return;

    final barcode = capture.barcodes.firstOrNull;
    if (barcode == null) return;

    final rawValue = barcode.rawValue;
    if (rawValue == null || rawValue.isEmpty) return;

    _processing = true;

    // Parse the otpauth:// URI.
    final result = TotpUriParser.parse(rawValue);

    switch (result) {
      case TotpImportSuccess(:final config):
        // Success — show preview for user confirmation.
        setState(() {
          _pendingConfig = config;
          _lastError = null;
          _processing = false;
        });

      case TotpImportError(:final error):
        // Parse failed — show error, keep scanning.
        setState(() {
          _lastError = error;
          _processing = false;
        });
        // Auto-clear error after 3 seconds.
        Future.delayed(const Duration(seconds: 3), () {
          if (mounted) setState(() => _lastError = null);
        });

      default:
        // Bulk import not supported via QR (single config expected).
        setState(() {
          _lastError = TotpParseError.unknownFormat;
          _processing = false;
        });
    }
  }

  /// User confirmed import — return config to caller.
  void _confirmImport() {
    final config = _pendingConfig;
    if (config == null) return;
    Navigator.of(context).pop(TotpScanResult(config));
  }

  /// User wants to rescan — clear pending, return to scanner.
  void _cancelImport() {
    setState(() {
      _pendingConfig = null;
      _processing = false;
    });
  }

  /// Show manual entry dialog (fallback when QR unavailable).
  void _showManualEntry() {
    final issuerController = TextEditingController();
    final accountController = TextEditingController();
    final secretController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Enter TOTP Manually'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: issuerController,
              decoration:
                  const InputDecoration(labelText: 'Issuer (e.g., GitHub)'),
            ),
            TextField(
              controller: accountController,
              decoration: const InputDecoration(labelText: 'Account'),
            ),
            TextField(
              controller: secretController,
              decoration: const InputDecoration(
                labelText: 'Secret (base32)',
                hintText: 'JBSWY3DPEHPK3PXP',
              ),
              autocorrect: false,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              // Build otpauth:// URI and parse through same path.
              final uri = 'otpauth://totp/'
                  '${Uri.encodeComponent(issuerController.text)}:'
                  '${Uri.encodeComponent(accountController.text)}'
                  '?secret=${Uri.encodeComponent(secretController.text)}'
                  '&issuer=${Uri.encodeComponent(issuerController.text)}';
              Navigator.of(ctx).pop();

              final result = TotpUriParser.parse(uri);
              if (result is TotpImportSuccess) {
                setState(() => _pendingConfig = result.config);
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Invalid secret')),
                );
              }
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }

  /// Map parse error to user-facing message.
  String _errorMessage(TotpParseError error) {
    switch (error) {
      case TotpParseError.invalidScheme:
        return 'Not an otpauth:// QR code.';
      case TotpParseError.unsupportedType:
        return 'Only TOTP supported (not HOTP).';
      case TotpParseError.missingSecret:
        return 'QR code missing secret.';
      case TotpParseError.invalidBase32:
        return 'Secret is not valid base32.';
      case TotpParseError.missingLabel:
        return 'QR code missing account label.';
      case TotpParseError.invalidDigits:
        return 'Digits must be 6 or 8.';
      case TotpParseError.invalidPeriod:
        return 'Period must be positive.';
      case TotpParseError.invalidAlgorithm:
        return 'Unknown algorithm.';
      case TotpParseError.invalidJson:
        return 'Invalid JSON.';
      case TotpParseError.unknownFormat:
        return 'Unrecognized QR format.';
    }
  }
}
