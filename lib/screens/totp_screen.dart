import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:base32/base32.dart';
import 'package:vault_crypto/src/totp/totp_generator.dart';
import 'package:vault_crypto/src/totp/totp_import.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';

class TotpScreen extends StatefulWidget {
  const TotpScreen({super.key});

  @override
  State<TotpScreen> createState() => _TotpScreenState();
}

class _TotpScreenState extends State<TotpScreen> {
  final _secretController = TextEditingController();
  final _issuerController = TextEditingController();
  final _accountController = TextEditingController();
  
  TotpConfig? _config;
  String? _currentCode;
  String? _nextCode;
  int _secondsRemaining = 30;
  bool _showScanner = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _startCountdown();
  }

  @override
  void dispose() {
    _secretController.dispose();
    _issuerController.dispose();
    _accountController.dispose();
    super.dispose();
  }

  void _startCountdown() {
    Future.delayed(const Duration(seconds: 1), () {
      if (!mounted) return;
      setState(() {
        _secondsRemaining--;
        if (_secondsRemaining <= 0) {
          _secondsRemaining = 30;
        }
        _updateCodes();
      });
      _startCountdown();
    });
  }

  void _updateCodes() {
    if (_config == null) return;
    
    final code = TotpGenerator.generateNow(config: _config!);
    final next = TotpGenerator.generateNext(config: _config!);
    
    setState(() {
      _currentCode = code;
      _nextCode = next;
    });
  }

  void _parseManualEntry() {
    final secretB32 = _secretController.text.trim();
    if (secretB32.isEmpty) {
      setState(() => _error = 'Secret is required');
      return;
    }

    try {
      final secretBytes = base32.decode(secretB32.toUpperCase());
      final secret = SecureBuffer.fromList(secretBytes);
      
      final config = TotpConfig(
        issuer: _issuerController.text.trim().isEmpty ? 'Manual' : _issuerController.text.trim(),
        accountName: _accountController.text.trim().isEmpty ? 'Account' : _accountController.text.trim(),
        secret: secret,
        digits: 6,
        periodSeconds: 30,
        algorithm: TotpAlgorithm.sha1,
      );
      
      setState(() {
        _config = config;
        _error = null;
      });
      _updateCodes();
    } catch (e) {
      setState(() => _error = 'Invalid base32 secret: $e');
    }
  }

  void _importFromQr(BarcodeCapture capture) {
    final qr = capture.barcodes.first.rawValue;
    if (qr == null) return;
    
    final result = TotpUriParser.parse(qr);
    
    if (result is TotpImportSuccess) {
      setState(() {
        _config = result.config;
        _issuerController.text = result.config.issuer;
        _accountController.text = result.config.accountName;
        _showScanner = false;
        _error = null;
      });
      _updateCodes();
    } else if (result is TotpImportError) {
      setState(() => _error = 'QR parse error: ${result.error.name}');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('TOTP Generator'),
        actions: [
          IconButton(
            icon: Icon(_showScanner ? Icons.keyboard : Icons.qr_code_scanner),
            onPressed: () => setState(() => _showScanner = !_showScanner),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: _showScanner
            ? SizedBox(
                height: 400,
                child: MobileScanner(
                  onDetect: _importFromQr,
                ),
              )
            : Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (_config == null) ...[
                    const Text(
                      'Add TOTP Secret',
                      style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _issuerController,
                      decoration: const InputDecoration(
                        labelText: 'Issuer (optional)',
                        hintText: 'GitHub, Google, etc.',
                      ),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _accountController,
                      decoration: const InputDecoration(
                        labelText: 'Account (optional)',
                        hintText: 'user@example.com',
                      ),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _secretController,
                      decoration: const InputDecoration(
                        labelText: 'Secret (base32)',
                        hintText: 'JBSWY3DPEHPK3PXP',
                      ),
                      autocorrect: false,
                      enableSuggestions: false,
                    ),
                    const SizedBox(height: 16),
                    if (_error != null)
                      Container(
                        padding: const EdgeInsets.all(12),
                        margin: const EdgeInsets.only(bottom: 16),
                        decoration: BoxDecoration(
                          color: Colors.red.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: Colors.redAccent.withOpacity(0.3)),
                        ),
                        child: Text(
                          _error!,
                          style: const TextStyle(color: Colors.redAccent, fontSize: 14),
                        ),
                      ),
                    ElevatedButton(
                      onPressed: _parseManualEntry,
                      child: const Text('Add Secret'),
                    ),
                  ] else ...[
                    Text(
                      _config!.displayLabel,
                      style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 32),
                    Container(
                      padding: const EdgeInsets.all(24),
                      decoration: BoxDecoration(
                        color: Colors.grey[900],
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Column(
                        children: [
                          Text(
                            _currentCode ?? '------',
                            style: const TextStyle(
                              fontSize: 48,
                              fontWeight: FontWeight.bold,
                              letterSpacing: 8,
                              color: Colors.white,
                            ),
                          ),
                          const SizedBox(height: 16),
                          LinearProgressIndicator(
                            value: _secondsRemaining / 30,
                            backgroundColor: Colors.grey[800],
                            valueColor: const AlwaysStoppedAnimation<Color>(Colors.blueGrey),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            '$_secondsRemaining seconds',
                            style: const TextStyle(fontSize: 14, color: Colors.white70),
                          ),
                          const SizedBox(height: 16),
                          Text(
                            'Next: ${_nextCode ?? '------'}',
                            style: const TextStyle(fontSize: 16, color: Colors.white54),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),
                    OutlinedButton.icon(
                      onPressed: () {
                        setState(() {
                          _config = null;
                          _currentCode = null;
                          _nextCode = null;
                          _secretController.clear();
                          _issuerController.clear();
                          _accountController.clear();
                        });
                      },
                      icon: const Icon(Icons.refresh),
                      label: const Text('Add Another'),
                    ),
                  ],
                ],
              ),
      ),
    );
  }
}