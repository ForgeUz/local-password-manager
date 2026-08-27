import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:vault_crypto/src/app/vault_service.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/onboarding/onboarding_core.dart';
import 'dart:typed_data';
import 'decoy_setup_screen.dart';

class SetupScreen extends StatefulWidget {
  final VaultService service;
  const SetupScreen({super.key, required this.service});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> with SingleTickerProviderStateMixin {
  final _mpController = TextEditingController();
  final _confirmController = TextEditingController();
  bool _isLoading = false;
  late OnboardingStore _onboarding;
  late AnimationController _fadeController;
  late Animation<double> _fadeAnimation;

  @override
  void initState() {
    super.initState();
    _onboarding = OnboardingStore();
    _fadeController = AnimationController(
      duration: const Duration(milliseconds: 600),
      vsync: this,
    );
    _fadeAnimation = CurvedAnimation(parent: _fadeController, curve: Curves.easeIn);
    _fadeController.forward();
  }

  @override
  void dispose() {
    _mpController.dispose();
    _confirmController.dispose();
    _onboarding.dispose();
    _fadeController.dispose();
    super.dispose();
  }

  Future<void> _submitMP() async {
    if (_mpController.text != _confirmController.text) {
      HapticFeedback.heavyImpact();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Passwords do not match.')),
      );
      return;
    }

    final mpBytes = Uint8List.fromList(_mpController.text.codeUnits);
    final mp = SecureBuffer.alloc(mpBytes.length);
    mp.writeBytes(mpBytes);
    _onboarding.dispatch(SubmitMP(mp));
  }

  Future<void> _finalizeVault(bool createDecoy) async {
    final mp = _onboarding.masterPassword;
    if (mp == null) return;

    setState(() => _isLoading = true);
    try {
      await widget.service.createVault(mp);
      if (createDecoy && mounted) {
        _openDecoyWizard();
      }
    } catch (e) {
      HapticFeedback.heavyImpact();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error creating vault: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _openDecoyWizard() {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => DecoySetupScreen(service: widget.service)),
    );
  }

  double _getPasswordStrength(String password) {
    if (password.isEmpty) return 0.0;
    double score = 0;
    if (password.length > 8) score += 0.2;
    if (password.length > 12) score += 0.2;
    if (password.contains(RegExp(r'[A-Z]'))) score += 0.15;
    if (password.contains(RegExp(r'[0-9]'))) score += 0.15;
    if (password.contains(RegExp(r'[!@#$%^&*(),.?":{}|<>]'))) score += 0.3;
    return score.clamp(0.0, 1.0);
  }

  Color _getStrengthColor(double strength) {
    if (strength < 0.4) return Colors.red;
    if (strength < 0.7) return Colors.orange;
    return Colors.green;
  }

  String _getStrengthText(double strength) {
    if (strength < 0.4) return 'Weak';
    if (strength < 0.7) return 'Fair';
    return 'Strong';
  }

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<OnboardingState>(
      stream: _onboarding.stream,
      initialData: _onboarding.currentState,
      builder: (context, snapshot) {
        final state = snapshot.data ?? OnboardingWelcome();
        if (state is OnboardingDone) {
          WidgetsBinding.instance.addPostFrameCallback((_) => _finalizeVault(state.createDecoy));
          return const Scaffold(body: Center(child: CircularProgressIndicator()));
        }
        return _buildBody(context, state);
      },
    );
  }

  Widget _buildBody(BuildContext context, OnboardingState state) {
    final passwordStrength = _getPasswordStrength(_mpController.text);
    final strengthColor = _getStrengthColor(passwordStrength);
    final strengthText = _getStrengthText(passwordStrength);

    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 40.0),
          child: FadeTransition(
            opacity: _fadeAnimation,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const SizedBox(height: 40),
                if (state is OnboardingWelcome) _buildWelcome(),
                if (state is OnboardingDoctrine) _buildDoctrine(),
                if (state is OnboardingCreateMP) _buildCreateMP(passwordStrength, strengthColor, strengthText),
                if (state is OnboardingDecoyOptIn) _buildDecoyOptIn(),
                const SizedBox(height: 40),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildWelcome() {
    return Column(
      children: [
        Container(
          width: 80, height: 80,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: LinearGradient(colors: [Colors.blueGrey.shade700, Colors.blueGrey.shade900], begin: Alignment.topLeft, end: Alignment.bottomRight),
          ),
          child: const Icon(Icons.shield_outlined, size: 40, color: Colors.white),
        ),
        const SizedBox(height: 32),
        const Text('Vault Crypto', style: TextStyle(fontSize: 32, fontWeight: FontWeight.bold, color: Colors.white), textAlign: TextAlign.center),
        const SizedBox(height: 48),
        SizedBox(
          width: double.infinity, height: 56,
          child: ElevatedButton(
            onPressed: () => _onboarding.dispatch(BeginOnboarding()),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.blueGrey.shade700, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            child: const Text('Get Started', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
          ),
        ),
      ],
    );
  }

  Widget _buildDoctrine() {
    return Column(
      children: [
        const Icon(Icons.warning_amber_rounded, size: 64, color: Colors.orange),
        const SizedBox(height: 24),
        const Text('Zero-Knowledge Doctrine', style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.white), textAlign: TextAlign.center),
        const SizedBox(height: 16),
        const Text(
          'Your master password is the ONLY way to unlock your data.\n\n'
          'There is NO cloud recovery.\nThere is NO support reset.\n\n'
          'If you lose it, your data is gone forever.',
          style: TextStyle(color: Colors.white70, height: 1.5, fontSize: 16),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 48),
        SizedBox(
          width: double.infinity, height: 56,
          child: ElevatedButton(
            onPressed: () => _onboarding.dispatch(AcceptDoctrine()),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.orange.shade800, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            child: const Text('I Understand', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
          ),
        ),
      ],
    );
  }

  Widget _buildCreateMP(double strength, Color color, String text) {
    return Column(
      children: [
        const Text('Create Master Password', style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.white), textAlign: TextAlign.center),
        const SizedBox(height: 32),
        TextField(
          controller: _mpController, obscureText: true, autocorrect: false, enableSuggestions: false,
          decoration: InputDecoration(labelText: 'Master Password', filled: true, fillColor: Colors.grey[900], border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none), prefixIcon: Icon(Icons.lock_outline, color: Colors.white54)),
          style: const TextStyle(color: Colors.white),
          onChanged: (_) => setState(() {}),
        ),
        if (_mpController.text.isNotEmpty) ...[
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: Container(
                  height: 4,
                  decoration: BoxDecoration(color: Colors.grey[800], borderRadius: BorderRadius.circular(2)),
                  child: FractionallySizedBox(
                    alignment: Alignment.centerLeft,
                    widthFactor: strength,
                    child: Container(
                      decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(2)),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Text(text, style: TextStyle(color: color, fontWeight: FontWeight.w600)),
            ],
          ),
        ],
        const SizedBox(height: 16),
        TextField(
          controller: _confirmController, obscureText: true, autocorrect: false, enableSuggestions: false,
          decoration: InputDecoration(labelText: 'Confirm Password', filled: true, fillColor: Colors.grey[900], border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none), prefixIcon: Icon(Icons.lock_outline, color: Colors.white54)),
          style: const TextStyle(color: Colors.white),
        ),
        const SizedBox(height: 32),
        SizedBox(
          width: double.infinity, height: 56,
          child: ElevatedButton(
            onPressed: _isLoading ? null : _submitMP,
            style: ElevatedButton.styleFrom(backgroundColor: Colors.blueGrey.shade700, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            child: const Text('Create Vault', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
          ),
        ),
      ],
    );
  }

  Widget _buildDecoyOptIn() {
    return Column(
      children: [
        const Icon(Icons.layers_outlined, size: 64, color: Colors.blueGrey),
        const SizedBox(height: 24),
        const Text('Decoy Vault (Optional)', style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.white), textAlign: TextAlign.center),
        const SizedBox(height: 16),
        const Text(
          'Create a secondary vault with a different password.\n\n'
          'Use this under duress to reveal a fake set of passwords while keeping your real data hidden in the primary vault.',
          style: TextStyle(color: Colors.white70, height: 1.5, fontSize: 15),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 48),
        SizedBox(
          width: double.infinity, height: 56,
          child: ElevatedButton(
            onPressed: () => _onboarding.dispatch(CreateDecoy()),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.blueGrey.shade700, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
            child: const Text('Create Decoy', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
          ),
        ),
        const SizedBox(height: 16),
        TextButton(
          onPressed: () => _onboarding.dispatch(SkipDecoy()),
          child: const Text('Skip for now', style: TextStyle(color: Colors.white54, fontSize: 16)),
        ),
      ],
    );
  }
}