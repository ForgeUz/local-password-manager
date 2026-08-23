import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'src/app/app_store.dart';
import 'src/app/vault_service.dart';
import 'src/clipboard/clipboard_controller.dart';
import 'src/clipboard/native_clipboard.dart';
import 'src/crypto/native/crypto_self_test.dart';
import 'src/crypto/v4/vault_crypto_v4.dart';
import 'src/lock/lifecycle_controller.dart';
import 'src/lock/posture_timer.dart';
import 'src/vault/vault_storage.dart';
import 'src/lock/state.dart';
import 'src/lock/intent.dart';
import 'src/desktop/native_linux.dart';
import 'src/desktop/tray_controller.dart';
import 'src/desktop/hotkey_controller.dart';
import 'screens/corrupt_blob_screen.dart';
import 'screens/lock_screen.dart';
import 'screens/mini_search_screen.dart';
import 'screens/setup_screen.dart';
import 'screens/unlocked_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Fail-closed: verify libsodium FFI primitives before any crypto use.
  CryptoSelfTest.run();
  final appDir = await getApplicationDocumentsDirectory();

  final appStore = AppStore();
  final vaultCrypto = VaultCryptoV4();
  final storage = VaultStorage(baseDir: appDir);
  final vaultService = VaultService(store: appStore, crypto: vaultCrypto, storage: storage);
  final clipboardController = ClipboardController(
    platform: NativeClipboard(),
    wipeDuration: const Duration(seconds: 30),
  );

  await vaultService.init();

  runApp(VaultApp(store: appStore, service: vaultService, clipboard: clipboardController));
}

class VaultApp extends StatefulWidget {
  final AppStore store;
  final VaultService service;
  final ClipboardController clipboard;

  const VaultApp({
    super.key,
    required this.store,
    required this.service,
    required this.clipboard,
  });

  @override
  State<VaultApp> createState() => _VaultAppState();
}

class _VaultAppState extends State<VaultApp> {
  late final LifecycleController _lifecycle;
  late final PostureTimer _postureTimer;
  late final TrayController _tray;
  late final HotkeyController _hotkey;
  BuildContext? _context;

  @override
  void initState() {
    super.initState();
    _lifecycle = LifecycleController(widget.service);
    _postureTimer = PostureTimer(widget.service);
    _tray = TrayController(
      platform: NativeLinuxTray(),
      // Window focus/quit are handled natively by the tray plugin; Dart only
      // needs to lock the vault on the tray menu "Lock Vault" action.
      onActivate: () {},
      onLock: () => widget.store.dispatch(AutoLock()),
      onQuit: () {},
    );
    _tray.init();
    // Global hotkey (Ctrl+Shift+Space) opens the quick mini-search window.
    _hotkey = HotkeyController(
      platform: NativeLinuxHotkey(),
      dispatch: (intent) {
        if (intent is RequestReveal && _context != null) {
          Navigator.push(
            _context!,
            MaterialPageRoute(
              builder: (_) => MiniSearchScreen(
                store: widget.store,
                service: widget.service,
                clipboard: widget.clipboard,
              ),
            ),
          );
        }
      },
    );
    _hotkey.register();
    WidgetsBinding.instance.addObserver(_lifecycle);
    // On unlock, arm the posture-driven idle auto-lock timer.
    widget.store.stateStream.listen((state) {
      _tray.onStateChanged(state);
      if (state is Unlocked) {
        _postureTimer.onUnlock(
          canaryTriggered: false,
          networkRecognized: true,
          recentFailures: 0,
        );
      }
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(_lifecycle);
    _postureTimer.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    _context = context;
    return MaterialApp(
      title: 'Vault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        primaryColor: Colors.blueGrey,
        scaffoldBackgroundColor: Colors.black87,
      ),
      home: StreamBuilder(
        stream: widget.store.stateStream,
        builder: (context, snapshot) {
          final state = widget.store.currentState;

          if (state is Unlocked) {
            return UnlockedScreen(store: widget.store, service: widget.service, clipboard: widget.clipboard);
          } else if (state is SetupRequired) {
            return SetupScreen(service: widget.service);
          } else if (state is BlobCorrupt) {
            return CorruptBlobScreen(service: widget.service);
          } else if (state is Locked) {
            return LockScreen(store: widget.store, service: widget.service, blob: state.blob);
          }

          return const Scaffold(body: Center(child: CircularProgressIndicator()));
        },
      ),
    );
  }
}