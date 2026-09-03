import 'dart:io';
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
import 'src/lock/state.dart';
import 'src/lock/intent.dart';
import 'src/vault/vault_storage.dart';
import 'src/desktop/native_linux.dart';
import 'src/desktop/tray_controller.dart';
import 'src/desktop/hotkey_controller.dart';
import 'src/autofill/android_autofill_bridge.dart';
import 'screens/corrupt_blob_screen.dart';
import 'screens/lock_screen.dart';
import 'screens/mini_search_screen.dart';
import 'screens/setup_screen.dart';
import 'screens/unlocked_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    // Fail-closed: verify libsodium FFI primitives before any crypto use.
    // On Android libsodium.so must be bundled in jniLibs; on Linux it is a
    // system lib. A load failure here previously crashed main() -> blank screen.
    // Now we surface a clear error so the user knows the native lib is missing.
    CryptoSelfTest.run();
  } catch (e) {
    runApp(_NativeMissingError(error: e));
    return;
  }
  final appDir = await getApplicationDocumentsDirectory();

  final appStore = AppStore();
  final vaultCrypto = VaultCryptoV4();
  final storage = VaultStorage(baseDir: appDir);
  final vaultService =
      VaultService(store: appStore, crypto: vaultCrypto, storage: storage);
  final clipboardController = ClipboardController(
    platform: NativeClipboard(),
    wipeDuration: const Duration(seconds: 30),
  );

  await vaultService.init();

  runApp(VaultApp(
      store: appStore, service: vaultService, clipboard: clipboardController));
}

// Rendered when libsodium (or another native crypto primitive) fails to load.
// Replaces a silent blank screen with an actionable diagnostic.
class _NativeMissingError extends StatelessWidget {
  final Object error;
  const _NativeMissingError({required this.error});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.error_outline, size: 64, color: Colors.red),
                const SizedBox(height: 16),
                const Text(
                  'Native crypto library failed to load',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                const Text(
                  'The libsodium native library is missing on this build.\n'
                  'On Android: ensure libsodium.so is bundled (android/app/src/main/jniLibs/<abi>/).\n'
                  'On Linux: install libsodium-dev.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Text('$error',
                    style: const TextStyle(fontSize: 12, color: Colors.grey)),
              ],
            ),
          ),
        ),
      ),
    );
  }
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

// Global observer that redirects to LockScreen if vault is locked
class _LockObserver extends NavigatorObserver {
  final AppStore store;
  final VaultService service;
  final BuildContext Function() getContext;
  bool _isNavigating = false;

  _LockObserver(
      {required this.store, required this.service, required this.getContext});

  @override
  void didPop(Route route, Route? previousRoute) {
    _checkLockState();
  }

  @override
  void didPush(Route route, Route? previousRoute) {
    _checkLockState();
  }

  @override
  void didReplace({Route? newRoute, Route? oldRoute}) {
    _checkLockState();
  }

  @override
  void didRemove(Route route, Route? previousRoute) {
    _checkLockState();
  }

  void _checkLockState() {
    if (_isNavigating) return;

    final state = store.currentState;
    debugPrint('LockObserver: state is ${state.runtimeType}');

    if (state is Locked) {
      // Guard: on the very first frame the Navigator/context may not exist yet.
      // getContext() null-asserts, so resolve defensively and bail if null.
      final BuildContext ctx;
      try {
        ctx = getContext();
      } catch (_) {
        return;
      }
      if (!ctx.mounted) return;
      {
        _isNavigating = true;

        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (ctx.mounted) {
            // maybeOf: during the warm-up frame no Navigator exists yet, and
            // Navigator.of() throws. Skip until the real Navigator is mounted.
            final nav = Navigator.maybeOf(ctx);
            if (nav == null) {
              _isNavigating = false;
              return;
            }
            debugPrint('LockObserver: forcing navigation to LockScreen');
            nav.pushAndRemoveUntil(
              MaterialPageRoute(
                builder: (_) => LockScreen(
                    store: store, service: service, blob: state.blob),
                fullscreenDialog: true,
              ),
              (route) => false,
            );
          }
          _isNavigating = false;
        });
      }
    }
  }
}

class _VaultAppState extends State<VaultApp> {
  late final LifecycleController _lifecycle;
  late final PostureTimer _postureTimer;
  late final _LockObserver _lockObserver;
  // Kept alive for the lifetime of the app: the constructor registers the
  // MethodChannel handler (VaultAutofillService -> Dart). Dropping the reference
  // would let GC collect it and silently kill autofill.
  // ignore: unused_field
  AndroidAutofillBridge? _autofillBridge;
  TrayController? _tray;
  HotkeyController? _hotkey;
  BuildContext? _context;

  @override
  void initState() {
    super.initState();
    _lifecycle = LifecycleController(widget.service);
    WidgetsBinding.instance.addObserver(_lifecycle);

    _postureTimer = PostureTimer(widget.service);
    _lockObserver = _LockObserver(
      store: widget.store,
      service: widget.service,
      getContext: () => _context!,
    );

    // Desktop-only integrations: system tray + global hotkey (Linux).
    if (Platform.isLinux) {
      _tray = TrayController(
        platform: NativeLinuxTray(),
        onActivate: () {},
        onLock: () => widget.store.dispatch(AutoLock()),
        onQuit: () {},
      );
      _tray!.init();

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
      _hotkey!.register();
    }

    // Android autofill bridge: handles MethodChannel from VaultAutofillService
    _autofillBridge =
        AndroidAutofillBridge(store: widget.store, service: widget.service);

    widget.store.stateStream.listen((state) {
      _tray?.onStateChanged(state);
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
      navigatorObservers: [_lockObserver], // Добавь эту строку
      home: StreamBuilder(
        stream: widget.store.stateStream,
        builder: (context, snapshot) {
          final state = widget.store.currentState;

          if (state is Unlocked) {
            return UnlockedScreen(
                store: widget.store,
                service: widget.service,
                clipboard: widget.clipboard);
          } else if (state is SetupRequired) {
            return SetupScreen(service: widget.service);
          } else if (state is BlobCorrupt) {
            return CorruptBlobScreen(service: widget.service);
          } else if (state is Locked) {
            return LockScreen(
                store: widget.store, service: widget.service, blob: state.blob);
          }

          return const Scaffold(
              body: Center(child: CircularProgressIndicator()));
        },
      ),
    );
  }
}
