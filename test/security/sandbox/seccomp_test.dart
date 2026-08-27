// File: test/security/sandbox/test_seccomp.dart
// Intent: security.md gate 11 — Seccomp sandbox (Linux) verification.
// Invariants:
// - Seccomp deny-list blocks: ptrace, process_vm_readv, process_vm_writev.
// - Seccomp deny-list blocks: kcmp, perf_event_open.
// - Seccomp policy does not block legitimate Flutter VM operations.
// - Seccomp failure causes app to abort (fail-closed).
// - No syscalls blocked that Flutter needs (verified by full test suite).
// Dependencies: seccomp_denylist.dart.

import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/os/seccomp_denylist.dart';

void main() {
  group('Gate 11 Seccomp Sandbox', () {
    test('deny-list blocks ptrace, process_vm_readv, process_vm_writev', () {
      final seccomp = const SeccompDenylist();
      expect(seccomp.isDenied('ptrace'), isTrue);
      expect(seccomp.isDenied('process_vm_readv'), isTrue);
      expect(seccomp.isDenied('process_vm_writev'), isTrue);
    });

    test('deny-list blocks kcmp, perf_event_open', () {
      final seccomp = const SeccompDenylist();
      expect(seccomp.isDenied('kcmp'), isTrue);
      expect(seccomp.isDenied('perf_event_open'), isTrue);
    });

    test('policy does not block legitimate Flutter VM operations', () {
      final seccomp = const SeccompDenylist();
      // Syscalls the Dart VM needs must be allowed.
      expect(seccomp.isAllowed('futex'), isTrue);
      expect(seccomp.isAllowed('epoll_wait'), isTrue);
      expect(seccomp.isAllowed('clone'), isTrue);
      expect(seccomp.isAllowed('mmap'), isTrue);
      expect(seccomp.isAllowed('read'), isTrue);
      expect(seccomp.isAllowed('write'), isTrue);
    });

    test('kill switch disables the filter (triage)', () {
      final seccomp = const SeccompDenylist(killSwitch: true);
      expect(seccomp.installed, isFalse);
      // With kill switch, nothing is denied.
      expect(seccomp.isDenied('ptrace'), isFalse);
    });

    test('deny-set is exactly the 5 scraping syscalls', () {
      expect(SeccompDenylist.deniedSyscalls, {
        'ptrace',
        'process_vm_readv',
        'process_vm_writev',
        'kcmp',
        'perf_event_open',
      });
    });
  });
}
