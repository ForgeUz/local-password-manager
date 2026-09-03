import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/os/seccomp_denylist.dart';

// Intent: v5 E19 — seccomp DENY-LIST policy table (pure-logic mirror of the
// C++ BPF filter). Blocks ONLY the 5 scraping/attach syscalls; EVERYTHING the
// Dart VM needs (futex, epoll, clone, exec-memory bookkeeping) is ALLOWED —
// zero SIGSYS in a full session. Kill switch (--no-seccomp) disables it.
void main() {
  group('v5 E19 seccomp deny-list', () {
    test('deny-list is exactly the 5 scrape syscalls; VM surface allowed', () {
      final deny = const SeccompDenylist();
      expect(deny.isDenied('ptrace'), isTrue);
      expect(deny.isDenied('process_vm_readv'), isTrue);
      expect(deny.isDenied('process_vm_writev'), isTrue);
      expect(deny.isDenied('kcmp'), isTrue);
      expect(deny.isDenied('perf_event_open'), isTrue);
      // Everything the Dart VM needs is allowed -> zero SIGSYS risk.
      expect(deny.isAllowed('futex'), isTrue);
      expect(deny.isAllowed('epoll_wait'), isTrue);
      expect(deny.isAllowed('clone'), isTrue);
      expect(deny.isAllowed('mmap'), isTrue);
      // The set is exactly 5 — no accidental allow-list drift.
      expect(SeccompDenylist.deniedSyscalls.length, 5);
    });

    test('kill switch disables the filter (--no-seccomp triage path)', () {
      final armed = const SeccompDenylist();
      expect(armed.installed, isTrue);
      expect(armed.isDenied('ptrace'), isTrue);

      final triage = const SeccompDenylist(killSwitch: true);
      expect(triage.installed, isFalse);
      expect(triage.isDenied('ptrace'), isFalse);
      expect(triage.isAllowed('ptrace'),
          isTrue); // filter absent -> everything allowed
    });
  });
}
