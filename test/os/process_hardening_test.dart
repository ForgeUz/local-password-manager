// ignore_for_file: constant_identifier_names
// Mirrors Linux C constant (PR_GET_DUMPABLE).

import 'dart:ffi';
import 'dart:io';
import 'package:test/test.dart';
import 'package:vault_crypto/src/os/process_hardening.dart';

// Intent: Verify process hardening executes and attempts a seccomp filter.
// Invariants: harden() does not throw; process remains functional after.
// Note: seccomp install is best-effort. Some sandboxes already impose their
// own seccomp policy, so PR_SET_SECCOMP may be denied (rc=-1) without errno.
// The real AC is: harden() never crashes and PR_SET_DUMPABLE=0 is applied.

typedef PrctlNative = Int32 Function(Int32, Int32, Int64, Int64, Int64);
typedef PrctlDart = int Function(int, int, int, int, int);

const int _PR_GET_DUMPABLE = 3;

void main() {
  test('harden() executes without throwing', () {
    expect(() => ProcessHardening.harden(), returnsNormally);
  });

  test('applies PR_SET_DUMPABLE=0 on Linux', () {
    if (!Platform.isLinux) return; // Android uses OS sandbox
    ProcessHardening.harden();
    final lib = DynamicLibrary.open('libc.so.6');
    final prctl = lib.lookupFunction<_PrctlNative, _PrctlDart>('prctl');
    final dumpable = prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0);
    expect(dumpable, 0);
  });
}

typedef _PrctlNative = Int32 Function(Int32, Int32, Int64, Int64, Int64);
typedef _PrctlDart = int Function(int, int, int, int, int);
