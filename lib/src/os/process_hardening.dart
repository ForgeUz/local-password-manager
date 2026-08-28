import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

// Intent: Linux process hardening to prevent memory dump, swap leakage, and
// external memory-scrape syscalls (ptrace, process_vm_*).
// Dependencies: dart:ffi, libc.so.6, package:ffi (calloc for BPF program).

typedef PrctlNative = Int32 Function(Int32, Int32, Int64, Int64, Int64);
typedef PrctlDart = int Function(int, int, int, int, int);
typedef MlockallNative = Int32 Function(Int32);
typedef MlockallDart = int Function(int);

// seccomp / prctl constants
const int _PR_SET_DUMPABLE = 4;
const int _PR_SET_SECCOMP = 22;
const int _SECCOMP_MODE_FILTER = 2;
const int _SECCOMP_RET_ALLOW = 0x7fff0000;
const int _SECCOMP_RET_ERRNO = 0x00050000;
const int _EPERM = 1;

// BPF instruction opcodes (struct sock_filter: 4 x uint32)
const int _BPF_LD_W_ABS = 0x20; // BPF_LD | BPF_W | BPF_ABS
const int _BPF_JMP_JEQ = 0x10; // BPF_JMP | BPF_JEQ
const int _BPF_RET = 0x06; // BPF_RET

// syscall numbers (x86-64)
const int _SYS_ptrace = 101;
const int _SYS_process_vm_readv = 310;
const int _SYS_process_vm_writev = 311;

class ProcessHardening {
  static const int _MCL_CURRENT = 1;
  static const int _MCL_FUTURE = 2;

  // Applies process hardening. Best-effort: logs warnings, does not crash.
  static void harden() {
    if (!Platform.isLinux) return; // Android uses OS sandbox

    try {
      final lib = DynamicLibrary.open('libc.so.6');

      final prctl = lib.lookupFunction<PrctlNative, PrctlDart>('prctl');
      final mlockall =
          lib.lookupFunction<MlockallNative, MlockallDart>('mlockall');

      // Disable core dumps
      final prctlResult = prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0);
      if (prctlResult != 0) {
        print('WARN: Failed to set PR_SET_DUMPABLE=0');
      }

      // Lock memory pages
      final mlockResult = mlockall(_MCL_CURRENT | _MCL_FUTURE);
      if (mlockResult != 0) {
        print('WARN: Failed to mlockall. CAP_IPC_LOCK might be missing.');
      }

      // Install seccomp deny-list filter (blocks ptrace / process_vm_*)
      _installSeccompFilter(prctl);
    } catch (e) {
      print('WARN: Process hardening failed: $e');
    }
  }

  // Builds a BPF program that returns EPERM for the deny-listed syscalls and
  // allows everything else, then installs it via prctl(PR_SET_SECCOMP).
  //
  // Program (6 instructions):
  //  0: LD  W  ABS 0            load syscall number
  //  1: JEQ ptrace, jt=3, jf=0  if ptrace -> jump to ERRNO (ins5)
  //  2: JEQ readv,  jt=2, jf=0  if readv  -> jump to ERRNO
  //  3: JEQ writev, jt=1, jf=0  if writev -> jump to ERRNO
  //  4: RET K = ALLOW
  //  5: RET K = ERRNO(EPERM)
  static void _installSeccompFilter(PrctlDart prctl) {
    final prog = calloc.allocate<Uint8>(6 * 16);
    try {
      final ins = prog.cast<Uint32>().asTypedList(6 * 4);
      var i = 0;
      // 0: LD W ABS 0
      ins[i++] = _BPF_LD_W_ABS;
      ins[i++] = 0;
      ins[i++] = 0;
      ins[i++] = 0;
      // 1: JEQ ptrace, jt=3, jf=0
      ins[i++] = _BPF_JMP_JEQ;
      ins[i++] = 0;
      ins[i++] = 3;
      ins[i++] = _SYS_ptrace;
      // 2: JEQ readv, jt=2, jf=0
      ins[i++] = _BPF_JMP_JEQ;
      ins[i++] = 0;
      ins[i++] = 2;
      ins[i++] = _SYS_process_vm_readv;
      // 3: JEQ writev, jt=1, jf=0
      ins[i++] = _BPF_JMP_JEQ;
      ins[i++] = 0;
      ins[i++] = 1;
      ins[i++] = _SYS_process_vm_writev;
      // 4: RET ALLOW
      ins[i++] = _BPF_RET;
      ins[i++] = 0;
      ins[i++] = 0;
      ins[i++] = _SECCOMP_RET_ALLOW;
      // 5: RET ERRNO(EPERM)
      ins[i++] = _BPF_RET;
      ins[i++] = 0;
      ins[i++] = 0;
      ins[i++] = _SECCOMP_RET_ERRNO | _EPERM;

      // sock_fprog { uint16 len; padding(6); sock_filter* filter; } = 16 bytes
      final fprog = calloc.allocate<Uint8>(16);
      try {
        final lenField = fprog.cast<Uint16>().asTypedList(1);
        lenField[0] = 6;
        // filter pointer at offset 8 (uint64)
        final ptrField = fprog.cast<Uint64>().asTypedList(2);
        ptrField[1] = prog.address;

        final rc =
            prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, fprog.address, 0, 0);
        if (rc != 0) {
          print(
              'WARN: Failed to install seccomp filter (rc=$rc). Kernel may lack seccomp.');
        }
      } finally {
        calloc.free(fprog);
      }
    } finally {
      calloc.free(prog);
    }
  }
}
