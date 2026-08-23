// Intent: v5 E19 — seccomp DENY-LIST policy table (pure-logic mirror of the
// C++ BPF filter installed in linux/runner/my_application.cc). Blocks ONLY the
// scraping/attach syscalls; EVERYTHING the Dart VM needs (futex, epoll, clone,
// exec-memory bookkeeping) is ALLOWED — zero SIGSYS in a full session. Long ago the
// allow-list was the Dart-VM crash lottery; the deny-list is the E19 fix.
// Kill switch (--no-seccomp / VAULT_NO_SECCOMP) disables the filter for triage.
// Best-effort install: a failed prctl logs, never crashes.
// Invariants: deny-set is exactly the 5 scraping syscalls; everything else allowed;
// kill switch -> filter not installed.

class SeccompDenylist {
  // The complete deny-list (x86-64 names). Matches the C++ BPF filter.
  static const Set<String> deniedSyscalls = {
    'ptrace',
    'process_vm_readv',
    'process_vm_writev',
    'kcmp',
    'perf_event_open',
  };

  // Runtime kill switch for triage.
  final bool killSwitch;

  const SeccompDenylist({this.killSwitch = false});

  // True when the filter would be active (not disabled by the kill switch).
  bool get installed => !killSwitch;

  // True if the named syscall is deny-listed.
  bool isDenied(String name) => installed && deniedSyscalls.contains(name);

  // True if the named syscall is allowed (anything not deny-listed).
  bool isAllowed(String name) => !isDenied(name);
}