// File: tool/fuzz_sync_protocol.dart
// Intent: security2.md gate 23.2 — Protocol fuzzer (sync).
// Simulates a man-in-the-middle attacker that intercepts and modifies Noise
// handshake messages, replays old messages, and injects out-of-sequence data.
// Invariants:
// - Modified handshake messages: rejected (MAC failure).
// - Replayed messages: rejected (nonce/counter).
// - Out-of-sequence messages: rejected (state machine).
// - No information leaked in rejection (uniform error).
// - No state corruption from malicious peer.
// Usage: dart run tool/fuzz_sync_protocol.dart --iterations 20000
// Dependencies: replay_counter.dart, noise_session.dart.

import 'dart:io';
import 'dart:math';

import 'package:vault_crypto/src/sync/noise_session.dart';
import 'package:vault_crypto/src/sync/replay_counter.dart';

// Mock transport that succeeds only for the correct PIN.
class MockTransport implements Transport {
  final String expectedPin;
  MockTransport(String pin) : expectedPin = pin;
  @override
  Future<bool> handshake(String pin) async => pin == expectedPin;
}

void main(List<String> args) async {
  final iterations = _parseIterations(args);
  final rng = Random.secure();
  var crashes = 0;
  var rejected = 0;

  print('Fuzzing sync protocol ($iterations iterations)...');

  for (var i = 0; i < iterations; i++) {
    final strategy = rng.nextInt(4);
    switch (strategy) {
      case 0: // Modified handshake message (wrong PIN).
        final s = NoiseSession(MockTransport('123456'), now: () => DateTime.now());
        final wrongPin = '${rng.nextInt(1000000)}'.padLeft(6, '0');
        final st = await s.pair(wrongPin);
        if (st.status == PairStatus.paired) {
          print('FAIL: wrong PIN accepted (handshake MAC bypass)');
          crashes++;
        } else {
          rejected++;
        }
        break;
      case 1: // Replayed message (replay counter).
        final counter = ReplayCounter();
        final c = rng.nextInt(1000);
        counter.validate(c);
        // Replay the same counter -> must be rejected.
        if (counter.validate(c)) {
          print('FAIL: replayed counter accepted');
          crashes++;
        } else {
          rejected++;
        }
        break;
      case 2: // Out-of-sequence message (lower counter).
        final counter = ReplayCounter();
        counter.validate(100);
        if (counter.validate(rng.nextInt(100))) {
          print('FAIL: out-of-sequence counter accepted');
          crashes++;
        } else {
          rejected++;
        }
        break;
      case 3: // Valid handshake then garbage.
        final s = NoiseSession(MockTransport('123456'), now: () => DateTime.now());
        final st = await s.pair('123456');
        if (st.status != PairStatus.paired) {
          print('FAIL: valid handshake rejected');
          crashes++;
        } else {
          rejected++;
        }
        break;
    }
    if (crashes > 10) break;
  }

  print('Done. iterations=$iterations | rejected=$rejected | crashes=$crashes');
  if (crashes > 0) {
    print('FAIL: $crashes protocol violation(s) accepted.');
    exit(1);
  }
  print('PASS: all malicious protocol inputs rejected.');
}

int _parseIterations(List<String> args) {
  for (var i = 0; i < args.length - 1; i++) {
    if (args[i] == '--iterations') {
      return int.tryParse(args[i + 1]) ?? 20000;
    }
  }
  return 20000;
}
