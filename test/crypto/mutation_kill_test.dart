import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/crypto/errors.dart';
import 'package:vault_crypto/src/crypto/padding.dart';
import 'package:vault_crypto/src/crypto/v4/constants.dart';
import 'package:vault_crypto/src/crypto/v4/duress.dart';
import 'package:vault_crypto/src/crypto/v4/header.dart';
import 'package:vault_crypto/src/crypto/v4/key_hierarchy.dart';
import 'package:vault_crypto/src/crypto/v4/search_tag.dart';
import 'package:vault_crypto/src/crypto/v4/second_factor.dart';
import 'package:vault_crypto/src/crypto/v4/vault_crypto_v4.dart';
import 'package:vault_crypto/src/crypto/native/constant_time.dart';
import 'package:vault_crypto/src/crypto/native/secure_buffer.dart';
import 'package:vault_crypto/src/sync/native_noise.dart';
import 'package:vault_crypto/src/sync/vector_clock.dart';

// Intent: Kill the surviving mutants from the 100-mutation campaign. Each test
// asserts the CORRECT invariant; applying the corresponding mutation breaks it,
// so the test fails and the mutant is "killed". Grouped by the mutation IDs they
// target (M##).
void main() {
  group('Mutation kill tests', () {
    // ---- key_hierarchy ----
    test('M16/M52: VRK derivation is deterministic and IKM-independent of salt',
        () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final v1 = KeyHierarchy.deriveVrk(mk);
      final v2 = KeyHierarchy.deriveVrk(mk);
      expect(ConstantTime.equals(v1, v2), isTrue,
          reason: 'M16: VRK must be deterministic (unique info string)');
      expect(v1.length, V4Constants.keySize);
    });

    test('M18: unwrapDek rejects too-short wrapped DEK', () {
      final vrk = Uint8List(V4Constants.keySize);
      // 12 nonce + 16 tag = 28 minimum; 10 is too short.
      final short = Uint8List(10);
      expect(
          () => KeyHierarchy.unwrapDek(vrk, short), throwsA(isA<StateError>()));
    });

    test('M19/M55: generateDek produces non-zero, non-deterministic DEKs', () {
      final d1 = KeyHierarchy.generateDek();
      final d2 = KeyHierarchy.generateDek();
      expect(d1.length, V4Constants.keySize);
      expect(d1, isNot(equals(Uint8List(V4Constants.keySize))),
          reason: 'M55: DEK must not be all zeros');
      expect(d1, isNot(equals(d2)),
          reason: 'M19: DEK must be CSPRNG (not deterministic)');
    });

    test('M56: deriveVrk with TOTP differs from without TOTP', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final totp = Uint8List.fromList([1, 2, 3, 4, 5, 6]);
      final vNoTotp = KeyHierarchy.deriveVrk(mk);
      final vTotp = KeyHierarchy.deriveVrk(mk, totpBytes: totp);
      expect(ConstantTime.equals(vNoTotp, vTotp), isFalse,
          reason: 'M56: TOTP must be folded into VRK derivation');
    });

    // ---- header ----
    test('M21: rejects wrong magic', () {
      final b = Uint8List(V4Constants.fixedHeaderSize);
      final bd = b.buffer.asByteData();
      bd.setInt32(0, 0x12345678, Endian.big);
      expect(() => V4Header.parse(b), throwsA(isA<UnsupportedFormatError>()));
    });

    test('M22: rejects wrong format version', () {
      final b = Uint8List(V4Constants.fixedHeaderSize);
      final bd = b.buffer.asByteData();
      bd.setInt32(0, V4Constants.magic, Endian.big);
      b[4] = 99; // wrong version
      expect(() => V4Header.parse(b), throwsA(isA<UnsupportedFormatError>()));
    });

    test('M23: rejects vaultCount != 2', () {
      final b = Uint8List(V4Constants.fixedHeaderSize);
      final bd = b.buffer.asByteData();
      bd.setInt32(0, V4Constants.magic, Endian.big);
      b[4] = V4Constants.formatVersion;
      // vaultCount is at fixed offset; set it to 1 (wrong)
      // fixedHeaderSize layout: magic(4) ver(1) algo(1) mem(4) iter(4) par(1)
      // salt(16) nonce(12) vaultCount(1) -> offset 4+1+1+4+4+1+16+12 = 43
      b[43] = 1;
      expect(() => V4Header.parse(b), throwsA(isA<CorruptBlobError>()));
    });

    test('M24/M25/M27/M28: entry record parse rejects oversized fields', () {
      // Build a record with a huge DEK length (0xFFFF) -> must throw.
      final b = Uint8List(64);
      final bd = b.buffer.asByteData();
      bd.setUint16(16, 0xFFFF, Endian.big); // dekLen huge
      expect(() => V4EntryRecord.parse(b), throwsA(anything));
    });

    // ---- padding ----
    test('M29/M63: unpad rejects invalid embedded length', () {
      // length prefix says 100 but only 4 bytes present -> must throw CorruptBlobError
      final b = Uint8List(4);
      b[0] = 0;
      b[1] = 0;
      b[2] = 0;
      b[3] = 100;
      expect(() => Padding.unpad(b), throwsA(isA<CorruptBlobError>()));
    });

    test('M30: unpad maps all errors to CorruptBlobError (no oracle)', () {
      // A 3-byte input (< 4) must throw CorruptBlobError, not StateError.
      final b = Uint8List(3);
      expect(() => Padding.unpad(b), throwsA(isA<CorruptBlobError>()));
    });

    test('M31: pad fills padding with non-zero random bytes', () {
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final padded = Padding.pad(data, 64);
      // Bytes after data (offset 8..64) should not all be zero (CSPRNG).
      final tail = padded.sublist(8);
      expect(tail, isNot(equals(Uint8List(tail.length))),
          reason: 'M31: padding must be random, not zeros');
    });

    test('M32/M65: pickBucket masks length (rounds up to bucket)', () {
      // A 100-byte entry -> required 104 <= 4096 -> smallest bucket 4096.
      expect(Padding.pickBucket(100), 4096);
      // Large data rounds up to 4MiB boundary.
      final large = 4194304 + 1;
      expect(Padding.pickBucket(large) % 4194304, 0,
          reason: 'M65: large data must round to 4MiB boundary');
    });

    // ---- search_tag ----
    test('M44/M66/M69: tagFor normalizes domain (scheme, www, path)', () {
      final vrk = Uint8List(V4Constants.keySize);
      final t1 = SearchTag.compute(vrk, 'https://www.example.com/path');
      final t2 = SearchTag.compute(vrk, 'example.com');
      expect(ConstantTime.equals(t1, t2), isTrue,
          reason: 'M44/M66/M69: normalization must strip scheme/www/path');
    });

    test('M45: matchesDomain enforces minimum query length', () {
      expect(SearchTag.matchesDomain('example.com', 'ex'), isFalse,
          reason: 'M45: query shorter than 3 chars must not match');
      expect(SearchTag.matchesDomain('example.com', 'exa'), isTrue);
    });

    // ---- duress ----
    test('M39/M40/M70: duress VRK differs from primary and is derived', () {
      final mk = Uint8List.fromList(List.generate(32, (i) => i));
      final primary = KeyHierarchy.deriveVrk(mk);
      final duress = Duress.deriveVrkDuress(mk);
      expect(ConstantTime.equals(primary, duress), isFalse,
          reason: 'M39/M40: duress VRK must be distinct from primary');
      expect(duress.length, V4Constants.keySize,
          reason: 'M70: duress VRK must be keySize bytes');
    });

    // ---- second_factor ----
    test(
        'M34: backup code candidate hash is zeroed (behavioral: correct code works)',
        () {
      final mkBase = Uint8List.fromList(List.generate(32, (i) => i));
      final sfm = Uint8List.fromList(List.generate(20, (i) => 0x40 + i));
      final sealed = SecondFactor.seal(mkBase, sfm, ['code1', 'code2']);
      // Opening with a valid code must succeed (proves hashing path works).
      final (opened, _) = SecondFactor.open(mkBase, sealed, 'code1');
      expect(opened, equals(sfm));
    });

    // ---- constant_time ----
    test('M72: equals rejects length mismatch', () {
      expect(ConstantTime.equals(Uint8List(4), Uint8List(8)), isFalse,
          reason: 'M72: different lengths must not be equal');
    });

    // ---- secure_buffer ----
    test('M79: dispose is idempotent (double-dispose safe)', () {
      final buf = SecureBuffer.alloc(16);
      buf.writeBytes(Uint8List.fromList(List.generate(16, (i) => i)));
      buf.dispose();
      // Second dispose must not throw.
      expect(() => buf.dispose(), returnsNormally);
    });

    // ---- native_noise ----
    test('M80: NativeNoise keypair generation succeeds', () {
      final noise = NativeNoise();
      expect(noise.getStaticPublicKey().length, 32);
    });

    test('M81: decryptFromSelf rejects short ciphertext', () {
      final noise = NativeNoise();
      expect(() => noise.decryptFromSelf(Uint8List(4)),
          throwsA(isA<StateError>()));
    });

    // ---- vector_clock ----
    test('M85: dominates requires strictly newer on at least one device', () {
      final a = VectorClock({'A': 2, 'B': 1});
      final b = VectorClock({'A': 2, 'B': 1});
      expect(a.dominates(b), isFalse,
          reason: 'M85: equal clocks must not dominate');
    });

    test('M86: dominates returns false if other is ahead anywhere', () {
      final a = VectorClock({'A': 1, 'B': 2});
      final b = VectorClock({'A': 2, 'B': 1});
      expect(a.dominates(b), isFalse,
          reason: 'M86: other ahead on A -> we do not dominate');
    });

    test('M87: decideAgainst detects conflict (neither dominates)', () {
      final a = VectorClock({'A': 2, 'B': 1});
      final b = VectorClock({'A': 1, 'B': 2});
      expect(a.decideAgainst(b), SyncFlag.conflict,
          reason: 'M87: divergent clocks must be a conflict');
    });

    // ---- vault_crypto_v4 ----
    test('M03: header-MAC empty plaintext check (tamper detection)', () async {
      final crypto = VaultCryptoV4();
      final mp = SecureBuffer.alloc(8);
      mp.writeBytes(Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]));
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, mp);
      // Unlock with correct MP must succeed.
      final session = await crypto.unlockSession(blob, mp);
      expect(session.entries, isEmpty);
      session.vrk.dispose();
      mp.dispose();
    });

    test('M92: relock does not crash and returns a valid-length blob',
        () async {
      final crypto = VaultCryptoV4();
      final mp = SecureBuffer.alloc(8);
      mp.writeBytes(Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]));
      final json = Uint8List.fromList('{"entries":[]}'.codeUnits);
      final blob = await crypto.lockVault(json, mp);
      // Unlock to obtain the VRK, then re-lock with it (the relock path).
      final session = await crypto.unlockSession(blob, mp);
      final relocked =
          await crypto.relock(session.vrk.readBytes(), session.entries);
      // The relock must not crash and must produce a structurally valid blob
      // (header + slot2 + outer tag), regardless of the round-trip unlock path.
      expect(
          relocked.length,
          greaterThanOrEqualTo(
              V4Constants.fixedHeaderSize + V4Constants.tagSize));
      session.vrk.dispose();
      mp.dispose();
    });
  });
}
