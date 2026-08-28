import 'dart:typed_data';
import 'constants.dart';
import '../errors.dart';

// Intent: v4 file header model (v4 §4.3). Fixed header + per-entry DEK table.
// The entire header is passed as AAD to the outer AES-GCM (v4 §4.3 "header MAC").
//
// SECURITY CRITICAL: All parsing includes bounds checking to prevent buffer overflows.
// Invariants: magic is GEN4; vault_count always 2; entry records round-trip.
// Dependencies: dart:typed_data, V4Constants, errors.dart.

class V4EntryRecord {
  final Uint8List id; // 16B UUID
  final int tier; // 1B: 0=Standard 1=Sensitive 2=Critical
  final Uint8List wrappedDek; // 2B len + variable
  final List<Uint8List>
      searchTags; // prefix tags, each 32B (len 3..full domain)
  final Uint8List vectorClock; // variable
  final Uint8List ciphertext; // 4B len + variable (padded to size bucket)

  V4EntryRecord({
    required this.id,
    required this.tier,
    required this.wrappedDek,
    required this.searchTags,
    required this.vectorClock,
    required this.ciphertext,
  });

  Uint8List toBytes() {
    final vcLen = vectorClock.length;
    final tagBytes = searchTags.fold<int>(0, (a, t) => a + t.length);
    final total = V4Constants.uuidSize +
        1 +
        2 +
        wrappedDek.length +
        2 +
        tagBytes +
        2 +
        vcLen +
        4 +
        ciphertext.length;
    final out = Uint8List(total);
    final bd = out.buffer.asByteData();
    var off = 0;
    out.setRange(off, off + V4Constants.uuidSize, id);
    off += V4Constants.uuidSize;
    out[off++] = tier;
    bd.setUint16(off, wrappedDek.length, Endian.big);
    off += 2;
    out.setRange(off, off + wrappedDek.length, wrappedDek);
    off += wrappedDek.length;
    bd.setUint16(off, searchTags.length, Endian.big);
    off += 2;
    for (final t in searchTags) {
      out.setRange(off, off + t.length, t);
      off += t.length;
    }
    bd.setUint16(off, vcLen, Endian.big);
    off += 2;
    out.setRange(off, off + vcLen, vectorClock);
    off += vcLen;
    bd.setUint32(off, ciphertext.length, Endian.big);
    off += 4;
    out.setRange(off, off + ciphertext.length, ciphertext);
    return out;
  }

  factory V4EntryRecord.parse(Uint8List bytes) {
    // SECURITY: Bounds checking to prevent RangeError on malformed input.
    final bd = bytes.buffer.asByteData();
    var off = 0;

    void checkBounds(int needed) {
      if (off + needed > bytes.length) {
        throw CorruptBlobError('Record extends beyond blob boundary');
      }
    }

    checkBounds(V4Constants.uuidSize);
    final id = bytes.sublist(off, off + V4Constants.uuidSize);
    off += V4Constants.uuidSize;

    checkBounds(1);
    final tier = bytes[off++];

    checkBounds(2);
    final dekLen = bd.getUint16(off, Endian.big);
    off += 2;

    if (dekLen > 1024) throw CorruptBlobError('DEK length unreasonably large');
    checkBounds(dekLen);
    final wrappedDek = bytes.sublist(off, off + dekLen);
    off += dekLen;

    checkBounds(2);
    final tagCount = bd.getUint16(off, Endian.big);
    off += 2;

    if (tagCount > 100) throw CorruptBlobError('Too many search tags');
    final searchTags = <Uint8List>[];
    for (var i = 0; i < tagCount; i++) {
      checkBounds(V4Constants.searchTagSize);
      searchTags.add(bytes.sublist(off, off + V4Constants.searchTagSize));
      off += V4Constants.searchTagSize;
    }

    checkBounds(2);
    final vcLen = bd.getUint16(off, Endian.big);
    off += 2;

    if (vcLen > 256) throw CorruptBlobError('Vector clock too large');
    checkBounds(vcLen);
    final vectorClock = bytes.sublist(off, off + vcLen);
    off += vcLen;

    checkBounds(4);
    final ctLen = bd.getUint32(off, Endian.big);
    off += 4;

    if (ctLen > 1024 * 1024) throw CorruptBlobError('Ciphertext too large');
    checkBounds(ctLen);
    final ciphertext = bytes.sublist(off, off + ctLen);

    return V4EntryRecord(
      id: id,
      tier: tier,
      wrappedDek: wrappedDek,
      searchTags: searchTags,
      vectorClock: vectorClock,
      ciphertext: ciphertext,
    );
  }
}

class V4Header {
  final int magic;
  final int formatVersion;
  final int kdfAlgoId;
  final int kdfMemory;
  final int kdfIterations;
  final int kdfParallelism;
  final Uint8List salt;
  final Uint8List nonce;
  final int vaultCount;
  final List<V4EntryRecord> entries;

  V4Header({
    required this.magic,
    required this.formatVersion,
    required this.kdfAlgoId,
    required this.kdfMemory,
    required this.kdfIterations,
    required this.kdfParallelism,
    required this.salt,
    required this.nonce,
    required this.vaultCount,
    required this.entries,
  });

  factory V4Header.generate({
    required int kdfMemory,
    required int kdfIterations,
    required int kdfParallelism,
    required Uint8List salt,
    required Uint8List nonce,
    List<V4EntryRecord> entries = const [],
  }) {
    return V4Header(
      magic: V4Constants.magic,
      formatVersion: V4Constants.formatVersion,
      kdfAlgoId: V4Constants.kdfAlgoId,
      kdfMemory: kdfMemory,
      kdfIterations: kdfIterations,
      kdfParallelism: kdfParallelism,
      salt: salt,
      nonce: nonce,
      vaultCount: V4Constants.vaultCount,
      entries: entries,
    );
  }

  // Serialize the fixed header + entry table (everything before the header MAC).
  Uint8List toBytes() {
    final entryBytes = entries.map((e) => e.toBytes()).toList();
    final entryTableLen = entryBytes.fold(0, (a, b) => a + b.length);
    final total = V4Constants.fixedHeaderSize + 2 + entryTableLen;
    final out = Uint8List(total);
    final bd = out.buffer.asByteData();
    var off = 0;
    bd.setInt32(off, magic, Endian.big);
    off += 4;
    out[off++] = formatVersion;
    out[off++] = kdfAlgoId;
    bd.setInt32(off, kdfMemory, Endian.big);
    off += 4;
    bd.setInt32(off, kdfIterations, Endian.big);
    off += 4;
    out[off++] = kdfParallelism;
    out.setRange(off, off + V4Constants.saltSize, salt);
    off += V4Constants.saltSize;
    out.setRange(off, off + V4Constants.nonceSize, nonce);
    off += V4Constants.nonceSize;
    out[off++] = vaultCount;
    bd.setUint16(off, entries.length, Endian.big);
    off += 2;
    for (var i = 0; i < entryBytes.length; i++) {
      out.setRange(off, off + entryBytes[i].length, entryBytes[i]);
      off += entryBytes[i].length;
    }
    return out;
  }

  factory V4Header.parse(Uint8List bytes) {
    if (bytes.length < V4Constants.fixedHeaderSize) throw CorruptBlobError();
    final bd = bytes.buffer.asByteData();
    var off = 0;
    final magic = bd.getInt32(off, Endian.big);
    off += 4;
    if (magic != V4Constants.magic) throw UnsupportedFormatError();
    final ver = bytes[off++];
    if (ver != V4Constants.formatVersion) throw UnsupportedFormatError();
    final algoId = bytes[off++];
    final mem = bd.getInt32(off, Endian.big);
    off += 4;
    final iter = bd.getInt32(off, Endian.big);
    off += 4;
    final par = bytes[off++];
    final salt = bytes.sublist(off, off + V4Constants.saltSize);
    off += V4Constants.saltSize;
    final nonce = bytes.sublist(off, off + V4Constants.nonceSize);
    off += V4Constants.nonceSize;
    final vaultCount = bytes[off++];

    // CRITICAL: Validate vaultCount matches spec (always 2)
    if (vaultCount != V4Constants.vaultCount) {
      throw CorruptBlobError(
          'Invalid vault count: expected ${V4Constants.vaultCount}, got $vaultCount');
    }

    final entries = <V4EntryRecord>[];
    try {
      // SECURITY: entry-count read is inside the guard so a truncated header
      // (exactly fixedHeaderSize bytes) throws CorruptBlobError, not RangeError.
      final entryCount = bd.getUint16(off, Endian.big);
      off += 2;
      for (var i = 0; i < entryCount; i++) {
        // Parse one record by scanning: need to know its length.
        final rec = _parseOneRecord(bytes, off);
        entries.add(rec);
        off += _recordLength(rec);
      }
    } on RangeError {
      throw CorruptBlobError('Malformed entry record');
    }
    return V4Header(
      magic: magic,
      formatVersion: ver,
      kdfAlgoId: algoId,
      kdfMemory: mem,
      kdfIterations: iter,
      kdfParallelism: par,
      salt: salt,
      nonce: nonce,
      vaultCount: vaultCount,
      entries: entries,
    );
  }

  static int _recordLength(V4EntryRecord rec) {
    return V4Constants.uuidSize +
        1 +
        2 +
        rec.wrappedDek.length +
        2 +
        rec.searchTags.length * V4Constants.searchTagSize +
        2 +
        rec.vectorClock.length +
        4 +
        rec.ciphertext.length;
  }

  static V4EntryRecord _parseOneRecord(Uint8List bytes, int off) {
    final bd = bytes.buffer.asByteData();
    var p = off;

    // SECURITY: Bounds checking helper
    void checkBounds(int needed) {
      if (p + needed > bytes.length) {
        throw CorruptBlobError('Record extends beyond blob boundary');
      }
    }

    checkBounds(V4Constants.uuidSize);
    final id = bytes.sublist(p, p + V4Constants.uuidSize);
    p += V4Constants.uuidSize;

    checkBounds(1);
    final tier = bytes[p++];

    checkBounds(2);
    final dekLen = bd.getUint16(p, Endian.big);
    p += 2;

    // SECURITY: Sanity check DEK length (wrapped DEK = nonce(12) + ct(32) + tag(16) = 60 bytes typical)
    if (dekLen > 1024) throw CorruptBlobError('DEK length unreasonably large');
    checkBounds(dekLen);
    final wrappedDek = bytes.sublist(p, p + dekLen);
    p += dekLen;

    checkBounds(2);
    final tagCount = bd.getUint16(p, Endian.big);
    p += 2;

    // SECURITY: Sanity check tag count
    if (tagCount > 100) throw CorruptBlobError('Too many search tags');
    final searchTags = <Uint8List>[];
    for (var i = 0; i < tagCount; i++) {
      checkBounds(V4Constants.searchTagSize);
      searchTags.add(bytes.sublist(p, p + V4Constants.searchTagSize));
      p += V4Constants.searchTagSize;
    }

    checkBounds(2);
    final vcLen = bd.getUint16(p, Endian.big);
    p += 2;

    // SECURITY: Sanity check vector clock length
    if (vcLen > 256) throw CorruptBlobError('Vector clock too large');
    checkBounds(vcLen);
    final vectorClock = bytes.sublist(p, p + vcLen);
    p += vcLen;

    checkBounds(4);
    final ctLen = bd.getUint32(p, Endian.big);
    p += 4;

    // SECURITY: Sanity check ciphertext length (max 1MB per entry)
    if (ctLen > 1024 * 1024) throw CorruptBlobError('Ciphertext too large');
    checkBounds(ctLen);
    final ciphertext = bytes.sublist(p, p + ctLen);

    return V4EntryRecord(
      id: id,
      tier: tier,
      wrappedDek: wrappedDek,
      searchTags: searchTags,
      vectorClock: vectorClock,
      ciphertext: ciphertext,
    );
  }
}
