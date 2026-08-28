import 'dart:math';
import 'dart:typed_data';

// Intent: Sync traffic padding (Phase G.6). Pad all messages to fixed buckets
// (256B / 1KB / 4KB / 16KB) with CSPRNG bytes (not zeros), send 2-5 dummy
// messages per real message at random intervals, and split entries > 16KB into
// multiple padded messages. An eavesdropper cannot infer entry count/size.
// Dependencies: dart:math, dart:typed_data.

class TrafficPadding {
  static const int maxBucket = 16 * 1024;
  static const List<int> buckets = [256, 1024, 4 * 1024, 16 * 1024];
  static const int dummyMin = 2;
  static const int dummyMax = 5;

  // Pick the smallest bucket >= message length (capped at 16KB).
  static int pickBucket(int len) {
    for (final b in buckets) {
      if (len <= b) return b;
    }
    return maxBucket;
  }

  // Pad a message to its bucket with CSPRNG bytes. Returns the padded message.
  static Uint8List pad(Uint8List msg) {
    final bucket = pickBucket(msg.length);
    final r = Random.secure();
    final out = Uint8List(bucket);
    out.setRange(0, msg.length, msg);
    for (var i = msg.length; i < bucket; i++) {
      out[i] = r.nextInt(256);
    }
    return out;
  }

  // Split a message larger than 16KB into chunks (each placed at the start of a
  // 16KB padded message). Returns a list of ready-to-send messages.
  static List<Uint8List> splitAndPad(Uint8List msg) {
    if (msg.length <= maxBucket) return [pad(msg)];
    final chunks = <Uint8List>[];
    var off = 0;
    while (off < msg.length) {
      final take = msg.length - off < maxBucket ? msg.length - off : maxBucket;
      final chunk = msg.sublist(off, off + take);
      final r = Random.secure();
      // Place chunk at start of a 16KB bucket filled with CSPRNG.
      final padded = Uint8List(maxBucket);
      padded.setRange(0, chunk.length, chunk);
      for (var i = chunk.length; i < maxBucket; i++) {
        padded[i] = r.nextInt(256);
      }
      chunks.add(padded);
      off += take;
    }
    return chunks;
  }

  // Generate 2-5 dummy messages (random data in a random bucket).
  static List<Uint8List> generateDummies() {
    final r = Random.secure();
    final n = dummyMin + r.nextInt(dummyMax - dummyMin + 1);
    return List.generate(n, (_) {
      final bucket = buckets[r.nextInt(buckets.length)];
      return Uint8List.fromList(List.generate(bucket, (_) => r.nextInt(256)));
    });
  }
}
