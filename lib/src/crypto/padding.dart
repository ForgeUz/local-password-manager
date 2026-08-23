import 'dart:math';
import 'dart:typed_data';

// Intent: Size-bucket padding to mask entry count via ciphertext length.
class Padding {
  static const List<int> _buckets = [
    4096, 16384, 65536, 262144, 1048576, 4194304
  ];

  static int pickBucket(int length) {
    final required = length + 4;
    if (required <= _buckets.first) return _buckets.first;
    
    for (var b in _buckets) {
      if (required <= b) return b;
    }
    
    final mult = 4194304;
    final rem = required % mult;
    return rem == 0 ? required : required + (mult - rem);
  }

  static Uint8List pad(Uint8List data, int bucketSize) {
    final result = Uint8List(bucketSize);
    final random = Random.secure();
    
    result[0] = (data.length >> 24) & 0xFF;
    result[1] = (data.length >> 16) & 0xFF;
    result[2] = (data.length >> 8) & 0xFF;
    result[3] = data.length & 0xFF;
    
    result.setRange(4, 4 + data.length, data);
    
    final padLen = bucketSize - 4 - data.length;
    final randBytes = Uint8List.fromList(List.generate(padLen, (_) => random.nextInt(256)));
    result.setRange(4 + data.length, bucketSize, randBytes);
    
    return result;
  }

  static Uint8List unpad(Uint8List padded) {
    if (padded.length < 4) throw FormatException('Invalid padded length');
    
    final length = (padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3];
    if (length > padded.length - 4) throw FormatException('Invalid embedded length');
    
    return padded.sublist(4, 4 + length);
  }
}