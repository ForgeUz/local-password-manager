// Intent: Cryptographic constants and byte-layout sizes for vault file format.
class CryptoConstants {
  static const int magic = 0x56554c54; // 'VULT'
  static const int formatVersion = 1;
  static const int kdfAlgoId = 1; // 1 = Argon2id
  
  static const int saltSize = 16;
  static const int nonceSize = 12;
  static const int tagSize = 16;
  static const int keySize = 32;
  
  // [magic(4)][ver(1)][algo(1)][mem(4)][iter(4)][par(1)][salt(16)][nonce(12)]
  static const int headerSize = 43;
  
  static const int kdfFloorMemory = 64 * 1024 * 1024; // 64 MiB
  static const int kdfFloorIterations = 3;
  static const int kdfFloorParallelism = 1;
}
