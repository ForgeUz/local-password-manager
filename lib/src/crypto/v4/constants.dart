// Intent: v4 file-format constants (v4 §4.3). Supersedes flat-blob constants.dart.
class V4Constants {
  static const int magic = 0x47454e34; // 'GEN4'
  static const int formatVersion = 4;
  static const int kdfAlgoId = 1; // 1 = Argon2id
  static const int vaultCount = 2; // always two (deniability)

  static const int saltSize = 16;
  static const int nonceSize = 12;
  static const int tagSize = 16;
  static const int keySize = 32;
  static const int uuidSize = 16;
  static const int searchTagSize = 32;
  static const int headerMacSize = 16;

  // Fixed header: magic(4) ver(1) algo(1) mem(4) iter(4) par(1) salt(16) nonce(12) vault_count(1)
  static const int fixedHeaderSize = 44;

  static const int kdfFloorMemory = 64 * 1024 * 1024; // 64 MiB
  static const int kdfFloorIterations = 3;
  static const int kdfFloorParallelism = 1;
}