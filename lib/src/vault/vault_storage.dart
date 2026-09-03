import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

// Intent: Deep module for local file persistence. Hides path logic from app.
class VaultStorage {
  final Directory _baseDir;
  static const _fileName = 'vault.blob';
  static const _sfmFileName = 'second_factor.sfm';

  // For testing, inject baseDir. For prod, use path_provider.
  VaultStorage({required Directory baseDir}) : _baseDir = baseDir;

  Directory get baseDir => _baseDir;

  File get _file => File('${_baseDir.path}${Platform.pathSeparator}$_fileName');
  File get _sfmFile =>
      File('${_baseDir.path}${Platform.pathSeparator}$_sfmFileName');

  Future<bool> vaultExists() async {
    return _file.exists();
  }

  Future<Uint8List> readBlob() async {
    if (!await vaultExists()) throw FileSystemException('Vault not found');
    return Uint8List.fromList(await _file.readAsBytes());
  }

  // writeBlob is now atomic (temp + rename) so NO caller can leave a partial
  // file. The old non-atomic write could interleave with a concurrent atomic
  // write and corrupt the blob.
  Future<void> writeBlob(Uint8List blob) async {
    await writeBlobAtomic(blob);
  }

  // v5 E17/V3.3: ATOMIC write — temp file in the same directory, then rename
  // over the target. A rename within one filesystem is atomic: an interrupted
  // change leaves the OLD file fully intact. No mixed state is observable.
  // The temp name is unique (pid + random) so two concurrent atomic writes
  // never collide on the same temp file.
  Future<void> writeBlobAtomic(Uint8List blob) async {
    final tmp = File(
        '${_baseDir.path}${Platform.pathSeparator}.vault.blob.${pid}_${_rand()}.tmp');
    await tmp.writeAsBytes(blob, flush: true);
    await tmp.rename(_file.path);
  }

  static String _rand() =>
      Random.secure().nextInt(0x7fffffff).toRadixString(16);

  // v5 E2: SFM file lives OUTSIDE the vault (separate file, same app dir).
  Future<bool> sfmExists() async {
    return _sfmFile.existsSync();
  }

  Future<Uint8List> readSfm() async {
    if (!await sfmExists()) throw FileSystemException('SFM file not found');
    return Uint8List.fromList(await _sfmFile.readAsBytes());
  }

  // v5 E2/V3.2: atomic SFM write (temp + rename) so an interrupted MP change
  // never leaves a half-written SFM file.
  Future<void> writeSfmAtomic(Uint8List sfm) async {
    final tmp =
        File('${_baseDir.path}${Platform.pathSeparator}.second_factor.sfm.tmp');
    await tmp.writeAsBytes(sfm, flush: true);
    await tmp.rename(_sfmFile.path);
  }

  Future<void> deleteVault() async {
    if (await vaultExists()) {
      await _file.delete();
    }
  }

  Future<void> deleteSfm() async {
    if (await sfmExists()) {
      await _sfmFile.delete();
    }
  }
}
