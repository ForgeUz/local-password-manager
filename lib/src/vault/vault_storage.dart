import 'dart:io';
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
    return _file.existsSync();
  }

  Future<Uint8List> readBlob() async {
    if (!await vaultExists()) throw FileSystemException('Vault not found');
    return Uint8List.fromList(await _file.readAsBytes());
  }

  Future<void> writeBlob(Uint8List blob) async {
    await _file.writeAsBytes(blob, flush: true);
  }

  // v5 E17/V3.3: ATOMIC write — temp file in the same directory, then rename
  // over the target. A rename within one filesystem is atomic: an interrupted
  // change leaves the OLD file fully intact. No mixed state is observable.
  Future<void> writeBlobAtomic(Uint8List blob) async {
    final tmp =
        File('${_baseDir.path}${Platform.pathSeparator}.vault.blob.tmp');
    await tmp.writeAsBytes(blob, flush: true);
    await tmp.rename(_file.path);
  }

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
}
