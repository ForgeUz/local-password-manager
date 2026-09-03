import 'dart:io';
import 'dart:typed_data';

// Intent: Manages local versioned snapshots of encrypted vault blobs.
// State Transition: Save -> Rotate -> Persist
class SnapshotManager {
  final Directory _storageDir;
  final int _maxSnapshots;

  SnapshotManager({required Directory storageDir, required int maxSnapshots})
      : _storageDir = storageDir,
        _maxSnapshots = maxSnapshots {
    if (!_storageDir.existsSync()) _storageDir.createSync(recursive: true);
  }

  Future<void> saveSnapshot(Uint8List blob) async {
    final files = _getSortedFiles();

    // Delete oldest if we are at capacity
    if (files.length >= _maxSnapshots) {
      files.last.deleteSync();
    }

    // Shift indices: v1 -> v2, v2 -> v3...
    final shiftedFiles = _getSortedFiles(); // Re-fetch after potential delete
    for (var file in shiftedFiles.reversed) {
      final idx = _getIndexFromName(file.path);
      await file.rename(_getPathForIndex(idx + 1));
    }

    // Write new snapshot as v1
    final newFile = File(_getPathForIndex(1));
    await newFile.writeAsBytes(blob);
  }

  Future<Uint8List?> loadLatestSnapshot() async {
    final files = _getSortedFiles();
    if (files.isEmpty) return null;
    return Uint8List.fromList(await files.first.readAsBytes());
  }

  // Delete all snapshots (used by resetVault so no encrypted copy of the old
  // vault survives a reset).
  Future<void> clearSnapshots() async {
    for (final file in _getSortedFiles()) {
      await file.delete();
    }
  }

  List<File> _getSortedFiles() {
    if (!_storageDir.existsSync()) return [];
    final files = _storageDir.listSync().whereType<File>().toList();
    files.sort((a, b) =>
        _getIndexFromName(a.path).compareTo(_getIndexFromName(b.path)));
    return files;
  }

  int _getIndexFromName(String path) {
    final name = path.split(Platform.pathSeparator).last;
    return int.parse(name.replaceAll('vault.v', '').replaceAll('.blob', ''));
  }

  String _getPathForIndex(int index) {
    return '${_storageDir.path}${Platform.pathSeparator}vault.v$index.blob';
  }
}
