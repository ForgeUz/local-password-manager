import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/backup/snapshot_manager.dart';

void main() {
  late Directory tempDir;
  late SnapshotManager manager;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('vault_test');
    manager = SnapshotManager(storageDir: tempDir, maxSnapshots: 5);
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  test('Saves snapshot and loads it back', () async {
    final blob = Uint8List.fromList([1, 2, 3, 4]);
    await manager.saveSnapshot(blob);
    
    final loaded = await manager.loadLatestSnapshot();
    expect(loaded, equals(blob));
  });

  test('Rotates snapshots when exceeding max', () async {
    for (int i = 0; i < 6; i++) {
      await manager.saveSnapshot(Uint8List.fromList([i]));
    }

    final files = tempDir.listSync();
    expect(files.length, equals(5));
    
    final latest = await manager.loadLatestSnapshot();
    expect(latest, equals(Uint8List.fromList([5]))); // 6th save -> index 5
  });
}