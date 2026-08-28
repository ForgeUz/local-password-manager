// Intent: Verify every mutation's search string exists in its target source
// file. A mutation whose search string is not found would be SKIPPED by the
// campaign (not counted as killed), silently reducing coverage. This tool
// catches those before a long campaign run.
// Usage: dart run tool/verify_mutations.dart
import 'dart:io';
import 'mutation_campaign.dart';

void main() async {
  var ok = 0;
  var missing = 0;
  for (final m in ALL_MUTATIONS) {
    final src = await File(m.file).readAsString();
    if (src.contains(m.search)) {
      ok++;
    } else {
      missing++;
      print('MISSING: ${m.id} [${m.group}] ${m.invariant}');
      print('  file: ${m.file}');
      print('  search: ${m.search.length > 80 ? '${m.search.substring(0, 80)}…' : m.search}');
      print('');
    }
  }
  print('Total: ${ALL_MUTATIONS.length} | found: $ok | missing: $missing');
  exit(missing == 0 ? 0 : 1);
}
