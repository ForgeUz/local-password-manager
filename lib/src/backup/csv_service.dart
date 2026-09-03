import 'dart:convert';

import '../backup/csv_importer.dart';
import '../crypto/v4/vault_crypto_v4.dart';
import '../security/risk_tiers.dart';

// Intent: CSV import/export logic (Phase F.1/F.3). Pure logic, no state.
// Extracted from VaultService (god-class split, Part IV item 7) so the CSV
// security boundary (formula injection, plaintext exposure warning) has its own
// module + test file.
// Invariants:
// - Export neutralizes formula injection (=, +, -, @) that Excel would execute.
// - Import parses via CsvImporter and maps rows to V4VaultEntry.
// Dependencies: CsvImporter, V4VaultEntry, RiskTiers, dart:convert.
class CsvService {
  const CsvService._();

  // Parse a third-party CSV into V4VaultEntry rows. Skips empty rows.
  // Returns the parsed entries (caller persists + relocks).
  static List<V4VaultEntry> parseImport(String csv) {
    final json = CsvImporter.parse(csv);
    final list = (jsonDecode(utf8.decode(json)) as List)
        .map((e) => e as Map<String, dynamic>)
        .toList();
    final newEntries = <V4VaultEntry>[];
    var count = 0;
    for (final row in list) {
      final title = (row['title'] ?? '') as String;
      final username = (row['username'] ?? '') as String;
      final password = (row['password'] ?? '') as String;
      if (title.isEmpty && password.isEmpty) continue;
      newEntries.add(V4VaultEntry(
        id: DateTime.now().microsecondsSinceEpoch.toString() + count.toString(),
        title: title,
        username: username,
        password: password,
        url: title.toLowerCase(),
        domain: title.toLowerCase(),
        tier: RiskTiers.suggestTier(title.toLowerCase()),
      ));
      count++;
    }
    return newEntries;
  }

  // Build the export CSV. Neutralizes formula injection and quotes embedded
  // quotes (""). Excludes canaries.
  static String buildExport(List<V4VaultEntry> entries) {
    String cell(String s) {
      var v = s;
      if (v.startsWith('=') ||
          v.startsWith('+') ||
          v.startsWith('-') ||
          v.startsWith('@')) {
        v = "'$v";
      }
      return '"${v.replaceAll('"', '""')}"';
    }

    final rows = entries
        .where((e) => !e.isCanary)
        .map((e) =>
            '${cell(e.title)},${cell(e.username)},${cell(e.password)},${cell(e.url)}')
        .toList();
    return 'title,username,password,url\n${rows.join('\n')}';
  }
}