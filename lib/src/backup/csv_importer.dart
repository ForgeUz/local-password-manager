import 'dart:convert';
import 'dart:typed_data';

// Intent: Pure Dart CSV parser mapping third-party formats to vault JSON.
// Dependencies: dart:convert. No external deps needed for simple CSV.
class CsvImporter {
  static Uint8List parse(String csv) {
    if (csv.trim().isEmpty) {
      return Uint8List.fromList(utf8.encode('[]'));
    }

    final lines = const LineSplitter().convert(csv);
    if (lines.length < 2) {
      return Uint8List.fromList(utf8.encode('[]'));
    }

    final headers = _parseLine(lines[0]);
    final entries = <Map<String, String>>[];

    for (int i = 1; i < lines.length; i++) {
      final values = _parseLine(lines[i]);
      if (values.isEmpty || (values.length == 1 && values[0].isEmpty)) continue;
      
      final entry = <String, String>{};
      for (int j = 0; j < headers.length && j < values.length; j++) {
        switch (headers[j].toLowerCase()) {
          case 'name':
          case 'title':
            entry['title'] = values[j];
            break;
          case 'username':
            entry['username'] = values[j];
            break;
          case 'password':
            entry['password'] = values[j];
            break;
          default:
            // Drop unsupported fields to minimize attack surface
            break;
        }
      }
      if (entry.isNotEmpty) entries.add(entry);
    }

    final jsonStr = jsonEncode(entries);
    return Uint8List.fromList(utf8.encode(jsonStr));
  }

  // Basic CSV line parser handling quoted fields
  static List<String> _parseLine(String line) {
    final result = <String>[];
    var current = StringBuffer();
    var inQuotes = false;

    for (int i = 0; i < line.length; i++) {
      final char = line[i];

      if (char == '"') {
        if (inQuotes && i + 1 < line.length && line[i + 1] == '"') {
          current.write('"'); // Escaped quote
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char == ',' && !inQuotes) {
        result.add(current.toString());
        current = StringBuffer();
      } else {
        current.write(char);
      }
    }
    result.add(current.toString());

    // If quotes are unbalanced at end of line, it's malformed
    if (inQuotes) {
      throw FormatException('Malformed CSV: unbalanced quotes');
    }

    return result;
  }
}