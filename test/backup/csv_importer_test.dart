import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:vault_crypto/src/backup/csv_importer.dart';

void main() {
  test('Parses simple LastPass/Bitwarden CSV to JSON bytes', () {
    final csv = 'name,username,password\n'
        'Google,user@test.com,pass123\n'
        'Github,devuser,secret456';

    final result = CsvImporter.parse(csv);
    final jsonStr = utf8.decode(result);

    expect(jsonStr, contains('"title":"Google"'));
    expect(jsonStr, contains('"username":"user@test.com"'));
    expect(jsonStr, contains('"password":"pass123"'));
    expect(jsonStr, contains('"title":"Github"'));
  });

  test('Throws FormatException on malformed CSV', () {
    final csv = 'name,username,password\n'
        'Google,"unbalanced quotes,pass';

    expect(() => CsvImporter.parse(csv), throwsA(isA<FormatException>()));
  });

  test('Handles empty input gracefully', () {
    final result = CsvImporter.parse('');
    final jsonStr = utf8.decode(result);
    expect(jsonStr, equals('[]'));
  });
}
