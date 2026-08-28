import 'dart:convert';
import 'dart:typed_data';

// Intent: Core data model for the password vault. Pure Dart, no IO.
class VaultEntry {
  final String id;
  String title;
  String username;
  String password;
  String url;
  String?
      passkeyCredentialId; // Opaque FIDO2 handle (public data, key lives in hardware)

  VaultEntry({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    required this.url,
    this.passkeyCredentialId,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'username': username,
        'password': password,
        'url': url,
        'passkeyCredentialId': passkeyCredentialId,
      };

  factory VaultEntry.fromJson(Map<String, dynamic> json) {
    return VaultEntry(
      id: json['id'] as String,
      title: json['title'] as String,
      username: json['username'] as String,
      password: json['password'] as String,
      url: json['url'] as String,
      passkeyCredentialId: json['passkeyCredentialId'] as String?,
    );
  }
}

class VaultData {
  final List<VaultEntry> entries;

  VaultData({required this.entries});

  Uint8List toJsonBytes() {
    final jsonStr = jsonEncode({
      'entries': entries.map((e) => e.toJson()).toList(),
    });
    return Uint8List.fromList(utf8.encode(jsonStr));
  }

  factory VaultData.fromJsonBytes(Uint8List bytes) {
    final jsonStr = utf8.decode(bytes);
    final jsonMap = jsonDecode(jsonStr) as Map<String, dynamic>;
    final entries = (jsonMap['entries'] as List)
        .map((e) => VaultEntry.fromJson(e as Map<String, dynamic>))
        .toList();
    return VaultData(entries: entries);
  }
}
