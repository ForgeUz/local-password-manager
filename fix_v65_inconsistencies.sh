cd ~/Downloads/pass

# === [1] Обновить .gitignore ===
# Убрать pubspec.lock из игнора (приложение -> коммитим для воспроизводимости)
sed -i '/^pubspec.lock$/d' .gitignore

# Добавить v6.5_delta.md после v6_delta.md (секция внутренних док)
sed -i '/^v6_delta.md$/a v6.5_delta.md' .gitignore

# Добавить новые секции в конец
cat >> .gitignore << 'EOF'

# Logs (verification output)
*.log

# Backup files
*.backup

# Temporary fix scripts
fix_v65_inconsistencies*.sh

# Android local / signing (NEVER commit secrets)
android/local.properties
android/.gradle/
android/captures/
android/key.properties
*.keystore
*.jks
