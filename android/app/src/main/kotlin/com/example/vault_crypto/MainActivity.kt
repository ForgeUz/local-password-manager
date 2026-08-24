package com.example.vault_crypto

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * MainActivity for Vault Crypto.
 * Bridges: clipboard (sensitive MIME), biometric Keystore, BLE plugin,
 * and a native file picker (Storage Access Framework) so the user can
 * visually choose where to save/load the encrypted vault file.
 */
class MainActivity : FlutterFragmentActivity() {
    private val CLIPBOARD_CHANNEL = "vault_crypto/clipboard"
    private val BIOMETRIC_CHANNEL = "vault_crypto/biometric"
    private val FILE_PICKER_CHANNEL = "vault_crypto/file_picker"
    private val KEY_ALIAS = "vault_biometric_key"

    private var blePlugin: BleTransportPlugin? = null

    // Pending platform-channel results while the system picker is open
    private var pendingExportPath: String? = null
    private var pendingExportResult: MethodChannel.Result? = null
    private var pendingImportResult: MethodChannel.Result? = null

    // Modern Activity Result API (does not conflict with Flutter internals).
    // EXPORT: user picks a destination in the native "Save as" dialog,
    // then we stream the temp vault file into the chosen URI.
    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val uri = result.data?.data
        val tmpPath = pendingExportPath
        if (result.resultCode == RESULT_OK && uri != null && tmpPath != null) {
            try {
                val bytes = File(tmpPath).readBytes()
                contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                File(tmpPath).delete()
                pendingExportResult?.success(uri.toString())
            } catch (e: Exception) {
                pendingExportResult?.error("write_failed", e.message, null)
            }
        } else {
            pendingExportResult?.error("cancelled", "Export cancelled", null)
            tmpPath?.let { File(it).delete() }
        }
        pendingExportResult = null
        pendingExportPath = null
    }

    // IMPORT: user picks any file in the native "Open" dialog,
    // we read its bytes and hand them to Dart for MP verification.
    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val uri = result.data?.data
        if (result.resultCode == RESULT_OK && uri != null) {
            try {
                val bytes = contentResolver.openInputStream(uri)?.readBytes()
                pendingImportResult?.success(bytes)
            } catch (e: Exception) {
                pendingImportResult?.error("read_failed", e.message, null)
            }
        } else {
            pendingImportResult?.error("cancelled", "Import cancelled", null)
        }
        pendingImportResult = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Prevent screenshots and recent apps preview (security)
        window.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE
        )

        // Request Bluetooth runtime permissions per API level.
        // Intent: Nearby Connections needs these at runtime; manifest declares
        // them but Android 12+ requires an explicit user grant prompt.
        // State Transition: launch -> requestPermissions -> onRequestPermissionsResult.
        val notGranted = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(this, it) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED
        }
        if (notGranted.isNotEmpty()) {
            androidx.core.app.ActivityCompat.requestPermissions(
                this, notGranted.toTypedArray(), REQ_BLE
            )
        }
    }

    // Full BLE permission set per API level. Mirrors BleTransportPlugin.hasBlePermissions().
    // API 33+: add NEARBY_WIFI_DEVICES (WiFi Direct bulk transfer).
    // API <= 30: legacy ACCESS_FINE_LOCATION (BLE scanning).
    private val REQ_BLE = 1001

    private fun requiredPermissions(): Array<String> = when {
        Build.VERSION.SDK_INT >= 33 -> arrayOf(
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_ADVERTISE,
            android.Manifest.permission.NEARBY_WIFI_DEVICES,
        )
        Build.VERSION.SDK_INT >= 31 -> arrayOf(
            android.Manifest.permission.BLUETOOTH_CONNECT,
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_ADVERTISE,
        )
        else -> arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_BLE) {
            val sb = StringBuilder("BLE permission grant result: ")
            for (i in 0 until permissions.size) {
                if (i > 0) sb.append(", ")
                val granted = grantResults[i] ==
                    android.content.pm.PackageManager.PERMISSION_GRANTED
                sb.append(permissions[i]).append('=').append(granted)
            }
            android.util.Log.d("VaultCrypto", sb.toString())
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Register BLE Transport Plugin
        blePlugin = BleTransportPlugin.registerWith(this, flutterEngine)

        // Clipboard Channel
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CLIPBOARD_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "copy" -> {
                        val text = call.argument<String>("text") ?: ""
                        val sensitive = call.argument<Boolean>("sensitive") ?: false
                        copyToClipboard(text, sensitive)
                        result.success(null)
                    }
                    "clear" -> {
                        clearClipboard()
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }

        // Biometric Channel
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, BIOMETRIC_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "authenticate" -> authenticate(result)
                    "storeVrk" -> {
                        val blob = call.argument<ByteArray>("blob")
                        if (blob == null) {
                            result.error("bad_args", "blob required", null)
                            return@setMethodCallHandler
                        }
                        storeVrk(blob, result)
                    }
                    "retrieveVrk" -> retrieveVrk(result)
                    else -> result.notImplemented()
                }
            }

        // File picker channel: native "Save as" / "Open" dialogs (SAF)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, FILE_PICKER_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "pickExportPath" -> {
                        pendingExportPath = call.argument<String>("tmpPath")
                        pendingExportResult = result
                        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "*/*"
                            putExtra(Intent.EXTRA_TITLE, "vault_export.vault")
                        }
                        exportLauncher.launch(intent)
                    }
                    "pickImportPath" -> {
                        pendingImportResult = result
                        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "*/*"
                        }
                        importLauncher.launch(intent)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun copyToClipboard(text: String, sensitive: Boolean) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("vault", text)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && sensitive) {
            val extras = PersistableBundle()
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            clip.description.extras = extras
        }

        clipboard.setPrimaryClip(clip)
    }

    private fun clearClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
    }

    private fun authenticate(result: MethodChannel.Result) {
        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authenticationResult: BiometricPrompt.AuthenticationResult
                ) {
                    result.success(true)
                }

                override fun onAuthenticationFailed() {}

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    result.success(false)
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Vault Unlock")
            .setSubtitle("Authenticate to unlock vault")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        try {
            val cipher = initCipher()
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            biometricPrompt.authenticate(promptInfo)
        }
    }

    private fun initCipher(): Cipher {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }

        val cipher = Cipher.getInstance(
            KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_GCM + "/" +
            KeyProperties.ENCRYPTION_PADDING_NONE
        )
        cipher.init(Cipher.ENCRYPT_MODE, keyStore.getKey(KEY_ALIAS, null))
        return cipher
    }

    private fun storeVrk(blob: ByteArray, result: MethodChannel.Result) {
        try {
            val cipher = initCipher()
            val encrypted = cipher.doFinal(blob)
            val iv = cipher.iv

            val file = File(filesDir, "vrk.bin")
            file.writeBytes(iv + encrypted)
            result.success(true)
        } catch (e: Exception) {
            result.error("keystore", "storeVrk failed: ${e.message}", null)
        }
    }

    private fun retrieveVrk(result: MethodChannel.Result) {
        val file = File(filesDir, "vrk.bin")
        if (!file.exists()) {
            result.success(null)
            return
        }

        val data = file.readBytes()
        val iv = data.copyOfRange(0, 12)
        val ct = data.copyOfRange(12, data.size)

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authenticationResult: BiometricPrompt.AuthenticationResult
                ) {
                    try {
                        val crypto = authenticationResult.cryptoObject
                        val cipher = crypto?.cipher
                        if (cipher == null) {
                            result.success(null)
                            return
                        }
                        cipher.init(
                            Cipher.DECRYPT_MODE,
                            KeyStore.getInstance("AndroidKeyStore").getKey(KEY_ALIAS, null),
                            GCMParameterSpec(128, iv)
                        )
                        val vrk = cipher.doFinal(ct)
                        result.success(vrk)
                    } catch (e: Exception) {
                        result.error("keystore", "retrieveVrk decrypt failed: ${e.message}", null)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    result.success(null)
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Vault Unlock")
            .setSubtitle("Authenticate to retrieve vault key")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        try {
            val cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/" +
                KeyProperties.BLOCK_MODE_GCM + "/" +
                KeyProperties.ENCRYPTION_PADDING_NONE
            )
            cipher.init(
                Cipher.DECRYPT_MODE,
                KeyStore.getInstance("AndroidKeyStore").getKey(KEY_ALIAS, null),
                GCMParameterSpec(128, iv)
            )
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            result.error("keystore", "retrieveVrk init failed: ${e.message}", null)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        blePlugin?.dispose()
    }
}