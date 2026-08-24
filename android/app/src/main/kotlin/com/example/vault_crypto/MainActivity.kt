package com.example.vault_crypto

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * MainActivity for Vault Crypto Flutter app.
 *
 * Intent: Bridge Android platform APIs to Flutter via MethodChannels.
 * Handles: clipboard (sensitive MIME), biometric Keystore, BLE plugin registration.
 *
 * Invariants:
 * - Clipboard with sensitive=true uses EXTRA_IS_SENSITIVE (Android 13+)
 * - Biometric key invalidated on new fingerprint enrollment
 * - VRK never stored in plaintext (encrypted under Keystore key)
 * - BLE plugin registered as MethodCallHandler (not FlutterActivity)
 *
 * Dependencies: AndroidKeyStore, BiometricPrompt, Nearby Connections (via plugin)
 */
class MainActivity : FlutterActivity() {
    private val CLIPBOARD_CHANNEL = "vault_crypto/clipboard"
    private val BIOMETRIC_CHANNEL = "vault_crypto/biometric"
    private val KEY_ALIAS = "vault_biometric_key"

    private var blePlugin: BleTransportPlugin? = null

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
    }

    /**
     * Copy text to clipboard with optional sensitive flag.
     * Android 13+ (API 33): EXTRA_IS_SENSITIVE prevents UI preview.
     */
    private fun copyToClipboard(text: String, sensitive: Boolean) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("vault", text)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && sensitive) {
            val extras = Bundle()
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            clip.description.extras = extras
        }

        clipboard.setPrimaryClip(clip)
    }

    /**
     * Clear clipboard by setting empty content.
     */
    private fun clearClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
    }

    /**
     * Authenticate user via biometric prompt.
     * Returns true on success, false on cancel/error.
     */
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

                override fun onAuthenticationFailed() {
                    // Do not return false immediately, user might retry
                }

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
            // Fallback if key is invalidated or unavailable
            biometricPrompt.authenticate(promptInfo)
        }
    }

    /**
     * Initialize AES-GCM cipher with AndroidKeyStore key.
     * Key invalidated on new biometric enrollment (security).
     */
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

    /**
     * Store wrapped VRK in Keystore-encrypted file.
     * VRK never stored in plaintext.
     */
    private fun storeVrk(blob: ByteArray, result: MethodChannel.Result) {
        try {
            val cipher = initCipher()
            val encrypted = cipher.doFinal(blob)
            val iv = cipher.iv

            // Persist iv + ciphertext to app-private storage
            val file = File(filesDir, "vrk.bin")
            file.writeBytes(iv + encrypted)
            result.success(true)
        } catch (e: Exception) {
            result.error("keystore", "storeVrk failed: ${e.message}", null)
        }
    }

    /**
     * Retrieve wrapped VRK with biometric-gated decryption.
     * Returns VRK bytes or null if absent/failed.
     */
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
