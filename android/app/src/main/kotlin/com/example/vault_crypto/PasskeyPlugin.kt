// File: android/app/src/main/kotlin/com/example/vault_crypto/PasskeyPlugin.kt
// Intent: P3 FIDO2/WebAuthn bridge via Android 14+ CredentialManager.
// Invariants:
// - Private keys NEVER leave the hardware-backed Keystore.
// - Core only stores opaque credentialId (bytes).
// - rpId isolation enforced by Android OS and FIDO2 protocol.
// Dependencies: androidx.credentials, ActivityAware, kotlinx.coroutines.

package com.example.vault_crypto

import android.app.Activity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetPublicKeyCredentialRequest
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

class PasskeyPlugin : FlutterPlugin, MethodChannel.MethodCallHandler, ActivityAware {
    private var channel: MethodChannel? = null
    private var activity: Activity? = null
    private var credentialManager: CredentialManager? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "vault_crypto/passkey")
        channel?.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        credentialManager = CredentialManager.create(binding.activity)
    }

    override fun onDetachedFromActivityForConfigChanges() { activity = null }
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        credentialManager = CredentialManager.create(binding.activity)
    }
    override fun onDetachedFromActivity() { activity = null }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "createPasskey" -> handleCreate(call, result)
            "getPasskey" -> handleGet(call, result)
            else -> result.notImplemented()
        }
    }

    private fun handleCreate(call: MethodCall, result: MethodChannel.Result) {
        val act = activity ?: run { result.error("NO_ACTIVITY", "Activity not attached", null); return }
        val cm = credentialManager ?: run { result.error("NO_CM", "CredentialManager unavailable", null); return }
        
        val rpId = call.argument<String>("rpId") ?: ""
        val rpName = call.argument<String>("rpName") ?: rpId
        val userId = call.argument<String>("userId") ?: "" // base64url
        val userName = call.argument<String>("userName") ?: ""
        val challenge = call.argument<String>("challenge") ?: "" // base64url

        // Build WebAuthn Level 2/3 PublicKeyCredentialCreationOptions JSON
        val json = JSONObject().apply {
            put("challenge", challenge)
            put("rp", JSONObject().put("name", rpName).put("id", rpId))
            put("user", JSONObject().put("id", userId).put("name", userName).put("displayName", userName))
            put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7))) // ES256
            put("authenticatorSelection", JSONObject()
                .put("authenticatorAttachment", "platform")
                .put("userVerification", "required")
                .put("residentKey", "required"))
            put("attestation", "none")
        }

        val request = CreatePublicKeyCredentialRequest(json.toString())
        
        CoroutineScope(Dispatchers.Main).launch {
            try {
                val response = cm.createCredential(act, request)
                val responseJson = JSONObject(response.credential.data)
                // "id" in the response JSON is the base64url encoded credential ID
                val rawId = responseJson.getString("id")
                result.success(rawId)
            } catch (e: Exception) {
                result.error("CREATE_FAILED", e.message, null)
            }
        }
    }

    private fun handleGet(call: MethodCall, result: MethodChannel.Result) {
        val act = activity ?: run { result.error("NO_ACTIVITY", "Activity not attached", null); return }
        val cm = credentialManager ?: run { result.error("NO_CM", "CredentialManager unavailable", null); return }
        
        val rpId = call.argument<String>("rpId") ?: ""
        val challenge = call.argument<String>("challenge") ?: "" // base64url
        val allowedCredentials = call.argument<List<String>>("allowedCredentials") ?: emptyList() // list of base64url credIds

        // Build WebAuthn Level 2/3 PublicKeyCredentialRequestOptions JSON
        val allowCredsArray = JSONArray()
        for (credId in allowedCredentials) {
            allowCredsArray.put(JSONObject()
                .put("type", "public-key")
                .put("id", credId))
        }

        val json = JSONObject().apply {
            put("challenge", challenge)
            put("rpId", rpId)
            put("allowCredentials", allowCredsArray)
            put("userVerification", "required")
        }

        val request = GetPublicKeyCredentialRequest(json.toString())

        CoroutineScope(Dispatchers.Main).launch {
            try {
                val response = cm.getCredential(act, request)
                val responseJson = JSONObject(response.credential.data)
                val usedCredId = responseJson.getString("id")
                val signature = responseJson.getJSONObject("response").optString("signature", "")
                val authenticatorData = responseJson.getJSONObject("response").optString("authenticatorData", "")
                val clientDataJSON = responseJson.getJSONObject("response").optString("clientDataJSON", "")
                
                result.success(mapOf(
                    "credentialId" to usedCredId,
                    "signature" to signature,
                    "authenticatorData" to authenticatorData,
                    "clientDataJSON" to clientDataJSON
                ))
            } catch (e: Exception) {
                result.error("GET_FAILED", e.message, null)
            }
        }
    }
}
