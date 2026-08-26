// File: android/app/src/main/kotlin/com/example/vault_crypto/AutofillSession.kt
// Intent: Singleton bridge between VaultAutofillService and MainActivity.
// Invariants:
// - Holds pending FillCallback + AutofillIds across Activity lifecycle.
// - Credentials NEVER transit via Android Binder or Intent extras.
// - State Transition: Service populates -> Activity encrypts/fills -> Service consumes.
// Dependencies: AndroidKeyStore, AutofillService, Dataset.

package com.example.vault_crypto

import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

object AutofillSession {
    private var pendingCallback: FillCallback? = null
    private var pendingFields: Map<AutofillId, Boolean> = emptyMap() // id -> isPassword

    // Service calls this when onFillRequest starts.
    fun initSession(callback: FillCallback, fields: Map<AutofillId, Boolean>) {
        pendingCallback = callback
        pendingFields = fields
    }

    // Activity calls this with plaintext credentials.
    // NO Binder transit involved. Zero exposure.
    fun completeSession(username: String, password: String) {
        val cb = pendingCallback ?: return
        val fields = pendingFields
        
        if (fields.isEmpty()) {
            cb.onSuccess(null)
            destroySession()
            return
        }

        try {
            val builder = Dataset.Builder()
            val presentation = RemoteViews("com.example.vault_crypto", android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, "Vault Crypto")
            }

            for ((id, isPwd) in fields) {
                val value = if (isPwd) password else username
                builder.setValue(id, AutofillValue.forText(value), presentation)
            }
            cb.onSuccess(builder.build())
        } catch (e: Exception) {
            cb.onSuccess(null) // Fail closed on UI build error
        } finally {
            destroySession()
        }
    }

    // Activity calls this if user cancels or tier blocks autofill.
    fun cancelSession() {
        pendingCallback?.onSuccess(null)
        destroySession()
    }

    fun destroySession() {
        pendingCallback = null
        pendingFields = emptyMap()
    }
}