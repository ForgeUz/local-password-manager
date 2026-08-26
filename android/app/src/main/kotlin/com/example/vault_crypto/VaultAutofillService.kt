// File: android/app/src/main/kotlin/com/example/vault_crypto/VaultAutofillService.kt
// Intent: Android Autofill Service integration.
// Invariants:
// - Extracts domain from trusted AssistStructure.webDomain.
// - NEVER passes credentials via Intent extras (P0-2 Binder hole closed).
// - Delegates state to AutofillSession singleton to survive Activity launch.
// Dependencies: AutofillService, AutofillSession, AssistStructure.

package com.example.vault_crypto

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId

class VaultAutofillService : AutofillService() {

    companion object {
        const val EXTRA_ACTION = "com.example.vault_crypto.EXTRA_ACTION"
        const val ACTION_AUTOFILL_AUTH = "com.example.vault_crypto.ACTION_AUTOFILL_AUTH"
        const val ACTION_AUTOFILL_SAVE = "com.example.vault_crypto.ACTION_AUTOFILL_SAVE"
        const val EXTRA_DOMAIN = "com.example.vault_crypto.EXTRA_DOMAIN"
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }

        val domain = extractDomain(structure)
        val fields = parseAutofillFields(structure)

        if (fields.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        // Delegate state to singleton to survive Activity launch.
        // This prevents Binder transit of credentials later.
        AutofillSession.initSession(callback, fields)

        cancellationSignal.setOnCancelListener {
            AutofillSession.destroySession()
        }

        // Launch MainActivity for vault unlock + tier decision.
        // ONLY pass the domain. NO credentials.
        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra(EXTRA_ACTION, ACTION_AUTOFILL_AUTH)
            putExtra(EXTRA_DOMAIN, domain ?: "")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val domain = structure?.let { extractDomain(it) } ?: ""

        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra(EXTRA_ACTION, ACTION_AUTOFILL_SAVE)
            putExtra(EXTRA_DOMAIN, domain)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
        callback.onSuccess()
    }

    private fun extractDomain(structure: AssistStructure): String? {
        var domain: String? = null
        fun traverse(node: AssistStructure.ViewNode) {
            val webDomain = node.webDomain
            if (!webDomain.isNullOrEmpty() && domain == null) domain = webDomain
            for (i in 0 until node.childCount) traverse(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
            if (domain != null) break
        }
        return domain
    }

    private fun parseAutofillFields(structure: AssistStructure): Map<AutofillId, Boolean> {
        val result = mutableMapOf<AutofillId, Boolean>()
        fun traverse(node: AssistStructure.ViewNode) {
            if (result.size >= 20) return
            val id = node.autofillId
            val hints = node.autofillHints ?: emptyArray()
            val relevant = hints.any {
                it == android.view.View.AUTOFILL_HINT_USERNAME ||
                it == android.view.View.AUTOFILL_HINT_PASSWORD ||
                it == "newUsername" || it == "newPassword"
            }
            if (id != null && relevant) {
                val isPwd = hints.contains(android.view.View.AUTOFILL_HINT_PASSWORD) || 
                            hints.contains("newPassword")
                result[id] = isPwd
            }
            for (i in 0 until node.childCount) traverse(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
        }
        return result
    }

    override fun onConnected() {}
    override fun onDisconnected() {
        AutofillSession.destroySession()
    }
}