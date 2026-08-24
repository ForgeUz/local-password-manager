package com.example.vault_crypto

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec

/**
 * Vault Crypto Autofill Service.
 *
 * Architecture:
 * - Android calls onFillRequest with the app's AssistStructure.
 * - We parse the structure to find the requesting domain + autofill fields.
 * - We launch MainActivity (Flutter) for vault unlock + tier decision.
 * - MainActivity returns credentials via Intent extras (encrypted in transit
 *   by Android's autofill binder; additionally we minimize exposure).
 * - We build a Dataset and return it via FillCallback.
 *
 * Security notes:
 * - We extract the domain from AssistStructure.webDomain (trusted source),
 *   NOT from the page title or any editable field.
 * - We never log credential values.
 * - Tier enforcement (critical = manual only) is decided by Dart-side
 *   TierAutofillEnforcer; this service relays the decision.
 */
class VaultAutofillService : AutofillService() {

    companion object {
        // Request code for launching Flutter auth activity
        private const val AUTH_REQUEST_CODE = 1001

        // Intent extra keys for round-trip with MainActivity
        const val EXTRA_DOMAIN = "com.example.vault_crypto.EXTRA_DOMAIN"
        const val EXTRA_ACTION = "com.example.vault_crypto.EXTRA_ACTION"
        const val ACTION_AUTOFILL_AUTH = "com.example.vault_crypto.ACTION_AUTOFILL_AUTH"

        // Max number of autofill fields we track per structure
        private const val MAX_AUTOFILL_FIELDS = 20
    }

    // Pending fill callback (held while Flutter auth activity runs)
    private var pendingCallback: FillCallback? = null
    private var pendingFields: MutableMap<AutofillId, FieldInfo> = mutableMapOf()

    /** Metadata about an autofill field found in the AssistStructure. */
    private data class FieldInfo(
        val autofillId: AutofillId,
        val hints: Array<String>,
        val isPasswordField: Boolean
    )

    /**
     * Called by Android when an app requests autofill.
     */
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        // Get the latest AssistStructure (the app being autofilled)
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }

        // Extract the requesting domain (trusted source: webDomain)
        val domain = extractDomain(structure)
        if (domain.isNullOrEmpty()) {
            // No web domain (native app without web origin) — allow but
            // mark for package-name based matching in Dart.
            // For now, proceed with empty domain; Dart decides.
        }

        // Collect autofill-relevant fields (username + password)
        pendingFields.clear()
        parseAutofillFields(structure)

        if (pendingFields.isEmpty()) {
            // No fillable fields found
            callback.onSuccess(null)
            return
        }

        // Hold the callback while we launch Flutter for auth + tier decision.
        // CancellationSignal lets Android abort if user navigates away.
        pendingCallback = callback
        cancellationSignal.setOnCancelListener {
            pendingCallback = null
        }

        // Launch MainActivity for vault unlock + tier enforcement.
        // MainActivity will call back with credentials or a block decision.
        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra(EXTRA_ACTION, ACTION_AUTOFILL_AUTH)
            putExtra(EXTRA_DOMAIN, domain ?: "")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
    }

    /**
     * Called by MainActivity (Flutter) after auth + tier decision.
     * This is invoked via a bound service call or broadcast.
     *
     * [decision] is the serialized AutofillDecision from Dart.
     * [username] / [password] are only non-null if decision allows release.
     */
    fun onAutofillAuthResult(
        decision: String,       // "fill" | "fill_after_reauth" | "block_manual" | "block_mismatch" | "hardstop_lookalike"
        username: String?,
        password: String?
    ) {
        val callback = pendingCallback ?: return
        pendingCallback = null

        when (decision) {
            "fill", "fill_after_reauth" -> {
                // Tier allows autofill — build dataset with credentials
                if (username != null && password != null) {
                    val response = buildFillResponse(username, password)
                    callback.onSuccess(response)
                } else {
                    callback.onSuccess(null)
                }
            }
            else -> {
                // block_manual, block_mismatch, hardstop_lookalike
                // -> offer NO dataset. User must type manually.
                // This is the hard-stop enforcement for critical tier
                // and phishing protection.
                callback.onSuccess(null)
            }
        }

        // Clear sensitive locals (best-effort; Kotlin strings not zeroable
        // but we drop references immediately)
        pendingFields.clear()
    }

    /**
     * Build a FillResponse containing one Dataset with username + password.
     */
    private fun buildFillResponse(username: String, password: String): FillResponse {
        val builder = FillResponse.Builder()

        // Build a single dataset covering all collected fields
        val datasetBuilder = Dataset.Builder()

        for ((autofillId, fieldInfo) in pendingFields) {
            val value = if (fieldInfo.isPasswordField) password else username

            // Presentation shown in the autofill picker
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, "Vault Crypto")
            }

            datasetBuilder.setValue(
                autofillId,
                AutofillValue.forText(value),
                presentation
            )
        }

        builder.addDataset(datasetBuilder.build())

        // Note: setIgnoredIds accepts vararg AutofillId. Since we don't need to 
        // ignore any specific IDs, we can simply omit calling this method.

        return builder.build()
    }

    /**
     * Called by Android when an app wants to save updated credentials.
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Saving new/updated credentials back to the vault.
        // Launch MainActivity to confirm + encrypt + store.
        val structure = request.fillContexts.lastOrNull()?.structure
        val domain = structure?.let { extractDomain(it) } ?: ""

        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra(EXTRA_ACTION, "com.example.vault_crypto.ACTION_SAVE")
            putExtra(EXTRA_DOMAIN, domain)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)

        // Save completion signaled by MainActivity later.
        callback.onSuccess()
    }

    /**
     * Extract the web domain from the AssistStructure.
     * Uses webDomain (trusted) from WINDOW_NODE with a WebView.
     * Falls back to null for native-only apps.
     */
    private fun extractDomain(structure: AssistStructure): String? {
        var domain: String? = null

        fun traverse(node: AssistStructure.ViewNode) {
            // webDomain is the trusted origin for web content
            val webDomain = node.webDomain
            if (!webDomain.isNullOrEmpty() && domain == null) {
                domain = webDomain
            }
            for (i in 0 until node.childCount) {
                traverse(node.getChildAt(i))
            }
        }

        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
            if (domain != null) break
        }

        return domain
    }

    /**
     * Walk the AssistStructure and collect username/password fields.
     * Identifies fields via autofill hints + inputType password flags.
     */
    private fun parseAutofillFields(structure: AssistStructure) {
        fun traverse(node: AssistStructure.ViewNode) {
            if (pendingFields.size >= MAX_AUTOFILL_FIELDS) return

            val autofillId = node.autofillId
            if (autofillId != null && node.autofillHints != null) {
                val hints = node.autofillHints ?: emptyArray()
                val isPassword = isPasswordField(node)

                // Only track fields that Android marked autofillable
                // We use hardcoded strings for "newUsername" and "newPassword" because
                // View.AUTOFILL_HINT_NEW_USERNAME was added in API 26/28 and might cause
                // unresolved reference errors depending on compile SDK and import context.
                val relevant = hints.any {
                    it == android.view.View.AUTOFILL_HINT_USERNAME ||
                    it == android.view.View.AUTOFILL_HINT_PASSWORD ||
                    it == android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS ||
                    it == "newUsername" ||
                    it == "newPassword"
                }

                if (relevant) {
                    pendingFields[autofillId] = FieldInfo(
                        autofillId = autofillId,
                        hints = hints,
                        isPasswordField = isPassword
                    )
                }
            }

            for (i in 0 until node.childCount) {
                traverse(node.getChildAt(i))
            }
        }

        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
        }
    }

    /** Determine if a node is a password field via inputType. */
    private fun isPasswordField(node: AssistStructure.ViewNode): Boolean {
        val inputType = node.inputType
        return (inputType and android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0 ||
               (inputType and android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) != 0 ||
               (inputType and android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD) != 0
    }

    override fun onConnected() {
        // Service connected to autofill framework
    }

    override fun onDisconnected() {
        pendingCallback = null
        pendingFields.clear()
    }
}