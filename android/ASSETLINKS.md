# Digital Asset Links — Autofill verification (v5 D.2)

The Android AutofillService (Phase D.2) verifies the requesting app via Digital
Asset Links. This blocks look-alike apps from receiving credentials.

## Hosting (production)

Host `assetlinks.json` at the well-known path on each domain the vault fills:

```
https://<your-domain>/.well-known/assetlinks.json
```

The file must list the app's package name + cert SHA-256 fingerprint:

```json
{
  "include": [
    {
      "relation": ["delegate_permission/common.crypto_autofill"],
      "target": {
        "namespace": "android_app",
        "package_name": "com.example.vault_crypto",
        "sha256_cert_fingerprints": [
          "REPLACE_WITH_YOUR_APP_CERT_SHA256_FINGERPRINT"
        ]
      }
    }
  ]
}
```

Get the fingerprint from the signing cert used for the release build:

```bash
# From the .pem cert used to sign the app
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

## Local testing (no hosted domain)

For development, use the Android "Autofill with Google" test flow:

1. Build + install the app on a device/emulator.
2. In the browser, open a page with `autocomplete="username"` /
   `autocomplete="current-password"` fields.
3. Long-press a field -> "Autofill" -> the vault app appears as a suggestion.
4. Tapping it launches the vault app (LockScreen if locked, else the fill).

The `autofill.xml` in `res/xml/` lists the trusted domains. For local testing,
add `localhost` / the test page origin to `trusted-domains`.

## Zero-trust note

The AutofillService NEVER holds the VRK or credentials. It only returns a
dataset that launches the vault app; the app (holding the unlocked VRK)
performs the actual fill. FLAG_SECURE marks the inline prompt as sensitive.