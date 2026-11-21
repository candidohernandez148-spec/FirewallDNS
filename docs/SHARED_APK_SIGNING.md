# Shared signing for FirewallDNS APKs

The main APK and diagnostic APK use a signature-protected ContentProvider. They must be signed by the same certificate.

## Local release builds

Use one JKS file for both modules. Do not commit it or its passwords.

```bash
export KEYSTORE_PATH="$HOME/.keys/firewalldns-release.jks"
export KEYSTORE_PASSWORD='...'
export KEY_ALIAS='firewalldns'
export KEY_PASSWORD="$KEYSTORE_PASSWORD" # or the distinct key password
./gradlew :app:assembleRelease :diagnostic-app:assembleRelease
```

If the variables or keystore are missing, release configuration intentionally fails. Debug variants continue to use the standard Android debug signing configuration; both modules built under the same developer account normally share that debug keystore.

## GitHub Actions secrets

The release workflow first restores the legacy Actions cache `firewalldns-signing-v1`, which contains the exact JKS/password/alias used by previous published APKs. It uses restore-only mode and never generates a replacement key. This preserves upgrade compatibility when that cache is available.

For a new or explicitly managed signing identity, configure repository Actions secrets:
- `KEYSTORE_BASE64`: base64 encoding of the same JKS.
- `KEYSTORE_PASSWORD`: JKS store password.
- `KEY_ALIAS`: alias.
- `KEY_PASSWORD`: private-key password (optional if equal to store password).

If neither the legacy cache nor a complete supplied JKS is available, Release fails closed. It never falls back to a debug or randomly generated certificate. CI verifies the APK signatures with `apksigner` and compares the SHA-256 certificate digests before uploading artifacts.

## Provider access

The diagnostic manifest declares the provider authority in `<queries>` for Android 11+ package visibility and requests the signature permission. Package visibility does not bypass signature permission enforcement. Install both release APKs signed with this same JKS; reinstall both if the signing identity changes.
