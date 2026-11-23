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

The release workflow never restores a signing keystore or password from an Actions cache. Private signing material must not be stored in Actions caches because pull-request workflows may be able to restore caches from the base branch.

Configure these repository Actions secrets using the **same JKS and certificate** used for previously distributed APKs:
- `KEYSTORE_BASE64`: base64 encoding of the existing JKS.
- `KEYSTORE_PASSWORD`: JKS store password.
- `KEY_ALIAS`: existing key alias.
- `KEY_PASSWORD`: private-key password (optional if equal to the store password).

Release signing runs only on trusted non-pull-request executions of `main`. Pull requests still run unit tests; the separate Debug workflow builds the test APK without release credentials. If the signing secrets are absent, the signed Release artifact is deliberately skipped; no replacement key is generated and no debug certificate is substituted.

**Repository maintenance:** delete the legacy Actions cache named `firewalldns-signing-v1` from Settings → Actions → Caches. The workflow no longer reads it, but deleting it removes the old private material from the cache store. If there is any reason to believe an untrusted workflow already restored or exposed that cache, treat the signing key as compromised and assess certificate rotation carefully before changing it, because existing app installations require compatible signing to accept updates.

CI verifies the Release APK signature with `apksigner` before uploading it. The diagnostic APK must continue to use the same release certificate because its provider access is signature-protected.

## Provider access

The diagnostic manifest declares the provider authority in `<queries>` for Android 11+ package visibility and requests the signature permission. Package visibility does not bypass signature permission enforcement. Install both release APKs signed with this same JKS; reinstall both if the signing identity changes.
