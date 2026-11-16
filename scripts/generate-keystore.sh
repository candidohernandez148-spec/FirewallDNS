#!/usr/bin/env bash
# Genera una clave de firma permanente y la sube como secretos de GitHub.
# Requiere: keytool y gh (con permiso para escribir secretos). Guarda el .jks en un lugar seguro.
set -Eeuo pipefail

PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
OUT="${1:-firewalldns-release.jks}"

keytool -genkeypair -keystore "$OUT" -alias firewalldns -keyalg RSA -keysize 4096 \
  -validity 36500 -storepass "$PASS" -keypass "$PASS" -dname "CN=Candido y Elizabeth, O=FirewallDNS"

base64 -w0 "$OUT" | gh secret set KEYSTORE_BASE64
printf %s "$PASS" | gh secret set KEYSTORE_PASSWORD
printf %s firewalldns | gh secret set KEY_ALIAS

echo "Listo. Guarda $OUT y esta contraseña (no se vuelve a mostrar): $PASS"
