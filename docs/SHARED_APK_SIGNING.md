# Firma de FirewallDNS

FirewallDNS se distribuye como una única aplicación Android. No existe una APK companion ni una identidad de firma compartida entre aplicaciones.

## Compilación local de Release

No guardes la llave privada ni sus contraseñas en el repositorio.

```bash
export KEYSTORE_PATH="$HOME/.keys/firewalldns-release.jks"
export KEYSTORE_PASSWORD='...'
export KEY_ALIAS='firewalldns'
export KEY_PASSWORD="$KEYSTORE_PASSWORD" # o la contraseña privada distinta
./gradlew :app:assembleRelease
```

Si faltan las variables o el keystore, la configuración de Release falla intencionalmente. Las compilaciones Debug siguen disponibles sin secretos.

## GitHub Actions

Configura estos secretos del repositorio usando la misma identidad de publicación de las versiones distribuidas:

- `KEYSTORE_BASE64`: JKS codificado en Base64.
- `KEYSTORE_PASSWORD`: contraseña del almacén.
- `KEY_ALIAS`: alias existente.
- `KEY_PASSWORD`: contraseña de la clave privada (opcional si coincide con la anterior).

El workflow solo prepara la firma en ejecuciones confiables de `main`. No recupera material privado desde cachés de Actions ni genera una identidad de sustitución. Si faltan secretos, omite el APK Release firmado.

Nunca publiques el JKS ni las contraseñas en commits, issues, informes o registros de Actions.
