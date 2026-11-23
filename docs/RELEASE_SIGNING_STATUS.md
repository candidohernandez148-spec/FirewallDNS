# Estado de firma de APK — FirewallDNS

Este documento deja constancia del estado y de la política para firmar la APK de FirewallDNS.

## Decisión

- La firma de Release se realizará en GitHub Actions.
- La misma identidad de firma debe utilizarse para la APK única de FirewallDNS.
- La llave privada JKS y sus contraseñas **nunca deben guardarse en este repositorio**, en commits, en archivos descargables públicos ni en cachés de Actions.
- GitHub Actions debe recibir el material privado únicamente mediante GitHub Actions repository secrets.

## Secrets necesarios

Configurar en **Settings → Secrets and variables → Actions**:

- `KEYSTORE_BASE64`: contenido Base64 del archivo JKS de publicación.
- `KEYSTORE_PASSWORD`: contraseña del almacén.
- `KEY_ALIAS`: alias de la clave.
- `KEY_PASSWORD`: contraseña de la clave privada; puede omitirse si coincide con `KEYSTORE_PASSWORD`, según el workflow.

## Automatización

El workflow de Release de `main` prepara la llave desde los secrets, compila la APK Release, verifica la firma y publica el artefacto cuando la configuración es válida. Si faltan los secrets, el flujo omite intencionalmente la firma/publicación de Release; no genera ni sustituye automáticamente una identidad de firma.

FirewallDNS se publica como una única APK firmada.

## Estado operativo

La automatización del repositorio está preparada, pero la firma Release no se considera completada hasta que los secrets estén configurados y una ejecución de GitHub Actions confirme:

1. Preparación de la firma completada.
2. Compilación de la APK Release completada.
3. Verificación de la firma de la APK esperada.
4. Publicación de los artefactos completada.

La conexión de GitHub utilizada para mantener el repositorio no dispone de una operación autorizada para crear o escribir repository secrets. Por seguridad, ese último paso debe realizarse desde la interfaz de GitHub por una persona con permisos de administración. No pegar contraseñas ni archivos JKS en issues, commits, chats o registros de Actions.

## Enlaces

- [Secrets de Actions](https://github.com/candidohernandez148-spec/FirewallDNS/settings/secrets/actions)
- [Workflow de Actions](https://github.com/candidohernandez148-spec/FirewallDNS/actions)
- [Guía de firma de FirewallDNS](./SHARED_APK_SIGNING.md)
