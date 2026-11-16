# FirewallDNS

[![Build Debug (Firestack desde fuentes)](https://github.com/candidohernandez148-spec/FirewallDNS/actions/workflows/build.yml/badge.svg)](https://github.com/candidohernandez148-spec/FirewallDNS/actions/workflows/build.yml)

Firewall DNS local para Android, creado por Candido y Elizabeth.

Esta app usa un servicio `VpnService` para interceptar y filtrar consultas DNS compatibles, así como aplicar reglas personalizadas, listas externas y exclusiones por aplicación.

## Qué es exactamente

- Es un filtro DNS / firewall de dominios, no un firewall completo de todas las conexiones del sistema.
- Bloquea consultas DNS tradicionales y permite personalizar dominios bloqueados o permitidos.
- El tráfico cifrado como DoH/DoT no se inspecciona de forma fiable en este enfoque.
- La protección se centra en la resolución de nombres y en la gestión de reglas de dominio.

## Límite realista

- No reemplaza un firewall de paquete completo ni bloquea todo el tráfico TCP/UDP del dispositivo.
- La protección se entiende como seguridad DNS y filtrado de dominios.
- Para un control total por aplicación y por puerto, se requeriría un diseño de VPN más avanzado y pruebas de red reales.

## Créditos

- Desarrollo y diseño: Candido y Elizabeth
- Proyecto: FirewallDNS

## Uso recomendado

- Mantén activado solo el filtrado DNS necesario.
- Usa listas externas con cuidado y valida reglas personalizadas.
- Si quieres mayor protección, combina este filtro con políticas de red y controles del sistema.

## Licencia

MIT. Consulta el archivo [LICENSE](LICENSE).

## Instalación y firma del APK

El workflow «Compilar APK» genera `app-release.apk`. La primera vez crea una clave de firma y la guarda en la caché de Actions, así que los siguientes builds se firman con la misma clave y el APK se puede actualizar sin desinstalar. Si la caché se borra (por ejemplo, tras 7 días sin builds), se crea una clave nueva y habrá que desinstalar la app una vez. Para una clave permanente se pueden definir los secretos `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD` y `KEY_ALIAS`, que tienen prioridad.

Aviso: Android pide permitir «instalar apps desconocidas» para cualquier APK instalado fuera de Google Play, y Google Play Protect puede mostrar un aviso a apps de desarrolladores no verificados. Esos avisos solo desaparecen del todo publicando en Google Play (o F-Droid).
