<p align="center">
  <img src="docs/logo.svg" alt="FirewallDNS" width="140">
</p>

<h1 align="center">FirewallDNS</h1>

<p align="center">
  Firewall local para Android: filtra dominios y controla el acceso a internet por app, con <a href="https://github.com/celzero/firestack">Firestack</a>.
</p>

<p align="center">
  <a href="https://github.com/candidohernandez148-spec/FirewallDNS/actions/workflows/build.yml"><img src="https://github.com/candidohernandez148-spec/FirewallDNS/actions/workflows/build.yml/badge.svg" alt="Build Debug (Firestack desde fuentes)"></a>
  <img src="https://img.shields.io/badge/Android-8.0%2B-3DDC84?logo=android&logoColor=white" alt="Android 8.0+">
  <img src="https://img.shields.io/badge/Kotlin-Jetpack%20Compose-7F52FF?logo=kotlin&logoColor=white" alt="Kotlin y Compose">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licencia-MIT-blue" alt="Licencia MIT"></a>
</p>

## Características

- **Motor Firestack**: túnel `VpnService` con DNS sobre HTTPS (Cloudflare). Si Firestack no arranca, se usa un filtro DNS clásico como respaldo.
- **Bloqueo por dominio**: listas adblock (`||dominio^`, `@@` excepciones, formato hosts), reglas propias de bloquear/permitir y lista inicial de anuncios y rastreo.
- **Bloqueo por app**: lista de apps instaladas (icono, nombre, UID) con interruptor para permitir o bloquear su acceso a internet, y exclusión de apps del túnel.
- **Protección inteligente**: aprende de la actividad de red y de tus reglas para detectar dominios nuevos de anuncios y rastreo con patrones ya vistos. Todo el aprendizaje es local y se puede reiniciar.
- **Actividad en tiempo real**: gráfica de bloqueados y permitidos, porcentaje de bloqueo, dominios más bloqueados y registro por app con acción rápida de permitir/bloquear.
- **Encendido y apagado fiable**: el interruptor refleja el estado real del túnel y el apagado cierra Firestack y la interfaz VPN en orden.

## Estructura

| Ruta | Contenido |
| --- | --- |
| `app/.../service` | `FirewallVpnService`, `FirestackBridge` y el servicio DNS de respaldo |
| `app/.../domain/engine` | `DomainBlocker`, `AppFirewallManager`, `SmartDomainAnalyzer`, `RuleEvaluator` |
| `app/.../data` | Repositorio, listas y preferencias |
| `app/.../ui` | Pantallas Compose: Actividad, Listas y Apps |

## Compilar

El workflow [`build.yml`](.github/workflows/build.yml) clona Firestack, genera `firestack.aar` con `gomobile` y compila el APK de depuración. Sin `app/libs/firestack.aar`, Gradle usa la dependencia publicada de Firestack.

## Instalación y firma del APK

El workflow «Compilar APK» genera `app-release.apk`. La primera vez crea una clave de firma y la guarda en la caché de Actions, así que los siguientes builds se firman con la misma clave y el APK se puede actualizar sin desinstalar. Si la caché se borra (por ejemplo, tras 7 días sin builds), se crea una clave nueva y habrá que desinstalar la app una vez. Para una clave permanente se pueden definir los secretos `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD` y `KEY_ALIAS`, que tienen prioridad.

Android pide permitir «instalar apps desconocidas» para cualquier APK fuera de Google Play, y Play Protect puede avisar sobre desarrolladores no verificados.

## Alcance y límites

- Filtra por dominio y por app; no es un firewall de paquetes completo.
- El bloqueo por dominio depende de lo que Firestack pueda observar; el tráfico cifrado con DNS propio de una app puede no verse.
- Usa listas externas con cuidado y revisa tus reglas personalizadas.

## Créditos

Desarrollo y diseño: Candido y Elizabeth. Motor de red: [celzero/firestack](https://github.com/celzero/firestack).

## Licencia

MIT. Consulta el archivo [LICENSE](LICENSE).
