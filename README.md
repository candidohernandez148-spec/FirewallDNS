# 🛡️ Firewall DNS

![Platform](https://img.shields.io/badge/Android-7.0%2B%20(API%2024%2B)-3DDC84?logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/Kotlin-2.1-7F52FF?logo=kotlin&logoColor=white)
![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white)
![Architecture](https://img.shields.io/badge/Architecture-MVVM-informational)

Aplicación Android de **firewall local y filtrado DNS sin permisos root**, construida en Kotlin con Jetpack Compose (Material 3) y arquitectura **MVVM**. Permite supervisar en tiempo real las consultas DNS y conexiones TCP/UDP de cada aplicación, aplicar listas estándar Adblock (`||dominio.com^`) y bloquear o excluir aplicaciones individuales directamente desde el dispositivo.

---

## ✨ Características principales

* **Motor híbrido Firestack + Respaldo DNS clásico:**
  * **Modo principal (`FirewallVpnService` + `Firestack`):** Túnel local IPv4/IPv6 (`gVisor/netstack`) para interceptar y registrar conexiones **TCP/UDP** y consultas **DNS** (`A`, `AAAA`, `HTTPS`, `CNAME`, `TXT`) identificando la aplicación propietaria por UID.
  * **Respaldo automático (`DnsFirewallService`):** Motor DNS ligero en Kotlin puro (`DnsPacketEngine`) que entra en acción automáticamente si el túnel principal no logra iniciar.
  * **Adaptación dinámica de red (`NetworkDns`):** Detecta cambios entre Wi-Fi, datos móviles y Ethernet para usar los servidores DNS de la red física activa.
* **Control de aplicaciones (Split Tunneling y bloqueo total):**
  * Bloquea por completo el acceso a Internet de aplicaciones individuales por UID (`AppFirewallManager`).
  * Excluye aplicaciones concretas del filtrado mediante `addDisallowedApplication`.
* **Listas Adblock externas y reglas personalizadas:**
  * Compatible con sintaxis estándar Adblock DNS (`||dominio.com^` y excepciones `@@||dominio.com^`), con presets recomendados de **HaGeZi** (Ligera, Estándar y Avanzada) y soporte para añadir URLs externas sin recompilar.
  * Reglas manuales de **Lista Blanca** y **Lista Negra** con prioridad sobre las listas descargadas, y botones rápidos de *Permitir/Bloquear* desde el historial en vivo.
* **Protección inteligente local (`SmartDomainAnalyzer`):**
  * Evaluación heurística multi-señal con escudo de dominios esenciales (`CORE_SAFE_HOSTS`) para evitar falsos positivos en chats, videos o inicios de sesión.
  * Aprendizaje ponderado local en el dispositivo basado en las decisiones del usuario, con opción para reiniciar los patrones aprendidos en cualquier momento.
* **Interfaz moderna y monitoreo en vivo:**
  * Gráfica de tráfico en tiempo real (`TrafficChart`), métricas de bloqueo, ranking de dominios más bloqueados, buscador por dominio o aplicación y detección de conflicto cuando otra VPN del sistema está activa.
  * Soporte automático para tema claro y oscuro (`Material 3`).

---

## 🏗️ Arquitectura del proyecto (MVVM)

El proyecto está organizado por capas dentro de `:app`:

```text
app/src/main/java/com/firewall/dns/
├── domain/
│   ├── model/         # Modelos de dominio (FirewallStats, DnsLogEntry, TrafficPoint, AppInfoItem)
│   └── engine/        # Lógica pura (DnsPacketEngine, RuleEvaluator, SmartDomainAnalyzer, DomainBlocker, AppFirewallManager)
├── data/
│   ├── local/         # Persistencia y fuentes de datos (PreferencesDataSource, BlocklistDataSource)
│   └── repository/    # Fuente única de verdad reactiva con StateFlow (FirewallRepository)
├── service/           # Servicios VPN y red (FirewallVpnService, FirestackBridge, DnsFirewallService, NetworkDns)
├── ui/
│   ├── viewmodel/     # Estado de presentación (FirewallViewModel)
│   ├── screens/       # Pantallas Jetpack Compose (LogsScreen, RulesScreen, AppsSettingsScreen)
│   └── theme/         # Paleta clara/oscura, tipografía y formas (Theme)
└── MainActivity.kt    # Punto de entrada, permisos de red/notificaciones y visor de fallos
