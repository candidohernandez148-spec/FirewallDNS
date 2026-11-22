<div align="center">
  <img src="docs/logo.svg" width="115" height="115" alt="Logo Firewall DNS" />
  <h1>Firewall DNS</h1>
  <p><strong>Firewall local y filtro DNS sin root para Android</strong></p>

  ![Platform](https://img.shields.io/badge/Android-7.0%2B%20(API%2024%2B)-3DDC84?logo=android&logoColor=white)
  ![Kotlin](https://img.shields.io/badge/Kotlin-2.1-7F52FF?logo=kotlin&logoColor=white)
  ![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white)
  ![Architecture](https://img.shields.io/badge/Architecture-MVVM-informational)
</div>

---

Aplicación Android de **firewall virtual local sin permisos root**, construida en Kotlin con Jetpack Compose (Material 3) y arquitectura **MVVM**. Un único `VpnService`/TUN entrega el tráfico IPv4/IPv6 a Firestack/gVisor; FirewallDNS aplica su propia política de conexiones y dominios, con DNS filtrado, control por aplicación y telemetría local.

---

## ✨ Características principales

* **Motor virtual de red TCP/UDP sobre TUN:**
    * Un solo `VpnService` y un solo descriptor TUN, administrado por `DnsFirewallService`.
    * Firestack/gVisor procesa conexiones TCP, UDP e ICMP IPv4/IPv6; smoltcp/Rust se conserva como componente nativo de DNS/TCP y banco de pruebas, no como una segunda pila que compita por el TUN.
    * Los callbacks de Firestack se conectan a la política única de FirewallDNS para bloquear, observar o permitir conexiones por UID, aplicación, protocolo, IP/CIDR y puerto.
    * Los sockets de salida se protegen contra bucles VPN y se enlazan a la red física seleccionada. Los cambios Wi-Fi/datos móviles actualizan resolvers y MTU sin reiniciar el TUN.
* **Filtrado DNS y protección de amenazas:**
    * Captura de DNS UDP/TCP por puerto 53 para aplicar listas, reglas propias y ThreatAnalyzer incluso cuando una aplicación consulta un resolver codificado.
    * DNS bloqueado se responde mediante el transporte `BlockAll` de Firestack; los flujos de red bloqueados utilizan su proxy `Block`.
    * DoT/DoQ se bloquean en puertos estándar configurados. DoH solo se identifica por correlación con dominios de endpoints conocidos; **no se descifra TLS ni se afirma inspección universal de DoH/DoT/DoQ**.
* **Control de aplicaciones y conexiones:**
    * UID de Firestack y, cuando no está disponible, intento de atribución mediante `ConnectivityManager.getConnectionOwnerUid` en Android 10+.
    * Reglas de flujo por UID, paquete, protocolo, dirección/rango IPv4/IPv6 y puerto; las reglas heurísticas solo pueden observar, nunca bloquear por sí solas.
    * Monitor de conexiones con bytes enviados/recibidos, motivo de decisión y generación de red.
* **Listas Adblock externas y reglas personalizadas:**
  * Compatible con sintaxis estándar Adblock DNS (`||dominio.com^` y excepciones `@@||dominio.com^`), con presets recomendados de **HaGeZi** (Ligera, Estándar y Avanzada) y soporte para añadir URLs externas sin recompilar.
  * Reglas manuales de **Lista Blanca** y **Lista Negra** con prioridad sobre las listas descargadas, y botones rápidos de *Permitir/Bloquear* desde el historial en vivo.
* **Protección inteligente determinista:**
  * Evaluación en tiempo real con indicadores integrados y curados de publicidad, rastreo y analítica, además de listas descargadas y reglas personalizadas.
  * Las decisiones son explicables y no se modifican por historial de actividad: no hay aprendizaje persistente, entrenamiento local ni perfiles construidos a partir del tráfico.
* **Interfaz moderna y monitoreo en vivo:**
  * Gráfica de tráfico en tiempo real (`TrafficChart`), métricas de bloqueo, ranking de dominios más bloqueados, buscador por dominio o aplicación y detección de conflicto cuando otra VPN del sistema está activa.
  * Soporte automático para tema claro y oscuro (`Material 3`).

---

## 🏗️ Arquitectura del proyecto (MVVM + motor modular)

El proyecto separa la política y la pila de red en módulos Gradle:

- `:engine-core`: normalización, reglas DNS y reglas de flujo TCP/UDP/ICMP.
- `:dns-engine`: análisis y evaluación DNS.
- `:threat-engine`: inteligencia de amenazas y señales deterministas.
- `:engine-monitor`: métricas y ciclo de vida de conexiones.
- `:engine-runtime`: autoridad de política y composición del motor.
- `:android-adapter`: puente Android/Firestack, protección de sockets y conexión con TUN.
- `:app`: interfaz, repositorio, permisos y ciclo de vida de `VpnService`.

El proyecto de aplicación conserva esta estructura MVVM:

```text
app/src/main/java/com/firewall/dns/
├── domain/
│   ├── model/         # Modelos de dominio (FirewallStats, DnsLogEntry, TrafficPoint, AppInfoItem)
│   └── engine/        # Lógica pura (DnsPacketEngine, RuleEvaluator, SmartDomainAnalyzer, DomainBlocker, AppFirewallManager)
├── data/
│   ├── local/         # Persistencia y fuentes de datos (PreferencesDataSource, BlocklistDataSource)
│   └── repository/    # Fuente única de verdad reactiva con StateFlow (FirewallRepository)
├── service/           # Servicio TUN DNS y utilidades de red (DnsFirewallService, NetworkDns)
├── ui/
│   ├── viewmodel/     # Estado de presentación (FirewallViewModel)
│   ├── screens/       # Pantallas Jetpack Compose (LogsScreen, RulesScreen, AppsSettingsScreen)
│   └── theme/         # Paleta clara/oscura, tipografía y formas (Theme)
└── MainActivity.kt    # Punto de entrada, permisos de red/notificaciones y visor de fallos

## Diagnóstico integrado del motor

El diagnóstico se ejecuta desde la pantalla **Diagnóstico** de FirewallDNS; no requiere instalar una aplicación adicional ni iniciar una segunda VPN. La pantalla consulta métricas del servicio TUN que está funcionando, permite comprobar Rust/JNI y ofrece una prueba DNS/TCP upstream real mediante los mismos sockets protegidos y resolvers configurados. La prueba TCP solo se considera aprobada cuando recibe y valida una respuesta DNS sobre TCP/53; el resultado de `VpnService.protect()` por sí solo no demuestra conectividad.

Desde esa pantalla puedes compartir el informe JSON. Los contadores son acumulativos del proceso/servicio y deben interpretarse junto con el estado de la VPN y el momento de la prueba. Consulta [docs/DIAGNOSTIC_APP.md](docs/DIAGNOSTIC_APP.md) para conocer el alcance y las limitaciones. El antiguo módulo companion queda fuera del flujo y no es necesario instalarlo.
