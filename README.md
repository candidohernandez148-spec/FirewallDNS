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

Aplicación Android de **firewall local y filtrado DNS sin permisos root**, construida en Kotlin con Jetpack Compose (Material 3) y arquitectura **MVVM**. Permite supervisar en tiempo real las consultas DNS de cada aplicación, aplicar listas estándar Adblock (`||dominio.com^`) y bloquear o excluir aplicaciones individuales directamente desde el dispositivo.

---

## ✨ Características principales

* **Arquitectura VPN simplificada:**
    * Se conserva un único servicio Android `VpnService` con interfaz TUN: `DnsFirewallService`.
    * El TUN procesa DNS por UDP y DNS por TCP/53 mediante smoltcp 0.14, con JNI, colas acotadas y un único hilo propietario del transporte.
    * El tráfico TCP/UDP general que no sea DNS/53 sigue fuera del alcance del filtrado; no se afirma inspección de DoH, DoT ni DoQ.
    * No existe un segundo motor VPN ni un servicio de respaldo.
* **Control de aplicaciones (Split Tunneling y bloqueo total):**
  * Aplica reglas DNS por aplicación; el bloqueo general de conexiones TCP/UDP por UID queda pendiente de integrar el motor nativo FirewallDNS.
  * Excluye aplicaciones concretas del filtrado mediante `addDisallowedApplication`.
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
├── service/           # Servicio TUN DNS y utilidades de red (DnsFirewallService, NetworkDns)
├── ui/
│   ├── viewmodel/     # Estado de presentación (FirewallViewModel)
│   ├── screens/       # Pantallas Jetpack Compose (LogsScreen, RulesScreen, AppsSettingsScreen)
│   └── theme/         # Paleta clara/oscura, tipografía y formas (Theme)
└── MainActivity.kt    # Punto de entrada, permisos de red/notificaciones y visor de fallos

## Diagnóstico integrado del motor

El diagnóstico se ejecuta desde la pantalla **Diagnóstico** de FirewallDNS; no requiere instalar una aplicación adicional ni iniciar una segunda VPN. La pantalla consulta métricas del servicio TUN que está funcionando, permite comprobar Rust/JNI y ofrece una prueba DNS/TCP upstream real mediante los mismos sockets protegidos y resolvers configurados. La prueba TCP solo se considera aprobada cuando recibe y valida una respuesta DNS sobre TCP/53; el resultado de `VpnService.protect()` por sí solo no demuestra conectividad.

Desde esa pantalla puedes compartir el informe JSON. Los contadores son acumulativos del proceso/servicio y deben interpretarse junto con el estado de la VPN y el momento de la prueba. Consulta [docs/DIAGNOSTIC_APP.md](docs/DIAGNOSTIC_APP.md) para conocer el alcance y las limitaciones. El antiguo módulo companion queda fuera del flujo y no es necesario instalarlo.
