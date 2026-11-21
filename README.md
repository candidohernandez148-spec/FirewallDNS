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
    * Se elimina la dependencia del motor VPN externo.
    * Se conserva un único servicio Android `VpnService` con interfaz TUN: `DnsFirewallService`.
    * En esta etapa el TUN procesa consultas DNS; el procesamiento general de TCP/UDP queda pendiente de integrar y validar con `FirewallDNS-Engine` en Rust.
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

## Diagnóstico integral del motor

El módulo `:diagnostic-app` genera un segundo APK llamado **FirewallDNS Diagnostic**. Instala los dos APK incluidos en el mismo artefacto de GitHub Actions:

1. Instala o actualiza **Firewall DNS**.
2. Instala **FirewallDNS Diagnostic** del mismo artefacto de compilación.
3. Abre Firewall DNS y activa la protección.
4. Abre FirewallDNS Diagnostic y pulsa **EJECUTAR DIAGNÓSTICO COMPLETO**.
5. Exporta el ZIP generado y comparte el informe para revisar los resultados.

La aplicación de diagnóstico no crea otra VPN. Lee únicamente contadores agregados mediante un proveedor protegido por permiso de firma. Los resultados distinguen **APROBADO**, **FALLIDO** y **NO VERIFICADO**. Consulta [docs/DIAGNOSTIC_APP.md](docs/DIAGNOSTIC_APP.md) para conocer el alcance y las limitaciones de cada prueba.
