<p align="center">
  <img src="docs/logo.svg" alt="FirewallDNS" width="140">
</p>

<h1 align="center">FirewallDNS</h1>

<p align="center">
  Firewall local para Android que permite filtrar dominios y controlar el acceso a Internet por aplicación.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Android-8.0%2B-3DDC84?logo=android&logoColor=white" alt="Android 8.0 o superior">
  <img src="https://img.shields.io/badge/Kotlin-Jetpack%20Compose-7F52FF?logo=kotlin&logoColor=white" alt="Kotlin y Jetpack Compose">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licencia-MIT-blue" alt="Licencia MIT"></a>
</p>

FirewallDNS utiliza el servicio VPN de Android para filtrar conexiones localmente. Su motor de red se basa en [Firestack](https://github.com/celzero/firestack).

## Características

- **Filtrado de dominios:** admite listas de bloqueo, excepciones y formato hosts, además de reglas personalizadas para permitir o bloquear dominios.
- **Control por aplicación:** consulta las aplicaciones instaladas y configura su acceso a Internet desde la aplicación.
- **Protección inteligente:** analiza localmente la actividad y las reglas para ayudar a identificar dominios de anuncios y rastreo.
- **Actividad de red:** muestra estadísticas de conexiones permitidas y bloqueadas, dominios frecuentes y actividad por aplicación.
- **DNS de respaldo:** incluye un filtro DNS alternativo si Firestack no puede iniciarse.
- **VPN local:** utiliza `VpnService` de Android. No requiere configurar un servidor VPN remoto.

## Requisitos

- Android 8.0 (API 24) o superior.
- Para compilar: JDK 17 y Android SDK compatible con el proyecto.

## Compilación

Clona el repositorio:

```bash
git clone https://github.com/candidohernandez148-spec/FirewallDNS.git
cd FirewallDNS