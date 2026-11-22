# Plan de integración del motor de red de FirewallDNS

## Objetivo

Completar FirewallDNS como un firewall virtual Android sobre un único `VpnService` y una única interfaz TUN. El motor propio debe poder recibir, clasificar, decidir y reenviar tráfico IPv4/IPv6 TCP y UDP, además de aplicar la política DNS y de amenazas ya existente.

La integración debe conservar el filtrado DNS que ya funciona en Wi-Fi y datos móviles. Ningún componente nuevo sustituye al servicio VPN actual ni crea una segunda VPN.

## Referencias técnicas fijadas

- Firestack: `https://github.com/celzero/firestack`
- Revisión de código estudiada: `c27887056230769ee897b7c7b92976b96d3c9a6d`
- Firestack usa gVisor/netstack para TCP/UDP sobre TUN y expone `intra.Connect(fd, linkmtu, tunmtu, ifaddrs, fakedns, defaultDNS, bridge)`.
- Rethink app: `https://github.com/celzero/rethink-app`, especialmente `GoVpnAdapter.kt` y `BraveVPNService.kt`, como referencia de integración Android.
- gVisor networking guide: `https://gvisor.dev/docs/architecture_guide/networking/`
- smoltcp actual de FirewallDNS: se conserva para pruebas nativas y se evalúa su uso especializado; no se mantendrán dos pilas TCP de producción compitiendo por los mismos paquetes.

## Arquitectura objetivo

1. **Android VPN host**: `DnsFirewallService` conserva la propiedad del descriptor TUN, el ciclo de vida, las rutas, la notificación y el permiso VPN.
2. **Adaptador de pila**: una interfaz interna `PacketStack` permite iniciar, detener y consultar estadísticas del motor. Firestack/gVisor será el candidato principal para la pila TCP/UDP general.
3. **Política FirewallDNS**: una sola autoridad de decisión recibe protocolo, UID, IP/puerto, dominio conocido y estado de la conexión. Devuelve BLOQUEAR, OBSERVAR o PERMITIR. El bloqueo DNS existente se conserva.
4. **Resolución de propietario**: usar `ConnectivityManager.getConnectionOwnerUid` cuando esté disponible; UID desconocido debe quedar explícito y no atribuirse a una aplicación inventada.
5. **Salida protegida**: todo socket de salida debe pasar por el controlador Android, enlazarse a la red física seleccionada cuando sea necesario y llamar a `VpnService.protect(fd)` antes de conectar.
6. **Selección de red**: mantener snapshots atómicos de `Network`, `LinkProperties`, MTU y resolvers. Un cambio Wi-Fi/LTE renueva las salidas, no destruye la sesión TUN.
7. **Telemetría**: eventos y métricas reales para TCP, UDP, DNS, UID, latencia, bytes, bloqueos, fallos y cambios de red; datos sensibles minimizados.
8. **Persistencia**: reglas, listas y reputación local en Room/SQLite; escrituras acotadas y lecturas rápidas. Las decisiones de flujo no esperan operaciones de disco.

## Contratos Firestack que debe implementar el adaptador

Firestack `intra.Connect` recibe un objeto `Bridge` que combina:

- `Controller`: `Bind4`, `Bind6`, `Protect`.
- `FlowListener`: `Preflow`, `Flow`, `Inflow`, `Flowing`, `Postflow`.
- `DNSListener`: `OnPrequery`, `OnQuery`, `OnUpstreamAnswer`, `OnResponse`, además de `ResolverListener`.
- `ServerListener` y `ProxyListener`.

La implementación Kotlin debe ser un adaptador delgado hacia interfaces de FirewallDNS, no una copia de las reglas de Rethink. La política de dominios y UID seguirá perteneciendo a FirewallDNS. No se activarán transportes/proxies opcionales de Firestack que no sean necesarios para el firewall local.

## Captura DNS de resolvers arbitrarios

Firestack's default DNS mode captures only the synthetic DNS IPs configured in the VPN. That would allow applications using hard-coded resolver IPs (for example, a public resolver) to send UDP/TCP port 53 without reaching FirewallDNS domain policy.

To close that gap, this repository carries the MPL-2.0 patch `third_party/patches/firestack-capture-dns-port.patch`. It adds `intra.CaptureDnsPort()`, which selects Firestack's `DNSModePort` before `Intra.Connect`. The resulting stack routes every DNS UDP/TCP port-53 flow through its DNS override and FirewallDNS `onQuery` decision. The Firestack default upstream sockets are protected by the Android Bridge, so they do not loop back into the TUN. CI runs a focused Go test for this patch before building the AAR.

This does **not** decrypt DoH/DoT/DoQ or arbitrary encrypted DNS on ports 443/853/784. It also does not make every TCP/UDP payload semantically inspectable; non-DNS traffic is filtered by flow policy and metadata.

## Secuencia de integración

### Fase A — Base reproducible y cumplimiento

- Fijar una revisión concreta de Firestack y registrar su licencia MPL-2.0, avisos y modificaciones.
- Resolver compatibilidad de toolchain: la revisión estudiada requiere Go 1.27.3 y Android NDK 28+ para compilar su AAR desde fuente; el proyecto actual compila Rust JNI para arm64.
- Preferir una dependencia/AAR reproducible y fijada por versión o una compilación propia reproducible; no depender de una rama móvil sin pin.
- Añadir inventario de dependencias y fuentes de terceros.

### Fase B — Adaptador Firestack aislado

- Crear módulo `firestack-adapter` con interfaz `PacketStack`.
- Implementar los callbacks Bridge y mapearlos a decisiones de FirewallDNS.
- Conectar el TUN existente sin crear otro `VpnService`.
- Proteger y enlazar todos los sockets de salida a la red física correcta.
- Desconexión idempotente, gestión de errores, límites de memoria y cierre seguro.

### Fase C — Activación progresiva del plano de datos

- Mantener DNS UDP actual como ruta de respaldo durante la migración.
- Activar primero TCP/UDP general en modo de observación, con contadores reales.
- Activar bloqueo por UID/IP/puerto y política DNS solo después de verificar el retorno de paquetes y el manejo de errores.
- Evitar doble procesamiento: cada paquete debe pertenecer a una única pila activa.
- Retirar RST/descartes experimentales de DNS/TCP solo cuando la nueva pila gestione realmente esos flujos.

### Fase D — Seguridad y resiliencia

- IPv4 e IPv6, fragmentación/reensamblado, MTU y paquetes malformados.
- DNS UDP/TCP, protección contra DNS rebinding y validación de respuestas.
- DoH/DoT/DoQ: solo declarar inspección si el tráfico está realmente terminado/proxyficado; el mero paso por TUN no revela consultas cifradas.
- Cambios Wi-Fi↔LTE y entre redes Wi-Fi, pérdida de red, captive portals, resolvers sin respuesta y reconexión.
- Límites de sesiones, colas, buffers, timeouts y presión de memoria.
- Pruebas de batería, CPU y estabilidad prolongada.

### Fase E — Retirada de duplicados y consolidación

- Comparar smoltcp y Firestack con pruebas y benchmarks.
- Mantener smoltcp solo donde aporte valor probado (por ejemplo, harness de pruebas o un protocolo especializado); no ejecutar dos pilas generales para el mismo TUN.
- Consolidar métricas, mapa, Monitor, Amenazas y Diagnóstico en el mismo origen de eventos.
- Documentar capacidades reales y límites visibles en la aplicación.

## Criterios de finalización

- Un solo `VpnService` y una sola sesión TUN.
- Tráfico TCP y UDP IPv4/IPv6 con ida y retorno comprobados.
- DNS bloqueado/permitido conforme a las reglas de FirewallDNS, sin pérdida de respuestas.
- La aplicación propietaria del flujo se identifica correctamente cuando Android proporciona el UID.
- Sockets protegidos contra bucles VPN y enlazados a la red física correcta.
- Cambios de red sin reinicio del TUN ni pérdida de protección.
- Pruebas automatizadas, pruebas en dispositivo y métricas de rendimiento.
- Licencias, avisos y fuentes de terceros incluidos.

## Estado de implementación de esta rama

- Añadido `NetworkFlowPolicyEngine` al módulo `engine-core`: reglas TCP/UDP/ICMP por protocolo, UID, paquete, CIDR IPv4/IPv6 y puerto; snapshots atómicos; prioridad/origen; caducidad; evaluación sin I/O; las reglas HEURISTIC no pueden bloquear.
- Expuesto `replaceFlowRules` y `evaluateFlow` desde `EngineRuntime` para que el futuro `FlowListener` de Firestack delegue en el motor único de FirewallDNS.
- Añadido `AndroidFlowPolicyAdapter`: traduce protocolos TCP/UDP/ICMP de la pila a reglas del motor, conserva UID desconocido sin inferencias y registra flujos/bytes/cierres con su generación de red.
- Añadidas pruebas del adaptador Android para reglas por UID, UID desconocido, bytes y flujos ICMP sin puertos ficticios.
- Añadidas pruebas unitarias para CIDR IPv4/IPv6, UID desconocido, expiración y rechazo de reglas heurísticas de bloqueo.
- Añadido `FlowConnectionMonitor` con límite estricto de flujos activos, contadores de bytes, UID/aplicación, protocolo, regla aplicada, generación de red, cierre y expiración segura ante concurrencia; expuesto desde `EngineRuntime`.
- Añadidas pruebas de capacidad, bytes, expiración y decisiones de bloqueo para telemetría de flujos.
- Actualizado el workflow para ejecutar pruebas de `engine-core`, `engine-monitor`, `threat-engine`, `dns-engine`, `engine-runtime`, `android-adapter` y `app`; ahora también se ejecuta en cada push a la rama de integración.
- **Todavía no integrado** el AAR/Go runtime de Firestack ni conectado `intra.Connect` al descriptor TUN. El siguiente paso es implementar el adaptador `Bridge` y verificar sus callbacks y protección de sockets.

## Estado al iniciar esta integración

- El servicio productivo existente sigue siendo principalmente DNS y ya registra bloqueos/permitidos UDP en el dispositivo.
- El código smoltcp/Rust/JNI existente demuestra límites y operaciones nativas en pruebas; eso no equivale todavía a un plano TCP/UDP general productivo.
- La prueba DNS/TCP upstream fallida en Telcel no debe bloquear la integración de una pila TCP general: son caminos distintos.
- Este documento define el trabajo; no afirma que Firestack esté ya enlazado al TUN ni que TCP/UDP general esté terminado.
