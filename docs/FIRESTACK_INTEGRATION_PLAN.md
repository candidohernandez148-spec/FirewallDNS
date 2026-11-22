# Plan de integración del motor de red de FirewallDNS

## Objetivo

FirewallDNS se ha ampliado como firewall virtual Android sobre un único `VpnService` y una única interfaz TUN. Firestack/gVisor proporciona el plano TCP/UDP/ICMP IPv4/IPv6 y FirewallDNS conserva la autoridad de política DNS, dominios, aplicaciones y flujos.

La integración debe conservar el filtrado DNS que ya funciona en Wi-Fi y datos móviles. Ningún componente nuevo sustituye al servicio VPN actual ni crea una segunda VPN.

## Referencias técnicas fijadas

- Firestack: `https://github.com/celzero/firestack`
- Revisión de código estudiada: `c27887056230769ee897b7c7b92976b96d3c9a6d`
- Firestack usa gVisor/netstack para TCP/UDP sobre TUN y expone `intra.Connect(fd, linkmtu, tunmtu, ifaddrs, fakedns, defaultDNS, bridge)`.
- Rethink app: `https://github.com/celzero/rethink-app`, especialmente `GoVpnAdapter.kt` y `BraveVPNService.kt`, como referencia de integración Android.
- gVisor networking guide: `https://gvisor.dev/docs/architecture_guide/networking/`
- Prototipo smoltcp/Rust de FirewallDNS: retirado del código activo, del APK y de CI; Firestack/gVisor permanece como única pila de paquetes.

## Arquitectura objetivo

1. **Android VPN host**: `DnsFirewallService` conserva la propiedad del descriptor TUN, el ciclo de vida, las rutas, la notificación y el permiso VPN.
2. **Adaptador de pila**: `FirestackTunnelAdapter` inicia, detiene y consulta estadísticas de Firestack/gVisor sobre el descriptor TUN duplicado del servicio Android.
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

### Fase B — Adaptador Firestack aislado (completada)

- Crear módulo `firestack-adapter` con interfaz `PacketStack`.
- Implementar los callbacks Bridge y mapearlos a decisiones de FirewallDNS.
- Conectar el TUN existente sin crear otro `VpnService`.
- Proteger y enlazar todos los sockets de salida a la red física correcta.
- Desconexión idempotente, gestión de errores, límites de memoria y cierre seguro.

### Fase C — Activación progresiva del plano de datos (completada para TCP/UDP/ICMP general)

- Mantener DNS UDP actual como ruta de respaldo durante la migración.
- Activar primero TCP/UDP general en modo de observación, con contadores reales.
- Activar bloqueo por UID/IP/puerto y política DNS solo después de verificar el retorno de paquetes y el manejo de errores.
- Evitar doble procesamiento: cada paquete debe pertenecer a una única pila activa.
- Retirar RST/descartes experimentales de DNS/TCP solo cuando la nueva pila gestione realmente esos flujos.

### Fase D — Seguridad y resiliencia (parcial; validación física pendiente)

- IPv4 e IPv6, fragmentación/reensamblado, MTU y paquetes malformados.
- DNS UDP/TCP, protección contra DNS rebinding y validación de respuestas.
- DoH/DoT/DoQ: solo declarar inspección si el tráfico está realmente terminado/proxyficado; el mero paso por TUN no revela consultas cifradas.
- Cambios Wi-Fi↔LTE y entre redes Wi-Fi, pérdida de red, captive portals, resolvers sin respuesta y reconexión.
- Límites de sesiones, colas, buffers, timeouts y presión de memoria.
- Pruebas de batería, CPU y estabilidad prolongada.

### Fase E — Retirada de duplicados y consolidación (completada en código)

- (Histórico) Se compararon prototipos smoltcp y Firestack; el código smoltcp fue retirado posteriormente.
- (Completado) Retirar smoltcp, su JNI y el banco de pruebas del proyecto activo.
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

## Estado integrado en `main`

- Firestack está fijado a `c27887056230769ee897b7c7b92976b96d3c9a6d` y se compila como AAR Android ARM64 desde fuente durante CI.
- `FirestackTunnelAdapter` conecta `Intra.connect` al descriptor duplicado del TUN establecido por el único `DnsFirewallService`; el servicio no mantiene lector TUN Kotlin, motor DNS alternativo.
- Si Firestack no arranca, se cierra el descriptor TUN y el servicio no declara protección activa ni establece un túnel DNS alternativo. No hay motor de respaldo en producción.
- El `Bridge` Android protege sockets y los enlaza a la instancia física `Network` seleccionada; cada resultado se contabiliza. No se cachean descriptores FD reutilizables.
- La selección de red, lista de resolvers y MTU se toman de snapshots físicos; el cambio Wi-Fi/LTE actualiza DNS y MTU sin reiniciar TUN, y los fallos de rebind quedan pendientes para reintento.
- Cuando Android cambia la identidad de la red física (por ejemplo, Wi-Fi → Telcel LTE), FirewallDNS actualiza el resolver y reinicia el netstack de Firestack sobre el mismo descriptor TUN. Los sockets existentes enlazados a la red anterior se cierran para que las aplicaciones reconecten por la nueva red; no se crea otra VPN ni otra interfaz TUN. Si el reinicio del netstack falla, el servicio programa la reconstrucción controlada de la sesión TUN.
- El parche MPL-2.0 `third_party/patches/firestack-capture-dns-port.patch` expone `Intra.captureDnsPort()` y cambia Firestack a `DNSModePort`: consultas UDP/TCP 53 hacia cualquier IP de resolver pasan por `onQuery` y la política de dominios. Hay pruebas Go para IPv4/IPv6.
- `AndroidFlowPolicyAdapter` conecta los callbacks `Flow`/`Inflow` con la política de FirewallDNS, conserva UID desconocido sin inferencias, consulta bloqueos por aplicación y registra flujos/bytes/cierres.
- `NetworkFlowPolicyEngine` evalúa TCP/UDP/ICMP por UID, paquete, protocolo, CIDR IPv4/IPv6 y puerto; usa snapshots atómicos, prioridad/origen y caducidad; las reglas HEURISTIC no pueden bloquear.
- `EncryptedDnsGuard` bloquea DoT TCP/853 y DoQ UDP/853, 784 y 8853; bloquea dominios DoH conocidos correlacionados con flujos y deja dominios probables en OBSERVAR. No descifra TLS ni garantiza detectar DoH por IP sin dominio correlacionado.
- `FlowConnectionMonitor` mantiene límites estrictos, métricas de bytes, UID/aplicación, protocolo, regla y generación de red; serializa cierre, actividad y expiración para evitar carreras.
- Inicio, Diagnóstico y métricas exponen el estado Firestack, flujos, protección/enlace de sockets y fallos de red.
- La compilación de `main` posterior a PR #95 pasó. La rama `refactor/single-firewalldns-engine` retira el lector TUN Kotlin y smoltcp del camino productivo; su CI debe confirmar compilación Debug/Release y pruebas. La validación física sigue pendiente.
- La validación final en dispositivo sigue pendiente: Samsung A34 5G, Wi-Fi, Telcel LTE, cambios de red, TCP/UDP, DNS con IP fija, DoT/DoQ/DoH y estabilidad prolongada.

## Validación y límites actuales

- La compilación reproducible y las pruebas automatizadas pasan en CI; el APK Release incluye los dos motores nativos ARM64.
- No se declara todavía completada la validación física: falta comprobar en Samsung A34 5G el tráfico TCP/UDP de ida y retorno, atribución UID, Wi-Fi↔Telcel, consumo de batería, estabilidad prolongada y comportamiento de DNS con resolvers de terceros.
- La captura de DNS UDP/TCP 53 sí está integrada; DoH/DoT/DoQ no se descifran. DoT/DoQ por puertos estándar se bloquean y los endpoints DoH solo se correlacionan por dominio/IP conocida.

## Línea base anterior a la integración (histórico)

- El servicio productivo inicial era principalmente DNS y registraba bloqueos/permitidos UDP.
- El código smoltcp/Rust/JNI fue retirado del proyecto activo; no forma parte del motor ni del APK.
- El fallo de DNS/TCP upstream observado en Telcel era un problema distinto del reenvío TCP general de la pila Firestack.
- Esta sección es histórica; el estado vigente de integración está descrito arriba.
