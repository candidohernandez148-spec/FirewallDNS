# Arquitectura del motor único FirewallDNS

## Principio de diseño

FirewallDNS tiene **un solo motor productivo**, una sola autoridad de políticas, un solo `VpnService` y una sola interfaz TUN. Firestack/gVisor está integrado como el plano de paquetes del motor FirewallDNS; no es una segunda VPN ni una aplicación paralela. El prototipo Rust/smoltcp fue retirado del APK y del flujo de compilación; Firestack/gVisor es la única pila de paquetes.

## Camino de producción

1. Android `DnsFirewallService` posee el permiso VPN, el descriptor TUN, el ciclo de vida y las rutas IPv4/IPv6.
2. `FirestackTunnelAdapter` conecta Firestack/gVisor al descriptor TUN duplicado. No existe un segundo lector Kotlin ni otra pila productiva que procese los mismos paquetes.
3. Los callbacks de Firestack delegan las decisiones en `EngineRuntime`: políticas DNS, reglas por aplicación/UID, protocolo, IP/CIDR, puerto y señales de amenaza.
4. `NetworkFlowPolicyEngine` evalúa TCP, UDP e ICMP con snapshots atómicos. Las reglas heurísticas pueden observar, pero nunca bloquear por sí solas.
5. Las consultas DNS UDP/TCP en puerto 53 se capturan mediante el parche versionado de Firestack y pasan por la política DNS de FirewallDNS.
6. Los sockets de salida se enlazan a la red física seleccionada y se protegen con `VpnService.protect()` antes de conectar. Los snapshots de red agrupan identidad `Network`, resolvers y MTU para evitar mezclar generaciones Wi-Fi/celular.
7. El monitor conserva métricas acotadas de flujos, bytes, bloqueos, generación de red y resultados de protección/enlace. La UI lee el estado real del motor, no contadores de un lector TUN retirado.

## Política y límites de seguridad

- `BLOCK`: descarta el flujo o responde NXDOMAIN para DNS bloqueado.
- `OBSERVE`: registra señales y deja continuar el flujo; no es un bloqueo encubierto.
- `ALLOW`: permite el flujo conforme a las reglas.
- UID desconocido se conserva como desconocido; no se inventa una aplicación.
- Las reglas CIDR se aplican también a destinos originales reportados por Firestack cuando utiliza destinos ALG.
- DoT/DoQ se pueden bloquear por puertos estándar configurados. Los endpoints DoH conocidos se correlacionan cuando Firestack proporciona metadatos de dominio. FirewallDNS **no descifra TLS**, no inspecciona universalmente DoH/DoQ y no afirma identificar todos los resolvers cifrados.
- Si Firestack/gVisor no puede iniciar o adjuntarse al TUN, el servicio se detiene y no informa protección activa. No se activa un motor DNS-only alternativo ni un segundo plano de paquetes.

## Componentes de referencia

- **Firestack/gVisor**: pila de red de espacio de usuario TCP/UDP/ICMP sobre TUN.
- **RethinkDNS**: referencia para el ciclo de vida del único VPN Android, el adaptador Firestack, la atribución de conexiones y el seguimiento de actividad.
- **NetGuard**: referencia para el modelo de firewall local sin root, los límites de Android VPN y el control por aplicación/red.
- **gVisor**: referencia para los contratos y el comportamiento de la pila de red.

Se aprovechan patrones y pruebas de proyectos maduros, respetando sus licencias. La política, el motor de decisiones y la integración final pertenecen a FirewallDNS.

## Validación obligatoria antes de declarar terminado el motor

### Automatizada
- Pruebas JVM de `engine-core`, `dns-engine`, `threat-engine`, `engine-monitor` y `engine-runtime`.
- Pruebas del adaptador Android: callbacks Firestack, UID desconocido, reglas CIDR IPv4/IPv6, destinos ALG, orden bind → protect, fallos de enlace/protección y handover.
- Pruebas Go del parche de captura DNS de Firestack.
- Compilación Android Debug y Release, empaquetado ARM64 y verificación de dependencias/licencias.

### En el dispositivo físico Samsung A34 5G
- Wi-Fi, Telcel LTE y cambios repetidos Wi-Fi ↔ móvil.
- IPv4 e IPv6, DNS UDP/53 y TCP/53 con resolvers del sistema y direcciones codificadas.
- Navegación HTTPS TCP, QUIC/UDP, ICMP y conexiones de aplicaciones de sistema/terceros.
- Reglas por UID, aplicación, IP/CIDR, puerto, allowlist, blocklist y OBSERVE.
- Pérdida/recuperación de red, captive portal, resolvers lentos, fallos de sockets y reinicio del stack.
- Latencia P50/P95/P99, throughput, CPU, memoria, batería, pérdidas, fugas DNS y estabilidad prolongada.

**Una compilación aprobada no sustituye estas pruebas físicas.** Hasta completar la matriz del dispositivo, el motor puede considerarse integrado en código, pero no certificado como terminado en todas las redes.
