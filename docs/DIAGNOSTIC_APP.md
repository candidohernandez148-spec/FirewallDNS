# Diagnóstico integrado de FirewallDNS

El diagnóstico soportado se ejecuta dentro de la aplicación principal, en la pantalla **Diagnóstico**. No requiere instalar el APK companion ni crear una segunda VPN.

## Qué mide la pantalla integrada

- Estado del único servicio productivo `DnsFirewallService`.
- Contadores en vivo del recorrido TUN: paquetes IPv4/IPv6, DNS UDP/TCP, decisiones, respuestas, errores y colas.
- Contadores del transporte Rust/JNI smoltcp: sesiones, paquetes aceptados, respuestas encoladas, rechazos y errores nativos.
- Estado de fragmentos IPv4/IPv6: aceptados, reensamblados, descartados y expirados.
- Resultado de una prueba de límites Rust/JNI.
- Prueba DNS/TCP upstream forzada a los resolvers activos, sin caché ni fallback UDP, usando el socket protegido de producción. La prueba requiere VPN activa y solo aprueba si recibe una respuesta DNS válida por TCP.
- Identidad de la red física seleccionada (Wi-Fi/celular/Ethernet), validación y resolvers obtenidos de un único snapshot de Android.
- Los sockets upstream UDP/TCP se enlazan a esa misma instancia de `Network` antes de `VpnService.protect()` y de conectar. Cuando se enlaza explícitamente, el servicio publica la red subyacente mediante `setUnderlyingNetworks()`.

## Interpretación

- **APROBADO**: el escenario concreto se ejecutó y cumplió su condición.
- **FALLIDO**: el escenario se ejecutó y produjo un error medible.
- **PENDIENTE / NO VERIFICADO**: no se ejecutó o no hay evidencia suficiente. No se debe convertir en aprobado por inferencia.

Un resultado positivo de `Network.bindSocket()` solo acredita que el socket quedó asociado a esa red; un resultado positivo de `VpnService.protect()` solo acredita que Android aceptó excluirlo del túnel. Ninguno acredita que el resolver responda ni que TCP/53 esté permitido en la red.

## Límites conocidos

- El motor inspecciona DNS tradicional en puerto 53. No afirma inspeccionar DoH, DoT ni DoQ.
- Los contadores TUN son métricas agregadas; no equivalen a una captura completa de paquetes.
- La pantalla expone métricas de fragmentación, pero una prueba de inyección de fragmentos a través del TUN productivo sigue pendiente.
- La prueba nativa de límites no sustituye una prueba de tráfico TCP real a través del TUN.
- La estabilidad prolongada, consumo de batería y CPU deben validarse en el dispositivo durante sesiones extendidas.

## Alcance real de captura DNS

El TUN configura las direcciones DNS virtuales de FirewallDNS y rutas explícitas para los resolvers públicos IPv4/IPv6 conocidos en el servicio. No instala una ruta predeterminada para todo el tráfico IP. Por tanto, una aplicación que ignore el DNS del sistema y envíe consultas a una IP DNS arbitraria que no esté entre las rutas configuradas puede quedar fuera de la captura actual. No debe afirmarse protección contra fugas DNS universal hasta cubrir y probar ese escenario.

El tráfico general TCP/UDP tampoco se reenvía a través de este motor; la inspección de esta etapa se limita a DNS/53. DoH, DoT y DoQ permanecen fuera de cobertura.

## Privacidad

El informe compartido contiene estado y métricas agregadas. No debe incluir payloads DNS, historial de navegación, direcciones IP consultadas ni identificadores de aplicaciones.
