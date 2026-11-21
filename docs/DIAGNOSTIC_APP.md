# Diagnóstico integrado de FirewallDNS

El diagnóstico soportado se ejecuta dentro de la aplicación principal, en la pantalla **Diagnóstico**. No requiere instalar el APK companion ni crear una segunda VPN.

## Qué mide la pantalla integrada

- Estado del único servicio productivo `DnsFirewallService`.
- Contadores en vivo del recorrido TUN: paquetes IPv4/IPv6, DNS UDP/TCP, decisiones, respuestas, errores y colas.
- Contadores del transporte Rust/JNI smoltcp: sesiones, paquetes aceptados, respuestas encoladas, rechazos y errores nativos.
- Estado de fragmentos IPv4/IPv6: aceptados, reensamblados, descartados y expirados.
- Resultado de una prueba de límites Rust/JNI.
- Prueba DNS/TCP upstream forzada a los resolvers activos, sin caché ni fallback UDP, usando el socket protegido de producción. La prueba requiere VPN activa y solo aprueba si recibe una respuesta DNS válida por TCP.

## Interpretación

- **APROBADO**: el escenario concreto se ejecutó y cumplió su condición.
- **FALLIDO**: el escenario se ejecutó y produjo un error medible.
- **PENDIENTE / NO VERIFICADO**: no se ejecutó o no hay evidencia suficiente. No se debe convertir en aprobado por inferencia.

Un resultado positivo de `VpnService.protect()` solo acredita que Android aceptó excluir el socket del túnel; no acredita que el resolver responda ni que TCP/53 esté permitido en la red.

## Límites conocidos

- El motor inspecciona DNS tradicional en puerto 53. No afirma inspeccionar DoH, DoT ni DoQ.
- Los contadores TUN son métricas agregadas; no equivalen a una captura completa de paquetes.
- La pantalla expone métricas de fragmentación, pero una prueba de inyección de fragmentos a través del TUN productivo sigue pendiente.
- La prueba nativa de límites no sustituye una prueba de tráfico TCP real a través del TUN.
- La estabilidad prolongada, consumo de batería y CPU deben validarse en el dispositivo durante sesiones extendidas.

## Privacidad

El informe compartido contiene estado y métricas agregadas. No debe incluir payloads DNS, historial de navegación, direcciones IP consultadas ni identificadores de aplicaciones.
