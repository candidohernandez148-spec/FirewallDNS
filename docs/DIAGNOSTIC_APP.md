# Diagnóstico integrado de FirewallDNS

El diagnóstico se ejecuta dentro de la aplicación principal, en la pantalla **Diagnóstico**. No requiere instalar una aplicación companion ni crear una segunda VPN.

## Arquitectura productiva

- Un solo `VpnService` (`DnsFirewallService`) y un único descriptor TUN.
- En el modo principal, Firestack/gVisor recibe el TUN y procesa tráfico TCP, UDP e ICMP IPv4/IPv6.
- El adaptador Kotlin implementa el contrato `Bridge` de Firestack y conecta decisiones de flujo/DNS con el motor único de FirewallDNS.
- Rust/JNI con smoltcp permanece únicamente como banco de pruebas nativo dentro de Diagnóstico. No se carga como motor productivo ni como respaldo cuando Firestack no puede iniciarse.
- Los sockets de salida se protegen con `VpnService.protect()` y se enlazan a la red física activa cuando Android proporciona un `Network`.
- Los cambios entre Wi-Fi, datos móviles y otras redes actualizan la selección de resolvers y el MTU sin reiniciar el servicio VPN.

## Qué mide la pantalla integrada

- Estado del único servicio productivo `DnsFirewallService` y nombre del motor activo.
- Telemetría en vivo del motor único: flujos activos/abiertos/cerrados/bloqueados, bytes TX/RX, protección de sockets y enlaces a la red física.
- Decisiones DNS comunicadas por Firestack: bloqueadas, observadas y permitidas.
- Resultado aislado de las pruebas Rust/JNI smoltcp: sesiones, límites, colas y errores. Nunca debe interpretarse como tráfico de producción.
- Estado de Firestack, conexiones observadas, bytes, protección de sockets y enlace a la red física.
- Resultado de una prueba de límites Rust/JNI.
- Prueba DNS/TCP upstream forzada a los resolvers activos, sin caché ni fallback UDP, usando el cliente de diagnóstico y sockets protegidos. La prueba requiere VPN activa y solo aprueba si recibe una respuesta DNS válida por TCP. Es una prueba de salida upstream; no demuestra por sí sola que una conexión TCP/53 entrante al TUN esté correctamente reenviada.
- Identidad de la red física seleccionada (Wi-Fi/celular/Ethernet), validación, MTU y resolvers obtenidos de un único snapshot de Android.

## Interpretación

- **APROBADO**: el escenario concreto se ejecutó y cumplió su condición.
- **FALLIDO**: el escenario se ejecutó y produjo un error medible.
- **PENDIENTE / NO VERIFICADO**: no se ejecutó o no hay evidencia suficiente. No se debe convertir en aprobado por inferencia.

Un resultado positivo de `Network.bindSocket()` solo acredita que el socket quedó asociado a esa red; un resultado positivo de `VpnService.protect()` solo acredita que Android aceptó excluirlo del túnel. Ninguno acredita que el resolver responda ni que TCP/53 esté permitido en la red.

## Cobertura y límites

- Firestack/gVisor procesa tráfico general TCP, UDP e ICMP que atraviesa el TUN. FirewallDNS puede decidir por UID, paquete, protocolo, IP/CIDR y puerto.
- El filtrado de dominios se aplica a consultas DNS tradicionales en puerto 53, tanto UDP como TCP, incluyendo consultas dirigidas a resolvers codificados gracias al parche de captura por puerto 53.
- Las decisiones de dominio se pueden correlacionar con flujos posteriores cuando Firestack proporciona dominios asociados al destino.
- DoT y DoQ se bloquean en los puertos estándar configurados. DoH solo se identifica mediante correlación con nombres de endpoints conocidos; **no se descifra TLS ni se inspecciona universalmente DoH, DoT o DoQ**.
- El tráfico de protocolos IP distintos de TCP, UDP e ICMP puede no ser reenviado por la pila de usuario.
- Los contadores TUN son métricas agregadas; no equivalen a una captura completa de paquetes.
- La prueba nativa de límites no sustituye una prueba de ida y vuelta TCP/UDP real a través del TUN.
- La compilación y las pruebas automatizadas no sustituyen la validación física en el teléfono: Wi-Fi, datos móviles, cambios de red, IPv4/IPv6, UID, batería y CPU durante sesiones prolongadas.

## Red física y cambios de conectividad

La selección de red se basa en `ConnectivityManager` y `LinkProperties`, excluyendo la propia VPN. Los resolvers y el objeto `Network` se publican como una generación coherente. Al cambiar de red, FirewallDNS renueva el transporte DNS y actualiza Firestack sin cerrar el TUN. Las conexiones ya abiertas pueden terminar sobre la red a la que fueron enlazadas originalmente; las nuevas utilizan la generación más reciente.

## Privacidad

El informe compartido contiene estado y métricas agregadas. No debe incluir payloads DNS, historial de navegación, direcciones IP consultadas ni identificadores sensibles de aplicaciones.
