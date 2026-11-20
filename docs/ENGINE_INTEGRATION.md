# Integración de FirewallDNS-Engine en Android

## Qué se integra en esta rama

Los módulos Kotlin/JVM y Android del motor compartido se incorporan como módulos Gradle locales del repositorio Android:

- `engine-core`: reglas y decisiones deterministas.
- `dns-engine`: parser DNS, evaluación de políticas, validación upstream, caché TTL, DNS UDP/TCP y failover.
- `threat-engine`: indicadores curados y heurísticas explicables.
- `engine-monitor`: eventos y métricas locales acotados.
- `engine-runtime`: fachada única de decisiones.
- `android-adapter`: composición Android y protección de sockets mediante `VpnService.protect()`.

El código se sincronizó desde `candidohernandez148-spec/FirewallDNS-Engine` (rama `main`) al crear esta integración. Los dos repositorios siguen siendo independientes; al actualizar el motor compartido, se debe sincronizar explícitamente su código y pruebas con la app o automatizar ese proceso en una entrega posterior.

## Ruta de producción conectada

`DnsFirewallService` continúa siendo el único `VpnService` y dueño del TUN. El servicio crea `AndroidEngineRuntime`, exporta el snapshot de reglas de `FirewallRepository` al motor, resuelve el paquete asociado al UID cuando Android lo permite y usa `EngineRuntime.evaluateDns()` para las decisiones DNS. Las consultas permitidas usan el cliente upstream del motor, que protege los sockets UDP/TCP antes de conectarlos.

La operación upstream es síncrona; por ello se invoca desde los workers existentes y no desde el hilo principal. Esta rama no convierte el motor en una pila IP/TCP completa y no activa todavía `TunDnsPacketProcessor` como lector de paquetes de producción.

## Compatibilidad y rollback

El campo `USE_SHARED_ENGINE` de `app/build.gradle.kts` funciona como interruptor de integración. Está habilitado en esta rama. Para volver temporalmente al evaluador y forwarding Kotlin anteriores, cambiarlo a `false` y reconstruir. Si no se puede inicializar el adaptador o el upstream compartido, el servicio conserva el camino anterior como fallback.

## Semántica

- `BLOCK` bloquea cuando el modo de observación está desactivado.
- El modo de observación convierte el resultado efectivo en no bloqueante y lo registra como `OBSERVE`.
- `ALLOW` y `OBSERVE` reenvían la consulta.
- Las reglas personalizadas tienen prioridad sobre las listas administradas; las excepciones administradas prevalecen sobre los bloqueos de listas.
- El análisis de amenazas puede desactivarse con la preferencia existente de modo inteligente.
- La protección sigue siendo DNS-only. No se inspeccionan tráfico TCP/UDP general, DoH ni DoT.

## Validación pendiente antes de activar como versión estable

1. Ejecutar pruebas JVM de todos los módulos y pruebas unitarias Android.
2. Compilar APK debug y release.
3. Probar en Samsung A34 5G con Wi-Fi, datos móviles, IPv4 e IPv6.
4. Verificar que `VpnService.protect()` evita el bucle upstream en hardware real.
5. Medir P50/P95/P99, CPU, memoria, batería, pérdida, timeouts y reconexiones.
6. Confirmar reglas por aplicación, excepciones, OBSERVE y fallback.
7. No retirar el código anterior hasta superar la matriz de validación.

La integración de código no equivale a validación en el dispositivo ni demuestra ausencia de fugas DNS.


## Protección del lector TUN ante saturación

La cola de paquetes del servicio Android es acotada (256 elementos) y usa
`AbortPolicy`. El hilo lector nunca ejecuta procesamiento DNS como alternativa
cuando la cola está llena, porque ese trabajo puede esperar al servidor upstream.
Los rechazos se contabilizan en `DnsFirewallService.queueRejectedPackets` y los
errores de procesamiento capturados en workers en
`DnsFirewallService.packetProcessingErrors`.

Un rechazo significa que ese paquete no se procesa y la consulta correspondiente
puede expirar en la aplicación de origen. El contador hace visible esa pérdida
para diagnóstico; no constituye un mecanismo de reintento ni garantiza entrega.

## Ciclo de vida de cada sesión TUN

Cada establecimiento crea una sesión con su propio descriptor, streams, lector
y estado activo. Los workers reciben esa sesión concreta, no un stream global:
antes de escribir comprueban que siga activa. Así una respuesta tardía de una
sesión anterior no puede entrar en un TUN recién establecido.

El cierre invalida primero la sesión, serializa el cierre del descriptor con las
escrituras, cierra el descriptor para desbloquear la lectura, espera al lector
con un límite de tiempo y da a los workers una ventana acotada para terminar.
Las escrituras fallidas se cuentan en
`DnsFirewallService.packetWriteErrors`. Las métricas de cola, procesamiento y
escritura siguen siendo contadores internos; todavía no están conectados a la UI
del monitor.

La espera de workers es deliberadamente limitada: una consulta upstream lenta no
debe bloquear indefinidamente el apagado. Los workers que terminen después de la
invalidación ya no pueden escribir en el descriptor cerrado. Esta etapa no
habilita TCP/UDP general ni cambia el alcance DNS-only.

## Validación de transporte en el límite TUN

`TunTransportPacketParser` valida paquetes IP completos antes de que el servicio lea puertos o genere una respuesta:
- IPv4: IHL, longitud total exacta, checksum de cabecera y rechazo de reservado/MF/offset; DF se permite.
- IPv6: cabecera base y longitud exacta; extensiones, fragmentos y jumbograms siguen fuera de alcance.
- UDP: cabecera y longitud coincidentes; checksum cero se permite solo en IPv4 y los checksums presentes se verifican.
- TCP: mínimo de 20 bytes, Data Offset válido y checksum de pseudo-cabecera obligatorio verificado sobre el segmento completo.

El servicio productivo usa ese resultado para procesar DNS UDP/53 y, mientras no exista TCP de cliente gestionado por smoltcp, responder con RST correcto a TCP/53 válido. El generador evita responder a RST, aplica las reglas de secuencia/ACK con y sin ACK entrante, incluye datos + SYN + FIN en el espacio de secuencia y reconstruye checksums IPv4/TCP o TCP/IPv6.

## DNS sobre TCP: qué está reutilizado y qué falta

`DnsTcpFrameCodec` ya codifica/decodifica el prefijo de longitud de 2 bytes Big Endian y devuelve cuántos bytes consumir, por lo que admite lecturas parciales y varios mensajes concatenados si el llamador conserva el resto del flujo. `DnsUpstreamClient` ya reintenta por TCP cuando la respuesta UDP upstream trae TC=1; protege el socket TCP antes de conectar y lee exactamente el frame anunciado.

Esto **no equivale** a DNS sobre TCP desde las aplicaciones del dispositivo. La VPN productiva todavía responde RST al TCP/53 del cliente. Para habilitarlo se requiere completar y probar la frontera JNI + `TunPacketDevice` + bucle `smoltcp` + socket TCP por flujo + parser incremental por conexión + política DNS compartida + respuesta por el mismo flujo. No se habilita full-tunnel ni se añade una segunda VPN con esta entrega.
