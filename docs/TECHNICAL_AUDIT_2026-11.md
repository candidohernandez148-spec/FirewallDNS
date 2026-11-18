# Auditoría técnica de FirewallDNS

**Fecha:** 2026-11-18  
**Rama auditada:** `main`  
**Commit auditado:** `42662b888af25f8a1193350cd49f484771e50bca`  
**Alcance:** revisión estática del árbol completo, manifiesto, Gradle, servicios VPN, motor DNS, repositorio, listas, aprendizaje, UI, pruebas y workflows. No se tuvo acceso a un dispositivo físico durante esta auditoría.

## Resumen ejecutivo

FirewallDNS ya tiene una base funcional que conviene conservar: Firestack como motor principal, un evaluador determinista de reglas, snapshots inmutables de listas, almacenamiento atómico, persistencia de aprendizaje local y pantallas Compose conectadas a StateFlow.

No se recomienda reescribir la aplicación ni introducir módulos, Room o SQLite nuevos. La evolución adecuada es gradual: primero cerrar riesgos de ciclo de vida y de publicación/selección de estado de red; después robustecer el respaldo DNS; luego reducir el coste de la ruta de decisión y separar responsabilidades del repositorio sin cambiar el comportamiento; finalmente completar observabilidad, mapa y pruebas de integración.

## Hallazgos priorizados

### ALTO — El scope de FirewallVpnService no se cancelaba al destruirse el servicio

- **Archivos/clases:** `service/FirewallVpnService.kt`, `FirewallVpnService.onDestroy()`.
- **Problema:** el servicio crea `ioScope` con un `SupervisorJob` y mantiene un collector permanente de `closeUidConnectionsEvent`. `onDestroy()` lanzaba la limpieza del túnel, pero no cancelaba el scope al terminar.
- **Consecuencia:** tras recreaciones del servicio, los collectors antiguos podían permanecer suscritos y retener referencias/recursos.
- **Solución:** cerrar el túnel y desregistrar callbacks primero; cancelar el scope en un `finally` después de terminar la limpieza.
- **Riesgo:** bajo; debe garantizarse que la cancelación no ocurra antes de que termine el cierre nativo.
- **Verificación:** compilar Debug/Release y realizar ciclos repetidos de encendido/apagado y revocación de VPN en un dispositivo; comprobar que no se acumulan callbacks ni collectors.
- **Estado en esta rama:** corregido.

### ALTO — El workflow almacenaba material de firma dentro de una caché de Actions

- **Archivo/clase:** `.github/workflows/blank.yml`.
- **Problema:** se configuraba `actions/cache` sobre el directorio `signing`; el mismo directorio recibía el keystore, el password y el alias cuando se proporcionaban secretos.
- **Consecuencia:** material de firma podía persistir en la caché de CI, ampliando innecesariamente la superficie de exposición.
- **Solución:** no cachear el directorio de firma. Los secretos deben existir solo durante el job que compila el APK.
- **Riesgo:** bajo para la compilación; el keystore se vuelve a preparar en cada ejecución. Si alguna clave real ya se almacenó en una caché accesible a terceros, debe evaluarse su rotación.
- **Verificación:** inspeccionar el workflow y confirmar que no hay caché del directorio `signing`; ejecutar Release.
- **Estado en esta rama:** corregido.

### ALTO — El respaldo DNS-only no soporta DNS sobre TCP y descarta ciertos paquetes IPv6

- **Archivos/clases:** `service/DnsFirewallService.kt`, `domain/engine/DnsPacketEngine.kt`.
- **Problema:** los paquetes TCP destinados al puerto 53 reciben RST; el parser IPv6 solo acepta TCP/UDP directamente en la cabecera base y no recorre cabeceras de extensión. Los fragmentos IP también se descartan.
- **Consecuencia:** resoluciones que requieran DNS sobre TCP (por ejemplo, tras una respuesta UDP truncada) pueden fallar. Consultas IPv6 que incluyan extensiones o fragmentación pueden no recibir respuesta.
- **Solución:** diseñar soporte TCP DNS con manejo correcto de flujo y límites; implementar recorrido validado de cabeceras IPv6 y política explícita de fragmentación. No simular soporte TCP enviando un RST.
- **Riesgo:** alto; un parser/stack TCP incorrecto puede bloquear conectividad o abrir vulnerabilidades de memoria/paquetes.
- **Verificación:** pruebas unitarias de parser, pruebas de paquetes malformados, DNS TCP/UDP, IPv4/IPv6, fragmentación y pruebas reales en Wi-Fi/datos.
- **Estado:** pendiente; requiere una implementación y pruebas específicas.

### ALTO — El respaldo puede bloquear la lectura del túnel cuando se satura su cola

- **Archivo/clase:** `service/DnsFirewallService.kt`, executor de paquetes.
- **Problema:** `CallerRunsPolicy` hace que el hilo lector ejecute `handlePacket()` cuando la cola de 256 elementos está llena. El reenvío DNS puede esperar hasta 3,5 segundos.
- **Consecuencia:** una ráfaga puede detener temporalmente la lectura del descriptor TUN y aumentar latencia de otras consultas.
- **Solución:** separar lectura, evaluación y reenvío con política de saturación explícita y respuesta de error DNS controlada; añadir métricas de cola y latencia. No cambiarlo a descarte silencioso.
- **Riesgo:** alto; una política de rechazo equivocada pierde paquetes o deja solicitudes esperando.
- **Verificación:** prueba de carga con cola llena, latencia p50/p95/p99, memoria, pérdida y orden de respuestas.
- **Estado:** pendiente de medición y diseño.

### MEDIO — El monitor de red observa todas las redes físicas y puede aplicar DNS de una red no preferida

- **Archivo/clase:** `service/FirewallVpnService.kt`, `registerNetworkMonitor()` y `applyNetworkDns()`.
- **Problema:** se registra un `NetworkRequest` que puede notificar varias redes con Internet y sin transporte VPN; cada `onAvailable`/evento de propiedades puede actualizar DNS y la red subyacente.
- **Consecuencia:** con Wi-Fi y datos móviles simultáneos, eventos de más de una red pueden competir. El orden de llegada no garantiza que el último DNS corresponda al camino que Firestack usa.
- **Solución:** definir explícitamente la política de selección de red física y asociar el DNS aplicado al identificador de esa red; evitar inferir la red predeterminada por el orden de `allNetworks`.
- **Riesgo:** medio-alto; las APIs de red distinguen la red predeterminada de la VPN y deben probarse en versiones Android reales.
- **Verificación:** Wi-Fi conectado + datos móviles activos, cambio Wi-Fi/datos, pérdida/restauración, IPv4/IPv6 y medición de DNS efectivo.
- **Estado:** pendiente de validación en dispositivo.

### MEDIO — NetworkDns puede seleccionar una red física arbitraria cuando la activa es la VPN

- **Archivo/clase:** `service/NetworkDns.kt`, `active()`, `firstActiveDns()` y `currentType()`.
- **Problema:** si la red activa reportada es VPN, el método cae a `allNetworks.firstOrNull`; `currentType()` prioriza cualquier Wi-Fi disponible sobre celular, no necesariamente la red usada por defecto.
- **Consecuencia:** upstream DNS o etiqueta de red podrían no representar el transporte efectivo.
- **Solución:** compartir una única fuente de estado de red física seleccionada por el monitor del servicio, y derivar DNS/tipo de red de esa misma fuente.
- **Riesgo:** medio; cambios de conectividad requieren pruebas de transición.
- **Verificación:** registrar el Network ID elegido, LinkProperties, DNS seleccionado y transporte efectivo durante cambios de red.
- **Estado:** pendiente.

### MEDIO — El repositorio concentra demasiadas responsabilidades

- **Archivo/clase:** `data/repository/FirewallRepository.kt`.
- **Problema:** el objeto singleton maneja estado, reglas, descargas, aprendizaje, logs, persistencia, monitor de red y eventos de servicio.
- **Consecuencia:** mayor acoplamiento, pruebas difíciles y riesgo de efectos laterales.
- **Solución:** extraer gradualmente coordinadores pequeños: publicación de snapshots de reglas, registro/estadísticas de actividad, aprendizaje local y estado de red. Mantener un único punto de decisión DNS y conservar las interfaces públicas hasta tener pruebas.
- **Riesgo:** alto si se hace una reescritura masiva; bajo/medio si se extrae una responsabilidad por vez.
- **Verificación:** pruebas de precedencia, concurrencia, persistencia y regresión de llamadas del servicio.
- **Estado:** pendiente; no se recomienda dividir el módulo Android todavía.

### MEDIO — Código residual con apariencia de segundo motor de dominios

- **Archivo/clase:** `domain/engine/DomainBlocker.kt`.
- **Problema:** contiene un conjunto propio y funciones de carga/mezcla; el flujo activo de Firestack consulta `FirewallRepository.evaluateDomain()`. En el puente solo se usa `DomainBlocker.normalize()`.
- **Consecuencia:** confusión sobre cuál motor decide y riesgo de reactivar accidentalmente un camino divergente.
- **Solución:** tras confirmar referencias completas, sustituir el uso de normalización por una utilidad neutral y retirar el evaluador/cargadores muertos.
- **Riesgo:** medio; comprobar referencias y pruebas antes de eliminarlo.
- **Verificación:** búsqueda de referencias, pruebas de normalización y pruebas de decisión central.
- **Estado:** pendiente.

### MEDIO — El estado “listas descargadas” solo comprueba que exista un archivo

- **Archivo/clase:** `data/local/BlocklistDataSource.kt`, `hasSavedBlocklists()`; inicialización en `FirewallRepository.init()`.
- **Problema:** el estado se establece con `File.isFile`, sin verificar tamaño ni integridad del snapshot.
- **Consecuencia:** un archivo vacío o dañado podría hacer que la UI muestre que ya existen listas guardadas.
- **Solución:** validar el snapshot al cargarlo y publicar el estado descargado solo después de una lectura válida; mantener las reglas semilla si la validación falla.
- **Riesgo:** medio; evitar escanear archivos grandes en el hilo principal.
- **Verificación:** archivo ausente, vacío, truncado, con versión desconocida y snapshot válido; comprobar estado UI y reglas activas.
- **Estado:** pendiente.

### MEDIO — No hay una pantalla Mapa conectada en la navegación actual

- **Archivos/clases:** `MainActivity.kt`, `ThreatKnowledgeGraph.kt`.
- **Problema:** la navegación visible tiene cinco destinos y no incluye Mapa. Hay lógica de conocimiento/correlación en dominio, pero no una pantalla que la presente.
- **Consecuencia:** parte del conocimiento local no está disponible como herramienta visible y no puede verificarse desde la UI.
- **Solución:** diseñar una vista compacta de correlaciones y evidencia, sin ejecutar análisis pesado en composición y sin duplicar el motor.
- **Riesgo:** medio; no mostrar correlaciones como atribución concluyente.
- **Verificación:** datos vacíos, catálogos, observaciones, rendimiento en el dispositivo objetivo y actualización en tiempo real.
- **Estado:** pendiente.

### MEDIO — Cobertura de pruebas insuficiente para servicios y red

- **Archivos/clases:** `app/src/test`, `.github/workflows/build.yml`, `.github/workflows/blank.yml`.
- **Problema:** existen pruebas unitarias para reglas, parser DNS, heurísticas, aprendizaje y políticas de fuentes; no se observan pruebas instrumentadas del ciclo de vida VPN, cambios de red, FirestackBridge, fallback ni descargas reales.
- **Consecuencia:** los riesgos de servicio/red no quedan cubiertos por la suite actual.
- **Solución:** agregar primero pruebas unitarias puras para políticas y parser; después pruebas instrumentadas de servicio y escenarios de conectividad. Ejecutar también tests en push a main, no solo en PR.
- **Riesgo:** bajo/medio; evitar tests de red frágiles dependientes de servicios externos.
- **Verificación:** CI Debug + unit tests, Release, y pruebas instrumentadas en emulador/dispositivo.
- **Estado:** pendiente.

### BAJO — Archivos residuales fuera de las rutas de compilación

- **Archivos:** `app/src/main/.service.DnsFirewallService`, `app/lifecycle-viewmodel-compose`.
- **Problema:** manifiesto y configuración Gradle duplicados/antiguos; el manifiesto residual incluso declara `allowBackup=true`, mientras el manifiesto real usa `allowBackup=false`.
- **Consecuencia:** confusión durante auditorías y riesgo de copiar configuración obsoleta.
- **Solución:** eliminarlos después de confirmar que no están referenciados por el build.
- **Riesgo:** bajo; no pertenecen al source set ni al proyecto incluido por settings.
- **Verificación:** árbol de archivos, Gradle Debug/Release.
- **Estado:** pendiente.

## Arquitectura objetivo gradual

Conservar un único módulo Android y estas fronteras:

1. **Presentación:** Compose + ViewModel. Solo consume StateFlow y emite acciones; no consulta paquetes ni redes directamente.
2. **Dominio de decisión:** `RuleEvaluator` como precedencia determinista; `SmartDecisionEngine` como etapa heurística posterior. Las excepciones/manuales/listas deben tener un orden único y documentado.
3. **Datos:** `BlocklistDataSource`, `PreferencesDataSource` y `SmartLearningStore`. Snapshots inmutables publicados atómicamente; sin base de datos nueva.
4. **Adaptadores de red:** `FirewallVpnService` y `FirestackBridge` para Firestack; `DnsFirewallService` aislado como respaldo DNS-only, nunca como motor paralelo del camino principal.
5. **Coordinación:** extraer del repositorio estado de red, actividad y aprendizaje de forma incremental, sin cambiar contratos hasta que las pruebas protejan el comportamiento.

No se recomienda agregar Hilt, Room, módulos Gradle adicionales ni una capa genérica de interfaces en esta fase.

## Orden recomendado de ejecución

1. Cerrar fugas de ciclo de vida y seguridad del pipeline CI.
2. Corregir/medir la selección de red y el cambio Wi-Fi ↔ celular.
3. Robustecer el respaldo DNS (TCP, IPv6, saturación y TTL de caché).
4. Validar el estado de listas guardadas y agregar pruebas de corrupción/recuperación.
5. Extraer responsabilidades del repositorio con pruebas de regresión.
6. Completar la pantalla Mapa y la cobertura instrumentada.
7. Medir latencia DNS p50/p95/p99, CPU, RAM y batería antes/después en el Galaxy A34 5G.

## Estado de verificación

- El commit auditado de `main` es `42662b888af25f8a1193350cd49f484771e50bca`.
- El workflow de Release de ese commit terminó correctamente.
- El workflow de PR de la corrección anterior también completó correctamente pruebas unitarias y Debug.
- No se realizaron pruebas en dispositivo físico, ni pruebas de transición de red ni pruebas de carga.
- No se afirma inspección de HTTPS, DoH o DoT externo.
