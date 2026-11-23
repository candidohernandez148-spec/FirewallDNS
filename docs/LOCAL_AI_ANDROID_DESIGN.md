# IA local única para FirewallDNS — diseño de integración

## Objetivo

Incorporar un único modelo local descargable bajo demanda para el Samsung Galaxy A34 5G SM-A346M (Android 13/API 33, arm64-v8a, 8 núcleos, Mali-G68 MC4 y aproximadamente 5.4 GB de memoria reportada), sin cambiar el motor Firestack/gVisor ni introducir latencia en el TUN.

## Modelo seleccionado

- Familia: Qwen3 1.7B Instruct.
- Formato: GGUF, cuantización Q4_K_M.
- Archivo de referencia: `Qwen3-1.7B-Q4_K_M.gguf`.
- Tamaño publicado: aproximadamente 1.19 GiB.
- Repositorio de referencia: https://huggingface.co/tauqir02/Qwen3-1.7B-GGUF
- Contexto inicial: 2,048 tokens; no habilitar modo thinking para tareas rutinarias.
- La aplicación no debe incluir el archivo GGUF dentro del APK. Se descarga una sola vez, bajo consentimiento del usuario, por Wi-Fi preferentemente, con verificación SHA-256 y almacenamiento privado.

La compatibilidad exacta del modelo y el rendimiento deben validarse en el SM-A346M real. La memoria total reportada por Android no equivale a memoria libre disponible; si no hay margen suficiente, no se carga el modelo.

## Reglas obligatorias de rendimiento y batería

1. **Nunca ejecutar inferencia en el hilo TUN, callbacks de Firestack, hilo principal ni ruta síncrona de DNS.**
2. Las decisiones BLOCK/ALLOW/OBSERVE inmediatas siguen a cargo de las reglas deterministas y listas verificadas existentes. La inferencia de IA se ejecuta por lotes fuera de la ruta DNS; una recomendación validada puede publicar una regla administrada por IA en el mismo motor determinista, sin ejecutar inferencia dentro del TUN.
3. La IA se inicia de forma perezosa: no cargar el modelo al arrancar FirewallDNS ni al iniciar la VPN.
4. Una sola instancia de modelo, un único ejecutor de inferencia y una cola acotada. Si la cola se llena, se agrupan o descartan tareas de análisis no críticas; nunca se acumulan eventos indefinidamente.
5. Analizar lotes/resúmenes de eventos, no cada paquete ni cada consulta DNS. Deduplicar dominios y limitar frecuencia por dominio/aplicación.
6. Ejecutar análisis oportunistas con prioridad baja cuando el dispositivo esté inactivo; permitir análisis manual inmediato. No mantener CPU despierta ni usar un servicio foreground adicional solo para IA.
7. Descargar el modelo de memoria al salir del módulo, tras inactividad configurable o ante presión de memoria/térmica. No reiniciar ni detener el servicio VPN.
8. Empezar con 2–3 hilos CPU, contexto 2,048 y batch pequeño; medir tokens/s, RAM PSS, temperatura y consumo antes de ajustar. No asumir aceleración GPU: el dispositivo reporta OpenCL no disponible.
9. Si la inferencia está ocupada, falla, el modelo no está instalado o el teléfono está bajo presión de memoria, FirewallDNS continúa con el motor actual sin degradación.
10. No enviar dominios, historial, UID ni tráfico a servicios remotos. Todo el análisis y almacenamiento del modelo son locales.

## Responsabilidades del modelo

El modelo único se utiliza como asistente de análisis y explicación para:
- resumir eventos DNS y hallazgos del analizador determinista;
- explicar por qué un dominio quedó BLOCK, OBSERVE o ALLOW;
- sugerir investigación adicional para dominios desconocidos;
- generar resúmenes por aplicación/UID y reportes de seguridad.

El texto libre del modelo nunca se interpreta como regla. Solo se acepta una salida estructurada (dominio, categoría, acción y confianza), validada por `LocalAiPolicyGate`. Solo publicidad/rastreo con confianza >= 0.92 puede pasar a la política como regla AI administrada. Las reglas manuales del usuario siempre prevalecen; las excepciones de feeds e indicadores importantes conservan su prioridad. El modelo no puede crear reglas para categorías ajenas a publicidad/rastreo ni convertir una sugerencia ALLOW en una excepción permanente.

## Integración técnica: evidencia local preparada; runtime pendiente

Ya está implementado `LocalAiEvidenceBuilder`, con pruebas unitarias, y `FirewallRepository.buildLocalAiSecurityPrompt()` para entregar al futuro coordinador de IA un contexto acotado que consulta las listas locales y resume los eventos reales por UID. El constructor distingue BLOCK/ALLOW/OBSERVE, marca coincidencias con listas y excepciones, limita el volumen de contexto y trata dominios/nombres como datos no confiables. No toma decisiones de filtrado ni se ejecuta en el TUN.

La rama todavía no contiene un runtime GGUF/llama.cpp integrado ni una API local de inferencia. La ruta de aplicación de políticas sí está conectada: `FirewallRepository.applyLocalAiSuggestion()` valida recomendaciones, persiste los dominios AI por separado de las reglas manuales y publica la actualización al motor; `enginePolicyRules()` los exporta como reglas MANAGED con prioridad inferior a reglas del usuario y excepciones/amenazas importantes. `RuleEvaluator` mantiene la misma precedencia en el evaluador local. `FirewallViewModel` expone la entrada al coordinador futuro y la pantalla Protección muestra los dominios AI administrados con acción «Permitir siempre», que crea una excepción manual prioritaria. Antes de inferencia real hay que seleccionar y fijar una versión compatible del runtime Android/NDK, revisar licencia y ABI arm64-v8a, integrar tokenizer/chat template Qwen3 y probar en SM-A346M. No se debe inventar una dependencia Gradle ni introducir una librería no verificada.

La integración debe exponerse como módulo aislado `LocalAiCoordinator` con estados `NOT_INSTALLED`, `DOWNLOADING`, `READY`, `RUNNING`, `UNLOADED` y `ERROR`. El coordinador consume snapshots ya persistidos; nunca recibe buffers de paquetes ni participa en la decisión de flujo del TUN.

## Criterios de aceptación antes de habilitarlo por defecto

- El servicio VPN y las pruebas de filtrado existentes conservan el mismo comportamiento.
- Ninguna llamada de inferencia ocurre desde el hilo TUN, callbacks de Firestack o hilo UI.
- Inicio de FirewallDNS y activación VPN no cargan el GGUF automáticamente.
- La cola de análisis tiene límite fijo, deduplicación y backpressure.
- Se puede descargar el modelo de RAM y recuperar el funcionamiento sin reiniciar la VPN.
- Pruebas instrumentadas miden memoria, latencia, temperatura y batería en el SM-A346M.
- La IA no bloquea dominios por sí sola y sus resultados siempre se identifican como sugerencias/análisis.
- Si no se cumplen los límites de recursos, la función queda apagada y el firewall continúa funcionando normalmente.

## Estado

El constructor de evidencia local por UID/listas, la puerta de decisión, la persistencia de bloqueos administrados por IA, la publicación a la política DNS y la corrección «Permitir siempre» en la pantalla Protección están implementados y cubiertos por pruebas de política. **La inferencia local todavía no está integrada**: no se debe mostrar la IA como activa ni afirmar que el modelo está instalado o que el bloqueo automático por modelo ya funciona hasta que el runtime Android, el coordinador, las pruebas instrumentadas y el APK hayan sido implementados y verificados.
