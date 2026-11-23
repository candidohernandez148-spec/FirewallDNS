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
2. Las decisiones BLOCK/ALLOW/OBSERVE inmediatas siguen a cargo de las reglas deterministas y listas verificadas existentes. La IA no puede retrasar ni reemplazar esas decisiones.
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

No se permite que un texto generado por el modelo cree una regla BLOCK automáticamente. Una sugerencia solo puede convertirse en regla después de validación mediante las políticas deterministas existentes y, cuando corresponda, confirmación del usuario. Esto evita falsos positivos y prompt injection desde nombres de dominio o datos de red no confiables.

## Integración técnica pendiente de implementación

La rama actual no contiene un runtime GGUF/llama.cpp integrado ni una API local de inferencia. Antes de añadir código de ejecución hay que seleccionar y fijar una versión compatible del runtime Android/NDK, revisar su licencia y ABI arm64-v8a, integrar el tokenizer/chat template Qwen3 y añadir pruebas instrumentadas en el SM-A346M. No se debe inventar una dependencia Gradle ni introducir una librería no verificada.

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

Diseño y límites de rendimiento documentados. **La inferencia local todavía no está integrada**: no se debe mostrar la IA como activa ni afirmar que el modelo está instalado hasta que el runtime Android, el coordinador, las pruebas y el APK hayan sido implementados y verificados.
