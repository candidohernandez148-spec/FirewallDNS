# Política de bloqueo de publicidad mediante IA local

## Comportamiento previsto

La IA local podrá clasificar dominios como publicidad, rastreo u otros y emitir una recomendación estructurada. Solo las recomendaciones de bloqueo de publicidad/rastreo con confianza igual o superior a 0.92 podrán pasar a la fase de aplicación automática. Las demás quedan en OBSERVE; una recomendación ALLOW del modelo no crea una excepción permanente.

## Control del usuario

Las reglas manuales existentes son la autoridad superior:
- «Permitir siempre» crea una regla manual ALLOW que prevalece sobre una sugerencia de bloqueo de IA, también para subdominios.
- «Bloquear siempre» crea una regla manual BLOCK y prevalece sobre una sugerencia ALLOW de IA.
- Las correcciones se guardan en el almacenamiento local de FirewallDNS.

## Implementación y límites actuales

`LocalAiPolicyGate` implementa y prueba el contrato de seguridad: normalización del dominio, precedencia de reglas manuales, umbral de confianza y limitación del bloqueo automático a las categorías ADVERTISING y TRACKER. `FirewallRepository.applyLocalAiSuggestion()` conecta el resultado validado con una lista persistente separada de bloqueos AI, y la exporta al motor DNS como regla administrada. El evaluador mantiene prioridad para reglas manuales, excepciones de listas y amenazas importantes. La pantalla Protección muestra estos dominios y permite corregir cada uno con «Permitir siempre».

**Runtime conectado:** Qwen3-0.6B Q4_K_M se ejecuta localmente mediante llama.cpp. El modelo se descarga en segundo plano solo con conexión no medida y se valida por SHA-256. WorkManager analiza los registros por lotes; la salida JSON pasa por `LocalAiPolicyGate` antes de persistirse. La primera ejecución real depende de que finalice la descarga y haya actividad DNS suficiente.

La inferencia se ejecutará fuera del TUN, callbacks Firestack y UI. El motor actual conserva el bloqueo inmediato y el firewall seguirá funcionando si la IA no está instalada, cargada o disponible.
