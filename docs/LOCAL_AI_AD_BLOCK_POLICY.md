# Política de bloqueo de publicidad mediante IA local

## Comportamiento previsto

La IA local podrá clasificar dominios como publicidad, rastreo u otros y emitir una recomendación estructurada. Solo las recomendaciones de bloqueo de publicidad/rastreo con confianza igual o superior a 0.92 podrán pasar a la fase de aplicación automática. Las demás quedan en OBSERVE; una recomendación ALLOW del modelo no crea una excepción permanente.

## Control del usuario

Las reglas manuales existentes son la autoridad superior:
- «Permitir siempre» crea una regla manual ALLOW que prevalece sobre una sugerencia de bloqueo de IA, también para subdominios.
- «Bloquear siempre» crea una regla manual BLOCK y prevalece sobre una sugerencia ALLOW de IA.
- Las correcciones se guardan en el almacenamiento local de FirewallDNS.

## Implementación y límites actuales

`LocalAiPolicyGate` implementa y prueba el contrato de seguridad: normalización del dominio, precedencia de reglas manuales, umbral de confianza y limitación del bloqueo automático a las categorías ADVERTISING y TRACKER. El gate no modifica reglas ni intercepta tráfico por sí solo.

**Pendiente:** conectar este gate a una inferencia GGUF real y al coordinador local; solo entonces se podrá ejecutar el bloqueo recomendado por el modelo. El runtime GGUF todavía no está integrado, por lo que esta entrega no debe anunciarse como IA activa ni como bloqueo automático ya disponible.

La inferencia se ejecutará fuera del TUN, callbacks Firestack y UI. El motor actual conserva el bloqueo inmediato y el firewall seguirá funcionando si la IA no está instalada, cargada o disponible.
