# FirewallDNS Browser — arquitectura de integración Chromium

Estado: propuesta técnica inicial; todavía no representa funciones implementadas.

## Objetivo

Crear FirewallDNS Browser como navegador Android basado en Chromium completo (Blink/V8), con interfaz propia inspirada en patrones de usabilidad de Brave/Chrome. El navegador no iniciará `VpnService`, no creará TUN y no añadirá telemetría propia.

## Restricciones no negociables

- No modificar ni reemplazar el servicio VPN/TUN que ya utiliza la protección global de FirewallDNS.
- El navegador debe poder navegar directamente con la red Android, incluso cuando el firewall global esté apagado.
- No crear un segundo motor DNS, motor de reglas, motor de amenazas ni base de conocimiento.
- Reutilizar las políticas existentes mediante una API de integración explícita y de bajo coste.
- No afirmar que un dominio, URL o recurso fue bloqueado si Chromium no confirmó que la solicitud se canceló.
- No registrar historial de navegación, URL completas, consultas ni eventos de telemetría adicionales para diagnóstico.
- Mantener Chromium y sus componentes de seguridad actualizados; no distribuir una revisión obsoleta.
- No habilitar depuración remota, interfaces JavaScript genéricas ni puentes inseguros entre páginas web y código nativo.

## Arquitectura propuesta

```
FirewallDNS Browser (aplicación / módulo Android)
  ├── UI: barra, búsqueda, pestañas, favoritos, historial, descargas
  ├── BrowserProfileManager
  │     ├── perfil normal
  │     └── perfil privado efímero
  ├── Chromium Embedder (Chromium Android / Content API)
  │     ├── Blink + V8
  │     ├── aislamiento de procesos / sitios
  │     ├── navegación, recursos, multimedia
  │     └── interceptación de solicitudes soportada por Chromium
  ├── BrowserSecurityAdapter (puente pequeño, sin política duplicada)
  │     ├── evaluación de host y recurso
  │     ├── resultado: ALLOW / OBSERVE / BLOCK
  │     └── cancelación de solicitud confirmada
  └── FirewallDNS Policy Facade
        ├── RuleEvaluator
        ├── SmartDecisionEngine
        ├── ThreatKnowledgeGraph / ThreatAnalyzer
        └── snapshot inmutable de reglas y listas
```

El navegador usa el motor de red de Chromium para las conexiones web. El adaptador consulta la política compartida de FirewallDNS y aplica la decisión en el punto de interceptación de solicitudes de Chromium. No se debe reenviar el tráfico del navegador por el TUN existente.

## Límite crítico: DNS sin VPN

El servicio DNS actual de FirewallDNS está acoplado a la ruta de red del servicio VPN/TUN. Un navegador sin VPN no puede invocar ese transporte como si fuera un resolvedor DNS autónomo. Para obtener filtrado real sin VPN hay que integrar la política en el proceso de resolución/solicitud de Chromium o crear una fachada de política que evalúe hosts antes de cargar recursos, manteniendo el resolvedor de red de Chromium/Android.

La primera entrega no debe declarar «DNS integrado» hasta que se haya demostrado en pruebas que:
1. la consulta/resolución utilizada por Chromium pasa por el punto de control previsto;
2. BLOCK impide la conexión/solicitud antes de enviar el recurso;
3. ALLOW conserva la resolución y carga normales;
4. OBSERVE no bloquea;
5. DoH/DoT, redirecciones, subrecursos, IPv4/IPv6 y cambios de red tienen comportamiento documentado;
6. el modo privado no deja datos persistentes.

No se debe afirmar inspección de DoH/DoT ni filtrado universal de solicitudes si la integración Chromium no expone esos eventos.

## Política de decisiones

- La autoridad de reglas sigue siendo FirewallDNS. No portar ni copiar reglas al navegador.
- La fachada entrega snapshots inmutables/versionados para evitar consultas a disco en cada recurso.
- BLOCK solo se aplica cuando existe evidencia suficiente según la política existente o una regla explícita.
- OBSERVE permite la solicitud; no se transforma en bloqueo por heurística.
- ALLOW permite la solicitud.
- La excepción manual del usuario conserva la prioridad definida por RuleEvaluator.
- Las decisiones de recursos web no deben alterar decisiones DNS ni reglas del firewall global.
- Los fallos del adaptador no deben bloquear navegación legítima: comportamiento fail-open para señales heurísticas; las reglas explícitas de bloqueo deben tener un resultado determinista y probado.

## Privacidad y almacenamiento

- Historial configurable y borrado por intervalo, con almacenamiento local.
- Modo privado: perfil temporal separado; cookies, caché, historial, almacenamiento web y descargas privadas se eliminan al cerrar todas las pestañas privadas. Las descargas guardadas explícitamente por el usuario se tratan como archivos externos y se advierte al salir.
- Contraseñas: Android Autofill Framework / proveedor seguro del sistema; no implementar criptografía propia ni sincronización de credenciales en esta fase.
- Autorrelleno: delegar en Android Autofill Framework.
- Comprobación de contraseñas comprometidas: no enviar contraseñas ni hashes completos a un servicio propio. Requiere diseño de privacidad independiente y consentimiento explícito; se excluye del primer corte.
- Sin telemetría adicional. Las estadísticas existentes del firewall no se duplican ni se alimentan con URLs del navegador.

## Funciones y fases

### Fase 0 — base de Chromium y seguridad
- Decidir estrategia de embedder Chromium Android y fijar revisión upstream.
- Automatizar compilación reproducible por ABI objetivo (inicialmente arm64-v8a).
- Definir actualización de Chromium y proceso de respuesta a CVE.
- Crear BrowserSecurityAdapter y pruebas de contrato.
- Verificar que abrir/cerrar el navegador no inicia VPN/TUN.

### Fase 1 — navegación esencial
- Barra de direcciones y buscador configurable.
- Pestañas múltiples y restauración controlada.
- Favoritos.
- Historial configurable y borrado.
- Descargas con permisos y notificaciones del sistema.
- Modo escritorio.
- Reproducción multimedia y pantalla completa.

### Fase 2 — protección web
- Filtrado de solicitudes de recursos mediante integración nativa de Chromium.
- Bloqueo de anuncios/rastreadores basado en reglas compatibles y listas existentes.
- Escudos por sitio con recuentos derivados de cancelaciones confirmadas, no telemetría duplicada.
- HTTPS: advertencias de certificado/TLS gestionadas por Chromium; nunca omitir errores de certificado.
- Protección contra phishing/malware con fuentes verificadas y política existente.
- Permisos por origen y cookies de terceros mediante APIs soportadas por Chromium.

### Fase 3 — privacidad avanzada
- Perfil privado efímero.
- Limpieza automática por configuración.
- Reducción de fingerprinting con mitigaciones compatibles, sin romper APIs esenciales ni prometer anonimato.
- Traducción mediante proveedor explícito y consentimiento; no enviar páginas privadas sin autorización.
- Navegación segura y actualizaciones de listas de reputación.

### Fase 4 — credenciales y endurecimiento
- Android Autofill Framework y Credential Manager.
- Gestor de contraseñas mediante proveedor seguro del sistema o solución auditada.
- Comprobación de credenciales comprometidas con protocolo de privacidad y consentimiento.
- Auditoría de aislamiento de sitios, sandbox, permisos, descargas y archivos.

## Dependencias y licencias

Chromium completo no es una dependencia Android Maven ligera ni un reemplazo directo de WebView. Requiere un embedder compatible, compilación de Chromium/Content API, artefactos nativos grandes, toolchain y mantenimiento de seguridad continuo. Antes de integrar binarios se debe seleccionar una estrategia mantenida, revisar sus licencias y avisos de terceros, y comprobar que permite el control de solicitudes requerido. No añadir un AAR arbitrario ni una versión antigua de Chromium.

## Criterios de aceptación globales

- No se invoca `VpnService.prepare`, no se inicia `DnsFirewallService` y no se crea TUN al navegar.
- La navegación funciona con FirewallDNS VPN apagado.
- Las decisiones de bloqueo se aplican realmente a solicitudes de Chromium y son verificables con pruebas.
- OBSERVE nunca cancela una solicitud.
- Las reglas y listas tienen una sola autoridad.
- No se duplican bases de datos ni telemetría.
- El modo privado no conserva datos de sesión tras cerrar su perfil.
- Chromium tiene una revisión soportada, parcheada y una ruta de actualización definida.
- Pruebas de regresión en Android 10+ y dispositivo ARM64, incluyendo Wi-Fi/datos móviles, IPv4/IPv6, redirecciones, descargas, multimedia y procesos de pestañas.

## Estado de esta propuesta

Este documento establece la arquitectura y el orden seguro de trabajo. No afirma que Chromium, el navegador ni las funciones enumeradas ya estén incorporados. La siguiente tarea de ingeniería es validar la estrategia de embedder Chromium y su mantenimiento antes de añadir dependencias o modificar el arranque de FirewallDNS.
