# FirewallDNS Browser — arquitectura de integración Chromium/Brave

Estado: arquitectura técnica seleccionada; implementación funcional pendiente.

## Objetivo

Crear FirewallDNS Browser como navegador Android independiente, basado en Chromium completo y actualizado, con interfaz propia y protecciones inspiradas en Brave Shields. Debe navegar por la conectividad normal de Android, sin iniciar `VpnService`, sin crear TUN y sin telemetría adicional del navegador.

## Decisión de plataforma

Se adopta **Brave Core para Android como base de integración y referencia de producto**, no Android WebView ni un AAR Chromium arbitrario.

Repositorios upstream:
- Brave Browser (producto Android y documentación): https://github.com/brave/brave-browser
- Brave Core (personalizaciones y scripts sobre Chromium): https://github.com/brave/brave-core
- Brave adblock-rust (motor de reglas de recursos): https://github.com/brave/adblock-rust
- Chromium (base upstream): https://chromium.googlesource.com/chromium/src

Razones:
- Brave Core mantiene la integración de Chromium y sus cambios específicos.
- El flujo upstream documenta inicialización Android con `pnpm run init --target_os=android --target_arch=arm` y compilación Android con `pnpm run build --target_os=android --target_arch=arm`.
- Brave publica un motor de bloqueo Rust separado (`adblock-rust`) que puede evaluarse e integrarse respetando MPL-2.0 y sus avisos.
- No se debe copiar la aplicación Brave completa ni habilitar automáticamente servicios, métricas, wallets, rewards, VPN, sincronización o endpoints de Brave. Se seleccionarán componentes abiertos y necesarios, verificando licencias y dependencias transitivas.

La rama Chromium/Brave debe fijarse a una revisión estable identificable. No usar `master` flotante en una compilación de producción. Las actualizaciones se realizan mediante el mecanismo upstream de sincronización, revisión de parches y actualización de dependencias; no se declara "actualizado" sin registrar la revisión Chromium exacta incluida en el artefacto.

## Restricciones de arquitectura

- No modificar ni reemplazar el servicio VPN/TUN que protege el resto del dispositivo.
- El navegador debe funcionar con FirewallDNS VPN apagado.
- No crear un segundo motor DNS, motor de reglas, motor de amenazas ni base de conocimiento.
- No crear un segundo servicio VPN, proxy global o TUN.
- No añadir telemetría, analítica de navegación, P3A, informes de uso ni registro adicional de URLs.
- No almacenar contraseñas en texto claro ni implementar criptografía propia.
- No ignorar errores TLS/certificados.
- No afirmar bloqueos que Chromium no haya cancelado realmente.
- No incorporar servicios propietarios de Brave/Google que requieran claves, cuentas o endpoints sin decisión explícita y revisión de privacidad.
- Mantener atribuciones, licencias, avisos y modificaciones exigidas por Chromium, Brave Core, Rust y demás dependencias.

## Arquitectura objetivo

```
FirewallDNS Browser (APK independiente)
  ├── Interfaz Android propia
  │     ├── barra de direcciones / buscador
  │     ├── pestañas / favoritos / historial
  │     ├── descargas / multimedia / traducción
  │     └── panel Shields por sitio
  ├── Perfil normal y perfil privado efímero
  ├── Chromium + Brave Core Android
  │     ├── Blink + V8
  │     ├── Content / Network Service
  │     ├── aislamiento de sitios y sandbox
  │     └── interceptación nativa de solicitudes
  ├── ShieldsAdapter
  │     ├── reglas de recursos / filtros compatibles
  │     ├── mitigaciones de privacidad
  │     └── cancelación verificable de solicitudes
  └── FirewallDNS BrowserPolicyAdapter
        └── fachada de política compartida
              ├── RuleEvaluator / reglas activas
              ├── SmartDecisionEngine
              ├── ThreatKnowledgeGraph / catálogo
              └── snapshot inmutable de listas
```

El navegador utiliza el stack de red Chromium sobre la red Android. La fachada consulta reglas/snapshots de FirewallDNS y toma decisiones sobre hosts/recursos antes de permitir la solicitud. El navegador no reenvía el tráfico por el TUN de FirewallDNS.

## Integración real con el motor FirewallDNS

El repositorio actual tiene `RuleEvaluator`, `SmartDecisionEngine`, `ThreatKnowledgeGraph` y `FirewallRepository`. La autoridad de reglas y listas debe permanecer en FirewallDNS.

La integración debe exponerse como una fachada pequeña, sin que Chromium dependa de clases UI ni del ciclo de vida del servicio VPN:
- Publicar snapshots inmutables y versionados de reglas/listas.
- Canonicalizar hostnames con la lógica existente.
- Traducir el resultado de política a `ALLOW`, `OBSERVE` o `BLOCK`.
- `OBSERVE` siempre permite la solicitud; nunca cancelar por heurística de observación.
- `BLOCK` cancela la solicitud en el punto nativo de control de Chromium.
- Las reglas manuales conservan exactamente la prioridad ya definida por FirewallDNS.
- No realizar I/O de disco, consultas Room ni operaciones de red en el hilo de interceptación.
- Caché local de decisiones por versión de snapshot; invalidar al cambiar listas/reglas.
- Fallo de la fachada: fail-open para señales heurísticas; no mostrar un bloqueo falso. Las reglas explícitas deben tener comportamiento determinista.
- No reutilizar `FirewallRepository.evaluateDomain` sin revisar sus efectos y dependencias; crear una API pura de evaluación compartida o extraer una fachada que no inicialice VPN, workers, estadísticas ni persistencia de actividad.

### Límite DNS sin VPN

El README actual describe el DNS productivo conectado al transporte de Firestack/gVisor y al TUN. Por ello, el navegador sin VPN **no puede afirmar que usa ese transporte DNS**.

Para esta aplicación:
- Chromium/Android resuelve conexiones normalmente.
- FirewallDNS aplica sus reglas de dominio en el punto de control de solicitudes Chromium.
- Las decisiones DNS existentes pueden compartirse como política, no como socket/servicio DNS acoplado al TUN.
- DoH/DoT y resolutores privados no se interceptan ni descifran automáticamente. No afirmar inspección universal.
- Documentar límites de redirecciones, subrecursos, IPv4/IPv6, WebSocket, WebRTC y cambios de red según las APIs nativas efectivamente integradas.

## Funciones del navegador

### Navegación esencial
- Barra de direcciones y buscador configurable.
- Pestañas múltiples, restauración y cierre.
- Marcadores y favoritos.
- Historial configurable y borrado por intervalo.
- Administrador de descargas con progreso y permisos.
- Traducción de páginas mediante proveedor configurable y consentimiento.
- Modo escritorio.
- Audio/vídeo, pantalla completa y controles multimedia.

### Shields y protección web
- Bloqueo de anuncios y rastreadores mediante motor de reglas de recursos compatible (evaluar adblock-rust y listas compatibles).
- Filtros DNS/host de FirewallDNS compartidos sin duplicar listas.
- Excepciones por sitio y escudo visible.
- Contadores del escudo derivados exclusivamente de solicitudes canceladas de verdad; no crear telemetría persistente.
- Bloqueo de cookies de terceros y controles de almacenamiento por sitio.
- Mitigaciones anti-fingerprinting compatibles con Chromium; no prometer anonimato ni romper APIs esenciales por defecto.
- HTTPS, validación de certificados y advertencias TLS nativas; nunca ignorar errores.
- Control de permisos por origen (cámara, micrófono, ubicación, notificaciones).
- Protección frente a phishing/malware con listas/fuentes verificadas y política FirewallDNS.
- Protección de descargas peligrosas y redirecciones abusivas, donde Chromium exponga controles soportados.
- Protección de WebRTC y aislamiento de red/almacenamiento según capacidades reales de Chromium.

### Privacidad y credenciales
- Modo privado con perfil temporal separado; al cerrar todas las pestañas privadas se eliminan cookies, caché, historial y almacenamiento web del perfil.
- Limpieza automática configurable.
- Gestor de contraseñas: Android Credential Manager / Autofill Framework o proveedor seguro auditado; no inventar bóveda criptográfica.
- Autorrelleno delegado al framework Android.
- Comprobación de contraseñas comprometidas: función desactivada hasta disponer de proveedor y protocolo de privacidad adecuados, consentimiento explícito y sin transmitir contraseñas ni hashes completos.
- Traducción y servicios externos deben explicar qué datos se envían y no operar sobre sesiones privadas sin consentimiento.

## Funciones que no se habilitan automáticamente

La referencia a Brave no autoriza activar servicios que no son necesarios para la navegación protegida. Se excluyen de la configuración inicial las funciones con cuentas, pagos, recompensas, wallets, VPN, sincronización propietaria y analítica/telemetría. Podrán evaluarse por separado si el usuario lo solicita y existe una justificación técnica y de privacidad.

## Compilación y mantenimiento

La compilación de Chromium/Brave Android no es una dependencia Gradle pequeña:
- Requiere Linux x86-64, depot_tools, toolchain Android, Node/pnpm según upstream y una descarga de gran tamaño.
- La documentación de Chromium indica al menos 100 GB libres y recomienda más de 16 GB de RAM; la compilación puede tardar horas.
- El destino inicial es Android ARM64 (`arm64-v8a`), coherente con el objetivo actual de FirewallDNS.
- El pipeline debe registrar revisión Chromium, revisión Brave Core, hash de listas de parches, configuración GN, NDK/SDK y versión del compilador.
- Actualizar Chromium mediante una revisión estable soportada y sincronizar dependencias/patches. No seguir una rama móvil sin pin.
- Cada actualización debe incluir los avisos/licencias y la evaluación de CVE aplicables.
- No distribuir APK hasta tener compilación reproducible, firma propia y proceso de actualización funcional.

## Fases de entrega

1. **Base upstream:** seleccionar y fijar revisión estable de Brave Core/Chromium; preparar entorno Linux Android ARM64; validar build nativo.
2. **Aplicación Android:** crear el producto FirewallDNS Browser, launcher, perfiles y ciclo de vida Chromium sin iniciar VPN/TUN.
3. **Policy Adapter:** conectar snapshots y decisiones de FirewallDNS a las solicitudes Chromium, sin I/O en callbacks.
4. **Navegación:** barra, pestañas, favoritos, historial, descargas, escritorio y multimedia.
5. **Shields:** motor de reglas de recursos, listas, bloqueo confirmado, excepciones y panel por sitio.
6. **Privacidad/seguridad:** cookies, permisos, HTTPS, anti-fingerprinting, navegación segura y modo privado.
7. **Credenciales/servicios:** Credential Manager, Autofill, traducción y comprobación de credenciales con consentimiento y proveedor.
8. **Distribución:** empaquetado ARM64, firma, avisos de terceros, actualizador y mantenimiento Chromium/CVE.

## Estado honesto

Este documento fija la estrategia y el contrato de integración. No significa que Chromium, Brave Core, Shields ni la aplicación estén compilados o incorporados al APK. El repositorio Android actual no contiene todavía un checkout de Chromium/Brave Core ni el entorno Linux de compilación.

No se debe sustituir este trabajo por WebView ni declarar terminada una función hasta que exista implementación nativa y el artefacto correspondiente. La fase de validación extensa solicitada por el usuario no se convierte en una campaña separada de pruebas; se mantienen únicamente las comprobaciones mínimas de compilación, seguridad y funcionamiento necesarias para no entregar una aplicación rota.
