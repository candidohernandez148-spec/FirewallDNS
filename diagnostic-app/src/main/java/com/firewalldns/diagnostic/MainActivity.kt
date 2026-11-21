package com.firewalldns.diagnostic

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.FileProvider
import com.firewalldns.engine.android.NativeTcpDnsTransport
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.runtime.EngineRuntime
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

private enum class TestStatus { APPROVED, FAILED, NOT_VERIFIED }
private data class TestResult(
    val name: String,
    val status: TestStatus,
    val detail: String,
    val elapsedMs: Long = 0,
)

class MainActivity : Activity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var output: TextView
    private lateinit var runButton: Button
    private lateinit var exportButton: Button
    private var results: List<TestResult> = emptyList()
    private var reportFile: File? = null
    private var beforeMetrics: Map<String, Long> = emptyMap()
    private var afterMetrics: Map<String, Long> = emptyMap()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        render("Listo para diagnosticar. Para probar el tráfico real, instala y activa primero FirewallDNS.")
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 28, 24, 20)
            setBackgroundColor(0xFFF5F7FA.toInt())
        }
        val title = TextView(this).apply {
            text = "FirewallDNS Diagnostic"
            textSize = 24f
            setTextColor(0xFF14243A.toInt())
            setTypeface(null, android.graphics.Typeface.BOLD)
        }
        val subtitle = TextView(this).apply {
            text = "Motor local Kotlin + Rust/JNI · smoltcp · red real · integración VPN"
            textSize = 13f
            setPadding(0, 6, 0, 18)
            setTextColor(0xFF526174.toInt())
        }
        runButton = Button(this).apply {
            text = "EJECUTAR DIAGNÓSTICO COMPLETO"
            setOnClickListener { startDiagnostics() }
        }
        exportButton = Button(this).apply {
            text = "EXPORTAR INFORME ZIP"
            isEnabled = false
            setOnClickListener { shareReport() }
        }
        output = TextView(this).apply {
            textSize = 13f
            setTextColor(0xFF17283D.toInt())
            setPadding(0, 16, 0, 24)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        root.addView(title)
        root.addView(subtitle)
        root.addView(runButton)
        root.addView(exportButton)
        val scroll = ScrollView(this).apply { addView(output) }
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
    }

    private fun startDiagnostics() {
        runButton.isEnabled = false
        exportButton.isEnabled = false
        reportFile = null
        render("Ejecutando pruebas locales y verificaciones del dispositivo…")
        executor.execute {
            val collected = mutableListOf<TestResult>()
            beforeMetrics = readProductionMetrics()
            val systemVpnActive = isVpnActive()
            val firewallDnsActive = systemVpnActive && beforeMetrics["firewallDnsRunning"] == 1L
            collected += timed("FirewallDNS VPN activa") {
                if (firewallDnsActive) TestResult("FirewallDNS VPN activa", TestStatus.APPROVED, "La aplicación principal informa el servicio activo y Android informa transporte VPN.")
                else TestResult("FirewallDNS VPN activa", TestStatus.NOT_VERIFIED, "Activa el servicio VPN de FirewallDNS; otra VPN del sistema no es suficiente.")
            }
            collected += runPolicyTest("Política BLOCK", PolicyAction.BLOCK)
            collected += runPolicyTest("Política OBSERVE", PolicyAction.OBSERVE)
            collected += runPolicyTest("Política ALLOW", PolicyAction.ALLOW)
            collected += timed("Inteligencia integrada: dominio publicitario conocido") {
                val result = EngineRuntime().evaluateDns(buildDnsQuery("doubleclick.net"))
                if (result is DnsEvaluation.Blocked && result.decision.action == PolicyAction.BLOCK)
                    TestResult("", TestStatus.APPROVED, "El indicador integrado de doubleclick.net produjo BLOCK.")
                else TestResult("", TestStatus.FAILED, "No se bloqueó el dominio publicitario de prueba.")
            }
            collected += timed("Excepción ALLOW sobre indicador integrado") {
                val runtime = EngineRuntime(initialRules = listOf(
                    PolicyRule("diagnostic-allow-override", "doubleclick.net",
                        action = PolicyAction.ALLOW, source = RuleSource.USER,
                        priority = 1000, reason = "diagnostic_allow_override")
                ))
                val result = runtime.evaluateDns(buildDnsQuery("doubleclick.net"))
                if (result is DnsEvaluation.Forward && result.decision.action == PolicyAction.ALLOW)
                    TestResult("", TestStatus.APPROVED, "La regla de usuario ALLOW prevaleció sobre el indicador integrado.")
                else TestResult("", TestStatus.FAILED, "La excepción ALLOW no prevaleció.")
            }
            collected += timed("Reglas por aplicación (laboratorio)") {
                val runtime = EngineRuntime(initialRules = listOf(
                    PolicyRule("diagnostic-app-rule", "app-probe.invalid",
                        appPackage = "com.example.diagnostic.probe",
                        action = PolicyAction.BLOCK, source = RuleSource.USER,
                        priority = 100, reason = "diagnostic_app_policy")
                ))
                val blocked = runtime.evaluateDns(buildDnsQuery("app-probe.invalid"), "com.example.diagnostic.probe")
                val allowed = runtime.evaluateDns(buildDnsQuery("app-probe.invalid"), "com.example.other")
                if (blocked is DnsEvaluation.Blocked && allowed is DnsEvaluation.Forward)
                    TestResult("", TestStatus.APPROVED, "La regla distingue el paquete indicado en el motor.")
                else TestResult("", TestStatus.FAILED, "La evaluación por paquete no produjo el resultado esperado.")
            }
            collected += timed("DNS malformado") {
                val result = EngineRuntime().evaluateDns(byteArrayOf(0x01, 0x02))
                if (result is DnsEvaluation.Rejected) TestResult("", TestStatus.APPROVED, "El motor rechazó un paquete DNS truncado.")
                else TestResult("", TestStatus.FAILED, "El paquete DNS truncado no fue rechazado.")
            }
            collected += timed("smoltcp nativo IPv4/IPv6") { testNativeTransport() }
            collected += timed("JNI: límites, cola y propiedad del hilo") { testNativeTransportGuards() }
            collected += TestResult("Reensamblado de fragmentos IPv4/IPv6", TestStatus.NOT_VERIFIED,
                "El APK no inyecta fragmentos en el TUN productivo; requiere una prueba instrumentada del servicio.")
            collected += TestResult("Aprendizaje inteligente persistente", TestStatus.NOT_VERIFIED,
                "Se requiere exponer el estado real de aprendizaje/Room y verificar una regla aprendida entre reinicios.")
            collected += TestResult("Actualización e integridad de listas", TestStatus.NOT_VERIFIED,
                "Se requiere consultar el estado del repositorio de listas, sus hashes y fecha de actualización.")
            collected += TestResult("Cobertura DoH/DoT/DoQ", TestStatus.NOT_VERIFIED,
                "DNS/53 no permite afirmar inspección de DoH, DoT o DoQ; estas rutas quedan fuera de esta prueba.")
            collected += TestResult("Estabilidad prolongada, CPU y batería", TestStatus.NOT_VERIFIED,
                "Requiere una sesión de carga prolongada y medición energética en el dispositivo.")

            val bridgeAvailable = beforeMetrics.isNotEmpty()
            collected += if (bridgeAvailable) {
                TestResult("Puente de métricas FirewallDNS", TestStatus.APPROVED, "Conexión de solo lectura a métricas agregadas.")
            } else {
                TestResult("Puente de métricas FirewallDNS", TestStatus.NOT_VERIFIED, "No se pudo leer el proveedor protegido. Reinstala ambos APK del mismo paquete de compilación.")
            }
            collected += when {
                !firewallDnsActive -> TestResult("Transporte smoltcp productivo", TestStatus.NOT_VERIFIED, "Activa FirewallDNS para verificar la instancia del transporte en el servicio real.")
                beforeMetrics["smoltcpTransportAvailable"] == 1L -> TestResult("Transporte smoltcp productivo", TestStatus.APPROVED, "El servicio productivo informa que el transporte nativo está inicializado.")
                else -> TestResult("Transporte smoltcp productivo", TestStatus.FAILED, "FirewallDNS informa VPN activa, pero el transporte smoltcp no está disponible.")
            }

            if (firewallDnsActive && bridgeAvailable) {
                val ipv4ProbeDns = chooseIpv4ProbeDns()
                collected += timed("DNS UDP IPv4 por VPN") { probeUdp(ipv4ProbeDns, "IPv4 UDP") }
                collected += timed("DNS TCP IPv4 por VPN (smoltcp)") { probeTcp(ipv4ProbeDns, "IPv4 TCP") }
                val hasIpv6 = hasGlobalIpv6()
                if (hasIpv6) {
                    collected += timed("DNS UDP IPv6 por VPN") { probeUdp("2606:4700:4700::1111", "IPv6 UDP") }
                    collected += timed("DNS TCP IPv6 por VPN (smoltcp)") { probeTcp("2606:4700:4700::1111", "IPv6 TCP") }
                } else {
                    collected += TestResult("DNS UDP IPv6 por VPN", TestStatus.NOT_VERIFIED, "La red activa no anuncia una dirección IPv6 global.")
                    collected += TestResult("DNS TCP IPv6 por VPN (smoltcp)", TestStatus.NOT_VERIFIED, "La red activa no anuncia una dirección IPv6 global.")
                }
            } else {
                collected += TestResult("DNS UDP IPv4 por VPN", TestStatus.NOT_VERIFIED, "Requiere FirewallDNS activo y métricas accesibles.")
                collected += TestResult("DNS TCP IPv4 por VPN (smoltcp)", TestStatus.NOT_VERIFIED, "Requiere FirewallDNS activo y métricas accesibles.")
                collected += TestResult("DNS UDP IPv6 por VPN", TestStatus.NOT_VERIFIED, "Requiere FirewallDNS activo, métricas y conectividad IPv6.")
                collected += TestResult("DNS TCP IPv6 por VPN (smoltcp)", TestStatus.NOT_VERIFIED, "Requiere FirewallDNS activo, métricas y conectividad IPv6.")
            }

            afterMetrics = readProductionMetrics()
            if (firewallDnsActive && bridgeAvailable) {
                collected += metricDeltaResult("Contador TUN DNS UDP", "dnsUdpPackets")
                collected += metricDeltaResult("Contador TUN DNS TCP", "dnsTcp")
                collected += metricDeltaResult("Sesiones smoltcp abiertas", "smoltcpSessionsOpened")
                collected += protectUdpResult()
                collected += metricDeltaResult("Rechazos internos smoltcp", "smoltcpIngressRejected", expectIncrease = false)
                collected += metricDeltaResult("Errores nativos smoltcp", "smoltcpNativeErrors", expectIncrease = false)
                collected += metricDeltaResult("Paquetes rechazados por cola", "queueRejected", expectIncrease = false)
                collected += metricDeltaResult("Errores de escritura TUN", "writeErrors", expectIncrease = false)
            } else {
                listOf("Contador TUN DNS UDP", "Contador TUN DNS TCP", "Sesiones smoltcp abiertas",
                    "Protect UDP upstream", "Rechazos internos smoltcp", "Errores nativos smoltcp", "Paquetes rechazados por cola", "Errores de escritura TUN")
                    .forEach { collected += TestResult(it, TestStatus.NOT_VERIFIED, "No hubo una sesión VPN verificable durante la prueba.") }
            }

            results = collected
            val file = createReport(collected)
            reportFile = file
            runOnUiThread {
                runButton.isEnabled = true
                exportButton.isEnabled = file != null
                render(formatResults(collected) + "\n\nInforme: " + (file?.name ?: "no generado"))
            }
        }
    }

    private fun runPolicyTest(label: String, action: PolicyAction): TestResult = timed(label) {
        val domain = "probe-${action.name.lowercase()}.invalid"
        val runtime = EngineRuntime(
            initialRules = listOf(
                PolicyRule(
                    id = "diagnostic-${action.name.lowercase()}",
                    domain = domain,
                    action = action,
                    source = RuleSource.USER,
                    priority = 100,
                    reason = "diagnostic_policy_probe",
                )
            )
        )
        val result = runtime.evaluateDns(buildDnsQuery(domain))
        val passed = when (action) {
            PolicyAction.BLOCK -> result is DnsEvaluation.Blocked
            PolicyAction.OBSERVE -> result is DnsEvaluation.Forward && result.decision.action == PolicyAction.OBSERVE
            PolicyAction.ALLOW -> result is DnsEvaluation.Forward && result.decision.action == PolicyAction.ALLOW
        }
        if (passed) TestResult("", TestStatus.APPROVED, "El motor aplicó $action correctamente.")
        else TestResult("", TestStatus.FAILED, "Resultado inesperado para $action: ${result::class.simpleName}.")
    }

    private fun testNativeTransport(): TestResult {
        val v4Dns = byteArrayOf(10, 77, 0, 1)
        val v4Client = byteArrayOf(10, 77, 0, 2)
        val v6Dns = ByteArray(16).apply {
            this[0] = 0x20.toByte(); this[1] = 0x01.toByte()
            this[2] = 0x0d.toByte(); this[3] = 0xb8.toByte(); this[15] = 1
        }
        val v6Client = v6Dns.copyOf().apply { this[15] = 2 }
        return try {
            val transport = NativeTcpDnsTransport.create(1500, v4Dns, v4Client, v6Dns, v6Client, 16)
                ?: return TestResult("", TestStatus.FAILED, "JNI no pudo crear la instancia smoltcp.")
            transport.use { native ->
                // These calls exercise the packaged Rust .so, not a Kotlin mock.
                val emptyPacket = native.enqueuePacket(byteArrayOf())
                val oversizedPacket = native.enqueuePacket(ByteArray(1501))
                val pollResult = native.poll(SystemClock.elapsedRealtime(), 0)
                val missingSession = native.queueResponse(
                    Long.MAX_VALUE,
                    byteArrayOf(0, 12, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0),
                )
                val noUnexpectedOutput = native.takePacket() == null && native.takeEvent() == null

                val wrongOwnerResult = AtomicInteger(Int.MIN_VALUE)
                val otherThread = Thread {
                    wrongOwnerResult.set(native.poll(SystemClock.elapsedRealtime(), 0))
                }.apply { name = "diagnostic-wrong-owner-probe"; start() }
                otherThread.join(2_000)

                val checks = listOf(
                    "poll=$pollResult" to (pollResult >= 0),
                    "empty=$emptyPacket" to (emptyPacket == -1),
                    "oversized=$oversizedPacket" to (oversizedPacket == -1),
                    "missingSession=$missingSession" to (missingSession == -5),
                    "ownerGuard=${wrongOwnerResult.get()}" to (wrongOwnerResult.get() == -3),
                    "emptyQueues=$noUnexpectedOutput" to noUnexpectedOutput,
                )
                val failures = checks.filterNot { it.second }.map { it.first }
                if (otherThread.isAlive) {
                    otherThread.interrupt()
                    return@use TestResult("", TestStatus.FAILED, "La prueba de exclusividad del hilo no terminó.")
                }
                if (failures.isEmpty()) {
                    TestResult("", TestStatus.APPROVED,
                        "Rust/JNI smoltcp IPv4+IPv6 inicializado; validación de paquetes, sesión inexistente, colas vacías y protección del hilo propietario correctas.")
                } else {
                    TestResult("", TestStatus.FAILED,
                        "Fallaron comprobaciones nativas: ${failures.joinToString()}.")
                }
            }
        } catch (t: Throwable) {
            TestResult("", TestStatus.FAILED, "Error JNI: ${t.javaClass.simpleName}: ${t.message ?: "sin detalle"}")
        }
    }

    /** Exercises the packaged JNI boundary, not merely native library loading. */
    private fun testNativeTransportGuards(): TestResult {
        val v4Dns = byteArrayOf(10, 77, 0, 1)
        val v4Client = byteArrayOf(10, 77, 0, 2)
        val v6Dns = ByteArray(16).apply {
            this[0] = 0x20.toByte()
            this[1] = 0x01.toByte()
            this[2] = 0x0d.toByte()
            this[3] = 0xb8.toByte()
            this[15] = 1
        }
        val v6Client = v6Dns.copyOf().apply { this[15] = 2 }
        return try {
            val transport = NativeTcpDnsTransport.create(1500, v4Dns, v4Client, v6Dns, v6Client, 16)
                ?: return TestResult("", TestStatus.FAILED, "JNI no pudo crear el transporte.")
            transport.use {
                val firstPoll = it.poll(SystemClock.elapsedRealtime(), 0)
                val emptyPacket = it.enqueuePacket(byteArrayOf())
                val oversizedPacket = it.enqueuePacket(ByteArray(1501))
                val missingSession = it.queueResponse(
                    9_999_999L,
                    byteArrayOf(0, 12) + ByteArray(12),
                )
                val rejectedPackets = it.rejectedPackets()
                val crossThreadResult = AtomicInteger(Int.MIN_VALUE)
                val worker = Thread {
                    crossThreadResult.set(it.poll(SystemClock.elapsedRealtime(), 0))
                }
                worker.start()
                worker.join(2_000)
                val threadFinished = !worker.isAlive
                if (!threadFinished) worker.interrupt()

                val checks = listOf(
                    firstPoll >= 0,
                    emptyPacket == -1,
                    oversizedPacket == -1,
                    missingSession == -5,
                    rejectedPackets == 2L,
                    threadFinished && crossThreadResult.get() == -3,
                )
                if (checks.all { passed -> passed }) {
                    TestResult(
                        "",
                        TestStatus.APPROVED,
                        "JNI operativo: cuenta ambos rechazos (paquete vacío y mayor al MTU), rechaza sesiones inexistentes y protege smoltcp contra acceso desde otro hilo.",
                    )
                } else {
                    TestResult(
                        "",
                        TestStatus.FAILED,
                        "Falló una guarda JNI: poll=" + firstPoll + ", vacío=" + emptyPacket +
                            ", MTU=" + oversizedPacket + ", sesión=" + missingSession +
                            ", rechazos=" + rejectedPackets + ", hilo=" + crossThreadResult.get() +
                            ", finalizó=" + threadFinished + ".",
                    )
                }
            }
        } catch (t: Throwable) {
            TestResult("", TestStatus.FAILED, "Error en pruebas JNI: " + t.javaClass.simpleName + ": " + (t.message ?: "sin detalle"))
        }
    }

    private fun probeUdp(host: String, label: String): TestResult {
        val query = buildDnsQuery("probe-${SystemClock.elapsedRealtimeNanos()}.example.com")
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 3500
                val address = InetAddress.getByName(host)
                socket.connect(address, 53)
                socket.send(DatagramPacket(query, query.size))
                val buffer = ByteArray(2048)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                val valid = validDnsResponse(query, buffer.copyOf(response.length))
                if (valid) TestResult("", TestStatus.APPROVED, "$label respondió a través del túnel.")
                else TestResult("", TestStatus.FAILED, "$label devolvió una respuesta DNS inválida.")
            }
        } catch (t: Throwable) {
            TestResult("", TestStatus.FAILED, "$label: ${t.javaClass.simpleName}: ${t.message ?: "sin respuesta"}")
        }
    }

    private fun probeTcp(host: String, label: String): TestResult {
        val query = buildDnsQuery("probe-${SystemClock.elapsedRealtimeNanos()}.example.com")
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(InetAddress.getByName(host), 53), 3500)
                socket.soTimeout = 3500
                val data = DataOutputStream(BufferedOutputStream(socket.getOutputStream()))
                data.writeShort(query.size)
                data.write(query)
                data.flush()
                val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
                val length = input.readUnsignedShort()
                if (length !in 12..4096) return TestResult("", TestStatus.FAILED, "$label anunció una longitud DNS inválida.")
                val response = ByteArray(length)
                input.readFully(response)
                if (validDnsResponse(query, response)) TestResult("", TestStatus.APPROVED, "$label completó conexión, framing DNS y respuesta.")
                else TestResult("", TestStatus.FAILED, "$label devolvió una respuesta DNS inválida.")
            }
        } catch (t: Throwable) {
            TestResult("", TestStatus.FAILED, "$label: ${t.javaClass.simpleName}: ${t.message ?: "sin respuesta"}")
        }
    }

    private fun protectUdpResult(): TestResult {
        val beforeAttempts = beforeMetrics["upstreamProtectUdpAttempts"]
            ?: return TestResult("Protect UDP upstream", TestStatus.NOT_VERIFIED, "Métrica de intentos no disponible.")
        val afterAttempts = afterMetrics["upstreamProtectUdpAttempts"]
            ?: return TestResult("Protect UDP upstream", TestStatus.NOT_VERIFIED, "Métrica de intentos no disponible.")
        val attempts = afterAttempts - beforeAttempts
        if (attempts <= 0L) {
            return TestResult("Protect UDP upstream", TestStatus.NOT_VERIFIED, "No se observó un intento upstream UDP durante las consultas de prueba.")
        }
        val successes = (afterMetrics["upstreamProtectUdpSuccess"] ?: beforeMetrics["upstreamProtectUdpSuccess"] ?: 0L) -
            (beforeMetrics["upstreamProtectUdpSuccess"] ?: 0L)
        val failures = (afterMetrics["upstreamProtectUdpFailure"] ?: beforeMetrics["upstreamProtectUdpFailure"] ?: 0L) -
            (beforeMetrics["upstreamProtectUdpFailure"] ?: 0L)
        val passed = successes == attempts && failures == 0L
        return TestResult(
            "Protect UDP upstream",
            if (passed) TestStatus.APPROVED else TestStatus.FAILED,
            "Intentos=$attempts, protect true=$successes, protect false=$failures."
        )
    }

    private fun metricDeltaResult(
        label: String,
        key: String,
        expectIncrease: Boolean = true,
    ): TestResult {
        val before = beforeMetrics[key] ?: return TestResult(label, TestStatus.NOT_VERIFIED, "Métrica no disponible.")
        val after = afterMetrics[key] ?: return TestResult(label, TestStatus.NOT_VERIFIED, "Métrica no disponible.")
        val delta = after - before
        val passed = if (expectIncrease) delta > 0 else delta == 0L
        return TestResult(label, if (passed) TestStatus.APPROVED else TestStatus.FAILED,
            "Valor inicial=$before, final=$after, variación=$delta.")
    }

    private fun timed(label: String, block: () -> TestResult): TestResult {
        val start = SystemClock.elapsedRealtime()
        val result = runCatching(block).getOrElse {
            TestResult("", TestStatus.FAILED, "${it.javaClass.simpleName}: ${it.message ?: "error"}")
        }
        return result.copy(name = label, elapsedMs = SystemClock.elapsedRealtime() - start)
    }

    private fun readProductionMetrics(): Map<String, Long> = runCatching {
        val uri = Uri.parse("content://com.firewall.dns.diagnostics/snapshot")
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            buildMap {
                val nameIndex = cursor.getColumnIndexOrThrow("metric")
                val valueIndex = cursor.getColumnIndexOrThrow("value")
                while (cursor.moveToNext()) put(cursor.getString(nameIndex), cursor.getLong(valueIndex))
            }
        }.orEmpty()
    }.getOrDefault(emptyMap())

    private fun isVpnActive(): Boolean {
        val manager = getSystemService(ConnectivityManager::class.java)
        val network = manager.activeNetwork ?: return false
        return manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    /**
     * Avoids the selected physical upstream: its route is intentionally excluded
     * from the VPN to prevent recursion, so probing it would bypass the TUN.
     */
    private fun chooseIpv4ProbeDns(): String {
        val manager = getSystemService(ConnectivityManager::class.java)
        val active = manager.activeNetwork
        val activeCaps = active?.let { manager.getNetworkCapabilities(it) }
        val physical = if (active != null && activeCaps != null &&
            activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        ) {
            active
        } else {
            manager.allNetworks.firstOrNull { network ->
                manager.getNetworkCapabilities(network)?.let { caps ->
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                } == true
            }
        }
        val upstream = physical?.let { network ->
            manager.getLinkProperties(network)?.dnsServers?.firstOrNull()?.hostAddress?.substringBefore('%')
        } ?: "1.1.1.1"
        return listOf("1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4")
            .firstOrNull { it != upstream } ?: "8.8.8.8"
    }

    private fun hasGlobalIpv6(): Boolean {
        val manager = getSystemService(ConnectivityManager::class.java)
        val network = manager.activeNetwork ?: return false
        return manager.getLinkProperties(network)?.linkAddresses?.any {
            val address = it.address
            address is Inet6Address && !address.isLinkLocalAddress && !address.isLoopbackAddress
        } == true
    }

    private fun buildDnsQuery(domain: String): ByteArray {
        val labels = domain.split('.')
        val qname = labels.flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        }.toByteArray() + byteArrayOf(0)
        val id = (System.nanoTime() and 0xffff).toInt()
        val header = byteArrayOf(
            (id shr 8).toByte(), id.toByte(), 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        )
        return header + qname + byteArrayOf(0x00, 0x01, 0x00, 0x01)
    }

    private fun validDnsResponse(query: ByteArray, response: ByteArray): Boolean =
        response.size >= 12 &&
            response[0] == query[0] && response[1] == query[1] &&
            (response[2].toInt() and 0x80) != 0

    private fun createReport(items: List<TestResult>): File? = runCatching {
        val directory = File(filesDir, "diagnostics").apply { mkdirs() }
        val file = File(directory, "FirewallDNS_Diagnostico_${System.currentTimeMillis()}.zip")
        val json = buildJson(items)
        val text = formatResults(items)
        ZipOutputStream(BufferedOutputStream(file.outputStream())).use { zip ->
            zip.putNextEntry(ZipEntry("diagnostico.json"))
            zip.write(json.toByteArray(Charsets.UTF_8))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("diagnostico.txt"))
            zip.write(text.toByteArray(Charsets.UTF_8))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("metricas_iniciales.csv"))
            zip.write(metricsCsv(beforeMetrics).toByteArray(Charsets.UTF_8))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("metricas_finales.csv"))
            zip.write(metricsCsv(afterMetrics).toByteArray(Charsets.UTF_8))
            zip.closeEntry()
        }
        file
    }.getOrNull()

    private fun buildJson(items: List<TestResult>): String {
        val device = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".replace("\"", "'")
        val body = items.joinToString(",\n") {
            """    {"test":"${jsonEscape(it.name)}","status":"${it.status}","elapsed_ms":${it.elapsedMs},"detail":"${jsonEscape(it.detail)}"}"""
        }
        return """{
  "format": "FirewallDNS diagnostic v1",
  "created_at_epoch_ms": ${System.currentTimeMillis()},
  "device": "${jsonEscape(device)}",
  "android_sdk": ${android.os.Build.VERSION.SDK_INT},
  "system_vpn_active": ${isVpnActive()},
  "firewall_dns_active": ${beforeMetrics["firewallDnsRunning"] == 1L && isVpnActive()},
  "results": [
$body
  ]
}
"""
    }

    private fun jsonEscape(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", " ")
        .replace("\r", " ")

    private fun metricsCsv(metrics: Map<String, Long>): String =
        "metric,value\n" + metrics.toSortedMap().entries.joinToString("\n") { "${it.key},${it.value}" } + "\n"

    private fun formatResults(items: List<TestResult>): String {
        val counts = TestStatus.entries.associateWith { status -> items.count { it.status == status } }
        val lines = items.joinToString("\n\n") {
            val marker = when (it.status) {
                TestStatus.APPROVED -> "APROBADO"
                TestStatus.FAILED -> "FALLIDO"
                TestStatus.NOT_VERIFIED -> "NO VERIFICADO"
            }
            "$marker · ${it.name} (${it.elapsedMs} ms)\n${it.detail}"
        }
        return "RESUMEN\nAprobado: ${counts[TestStatus.APPROVED]}  Fallido: ${counts[TestStatus.FAILED]}  No verificado: ${counts[TestStatus.NOT_VERIFIED]}\n\n$lines"
    }

    private fun render(message: String) {
        if (::output.isInitialized) output.text = message
    }

    private fun shareReport() {
        val file = reportFile ?: return
        val uri = FileProvider.getUriForFile(this, "$packageName.files", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/zip"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(intent, "Compartir diagnóstico FirewallDNS"))
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
