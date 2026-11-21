package com.firewall.dns.data.local

import android.content.Context
import android.util.AtomicFile
import com.firewall.dns.domain.engine.BlocklistSourcePolicy
import com.firewall.dns.domain.engine.RuleEvaluator
import com.firewall.dns.domain.engine.ThreatFeedCatalog
import com.firewall.dns.domain.engine.ThreatFeedCategory
import com.firewall.dns.domain.engine.ThreatFeedIntegrityPolicy
import com.firewall.dns.domain.engine.ThreatFeedSignatureConfig
import com.firewall.dns.domain.engine.ThreatFeedSignaturePolicy
import com.firewall.dns.domain.model.BlocklistDownloadProgress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

data class BlocklistSnapshot(
    val blocked: Set<String>,
    val exceptions: Set<String>,
    val threatDomainsByCategory: Map<ThreatFeedCategory, Set<String>>,
    val summary: String = ""
)

class BlocklistDataSource(context: Context) {
    private val filesDir: File = context.applicationContext.filesDir
    private val sourceCacheDir: File = File(filesDir, "blocklist_sources")

    companion object {
        private const val ADBLOCK_FILE_NAME = "adblock_rules.txt"
        private const val CATEGORY_PREFIX = "! FirewallDNS-CATEGORY\t"
        private const val MAX_SOURCE_BYTES = 8 * 1024 * 1024
        private const val MAX_SIGNATURE_BYTES = 16 * 1024
        private const val MAX_SOURCE_LINES = 200_000
        private const val MAX_LINE_CHARS = 4_096
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 25_000
    }

    fun hasSavedBlocklists(): Boolean = File(filesDir, ADBLOCK_FILE_NAME).let { it.isFile && it.length() > 0L }

    /** Removes only the downloaded aggregate; built-in and user rules live elsewhere. */
    fun clearSavedBlocklists() {
        AtomicFile(File(filesDir, ADBLOCK_FILE_NAME)).delete()
    }

    fun loadFromDisk(defaultDomains: List<String>): BlocklistSnapshot {
        val blocked = HashSet<String>(defaultDomains)
        val exceptions = HashSet<String>()
        val categories = ThreatFeedCategory.values().associateWith { HashSet<String>() }.toMutableMap()
        val file = File(filesDir, ADBLOCK_FILE_NAME)
        if (file.exists()) {
            file.bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
                lines.forEach { line ->
                    if (line.startsWith(CATEGORY_PREFIX)) {
                        val parts = line.removePrefix(CATEGORY_PREFIX).split('\t')
                        if (parts.size == 2) {
                            val category = runCatching { ThreatFeedCategory.valueOf(parts[0]) }.getOrNull()
                            val domain = RuleEvaluator.canonicalizeDomain(parts[1])
                            if (category != null && category != ThreatFeedCategory.GENERAL && domain != null) {
                                categories.getValue(category).add(domain)
                            }
                        }
                    } else {
                        RuleEvaluator.parseAdblockLine(line)?.let { parsed ->
                            if (parsed.isException) exceptions.add(parsed.domain) else blocked.add(parsed.domain)
                        }
                    }
                }
            }
        }
        return BlocklistSnapshot(
            blocked = blocked,
            exceptions = exceptions,
            threatDomainsByCategory = categories.mapValues { it.value.toSet() }
        )
    }

    suspend fun downloadMultipleAndSave(
        defaultDomains: List<String>,
        urls: List<String>,
        signedFeeds: Map<String, ThreatFeedSignatureConfig> = emptyMap(),
        onProgress: (BlocklistDownloadProgress) -> Unit = {}
    ): Result<BlocklistSnapshot> = withContext(Dispatchers.IO) {
        val configuredUrls = urls.map(String::trim).filter(String::isNotEmpty)
        if (configuredUrls.isEmpty()) {
            return@withContext Result.failure(IllegalArgumentException("Agrega al menos una URL HTTPS en sintaxis Adblock"))
        }
        val normalizedUrls = ArrayList<String>(configuredUrls.size)
        for (raw in configuredUrls) {
            val normalized = BlocklistSourcePolicy.canonicalize(raw)
                ?: return@withContext Result.failure(IllegalArgumentException("Fuente HTTPS inválida: $raw"))
            normalizedUrls.add(normalized)
        }
        val uniqueUrls = normalizedUrls.distinct()

        val blocked = HashSet<String>(defaultDomains)
        val exceptions = HashSet<String>()
        val categoryDomains = ThreatFeedCategory.values().associateWith { HashSet<String>() }.toMutableMap()
        var lastError: Exception? = null
        val completedSources = HashSet<String>()
        val sourceDigests = ArrayList<String>()
        var totalParsedRules = 0
        var verifiedSignedSources = 0
        var unsignedSources = 0

        for ((sourceIndex, targetUrl) in uniqueUrls.withIndex()) {
            if (!BlocklistSourcePolicy.isAllowed(targetUrl)) {
                lastError = IllegalArgumentException("Fuente rechazada: solo HTTPS en puerto 443, sin credenciales ni fragmentos")
                continue
            }

            var connection: HttpURLConnection? = null
            try {
                connection = (URL(targetUrl).openConnection() as HttpURLConnection).apply {
                    connectTimeout = CONNECT_TIMEOUT_MS
                    readTimeout = READ_TIMEOUT_MS
                    instanceFollowRedirects = false
                    setRequestProperty("Cache-Control", "no-cache, no-store")
                    setRequestProperty("Pragma", "no-cache")
                    setRequestProperty("User-Agent", "FirewallDNS/1.0")
                    setRequestProperty("Accept", "text/plain, application/octet-stream;q=0.9")
                }
                val status = connection.responseCode
                if (status != HttpURLConnection.HTTP_OK) {
                    throw IllegalStateException("HTTP $status; no se siguen redirecciones")
                }
                val declaredLength = connection.getHeaderFieldLong("Content-Length", -1L)
                if (declaredLength > MAX_SOURCE_BYTES) throw IllegalStateException("La lista supera 8 MiB")
                onProgress(BlocklistDownloadProgress(sourceIndex + 1, uniqueUrls.size,
                    "Descargando", 0L, declaredLength))

                val payload = connection.inputStream.use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(8 * 1024)
                    var total = 0
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > MAX_SOURCE_BYTES) throw IllegalStateException("La lista supera 8 MiB")
                        output.write(buffer, 0, count)
                        onProgress(BlocklistDownloadProgress(sourceIndex + 1, uniqueUrls.size, "Descargando", total.toLong(), declaredLength))
                    }
                    output.toByteArray()
                }
                onProgress(BlocklistDownloadProgress(sourceIndex + 1, uniqueUrls.size, "Validando", payload.size.toLong(), declaredLength))

                val signatureConfig = signedFeeds.entries.firstOrNull {
                    BlocklistSourcePolicy.canonicalize(it.key) == targetUrl
                }?.value
                if (signatureConfig == null) {
                    unsignedSources++
                } else {
                    val detachedSignature = downloadDetachedSignature(signatureConfig.signatureUrl)
                    if (!ThreatFeedSignaturePolicy.verifyRsaSha256(
                            payload,
                            detachedSignature,
                            signatureConfig.publicKeyX509
                        )
                    ) {
                        throw IllegalStateException("Firma digital no válida para la fuente: $targetUrl")
                    }
                    verifiedSignedSources++
                }

                val sourceBlocked = HashSet<String>()
                val sourceExceptions = HashSet<String>()
                var lineCount = 0
                var parsedRuleCount = 0
                String(payload, StandardCharsets.UTF_8).lineSequence().forEach { line ->
                    lineCount++
                    if (lineCount > MAX_SOURCE_LINES) throw IllegalStateException("La lista supera 200,000 líneas")
                    if (line.length > MAX_LINE_CHARS) throw IllegalStateException("La lista contiene una línea demasiado larga")
                    RuleEvaluator.parseAdblockLine(line)?.let { parsed ->
                        parsedRuleCount++
                        if (parsed.isException) sourceExceptions.add(parsed.domain) else sourceBlocked.add(parsed.domain)
                    }
                }
                ThreatFeedIntegrityPolicy.validateSource(payload.size, parsedRuleCount)?.let { message ->
                    throw IllegalStateException("$message: $targetUrl")
                }

                totalParsedRules += parsedRuleCount
                sourceDigests += ThreatFeedIntegrityPolicy.sha256(payload)
                blocked.addAll(sourceBlocked)
                exceptions.addAll(sourceExceptions)
                val category = ThreatFeedCatalog.categoryForUrl(targetUrl)
                if (category != ThreatFeedCategory.GENERAL) {
                    categoryDomains.getValue(category).addAll(sourceBlocked)
                }
                completedSources.add(targetUrl)
            } catch (error: Exception) {
                lastError = error
            } finally {
                connection?.disconnect()
            }
        }

        if (completedSources.size != uniqueUrls.size) {
            return@withContext Result.failure(lastError ?: IllegalStateException("No se pudieron validar todas las listas; se conserva la versión anterior"))
        }

        onProgress(BlocklistDownloadProgress(uniqueUrls.size, uniqueUrls.size, "Aplicando", 1L, 1L))
        val outputFile = File(filesDir, ADBLOCK_FILE_NAME)
        val atomicFile = AtomicFile(outputFile)
        var stream: FileOutputStream? = null
        try {
            val outputStream = atomicFile.startWrite()
            stream = outputStream
            val writer = OutputStreamWriter(outputStream, StandardCharsets.UTF_8).buffered()
            categoryDomains.forEach { (category, domains) ->
                if (category != ThreatFeedCategory.GENERAL) {
                    domains.sorted().forEach { domain ->
                        writer.write("$CATEGORY_PREFIX${category.name}\t$domain")
                        writer.newLine()
                    }
                }
            }
            blocked.sorted().forEach { domain ->
                writer.write("||$domain^")
                writer.newLine()
            }
            exceptions.sorted().forEach { domain ->
                writer.write("@@||$domain^")
                writer.newLine()
            }
            writer.flush()
            atomicFile.finishWrite(outputStream)
            stream = null
            // La lista consolidada sustituye la versión anterior de forma atómica.
            // Elimina copias temporales/cachés heredadas para que no queden descargas antiguas.
            sourceCacheDir.deleteRecursively()
            onProgress(BlocklistDownloadProgress(uniqueUrls.size, uniqueUrls.size, "Completado", 1L, 1L))
        } catch (error: Exception) {
            stream?.let(atomicFile::failWrite)
            return@withContext Result.failure(error)
        }

        val categorizedCount = categoryDomains.filterKeys { it != ThreatFeedCategory.GENERAL }.values.sumOf { it.size }
        val fingerprintInput = sourceDigests.sorted().joinToString("\\n").toByteArray(StandardCharsets.UTF_8)
        val fingerprint = ThreatFeedIntegrityPolicy.sha256(fingerprintInput).take(16)
        val summary = "Listas HTTPS actualizadas: ${uniqueUrls.size} fuentes validadas ($verifiedSignedSources con firma verificada, $unsignedSources sin firma), $totalParsedRules reglas DNS válidas, ${blocked.size} reglas activas, $categorizedCount indicadores categorizados. Huella SHA-256: $fingerprint"
        Result.success(
            BlocklistSnapshot(
                blocked = blocked,
                exceptions = exceptions,
                threatDomainsByCategory = categoryDomains.mapValues { it.value.toSet() },
                summary = summary
            )
        )
    }


    /**
     * Downloads a detached signature without following redirects. The signature endpoint
     * and public key are configured independently from the feed payload.
     */
    private fun downloadDetachedSignature(signatureUrl: String): ByteArray {
        if (!BlocklistSourcePolicy.isAllowed(signatureUrl)) {
            throw IllegalArgumentException("URL de firma rechazada: se requiere HTTPS en puerto 443")
        }
        val connection = (URL(signatureUrl).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = false
            setRequestProperty("User-Agent", "FirewallDNS/1.0")
            setRequestProperty("Accept", "application/octet-stream")
        }
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                throw IllegalStateException("No se pudo descargar la firma; no se siguen redirecciones")
            }
            val declaredLength = connection.getHeaderFieldLong("Content-Length", -1L)
            if (declaredLength > MAX_SIGNATURE_BYTES) {
                throw IllegalStateException("La firma digital supera 16 KiB")
            }
            val output = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(1024)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_SIGNATURE_BYTES) {
                        throw IllegalStateException("La firma digital supera 16 KiB")
                    }
                    output.write(buffer, 0, count)
                }
            }
            val signature = output.toByteArray()
            if (signature.isEmpty()) throw IllegalStateException("La firma digital está vacía")
            return signature
        } finally {
            connection.disconnect()
        }
    }
}
