package com.firewall.dns.data.local

import android.content.Context
import android.util.AtomicFile
import com.firewall.dns.domain.engine.BlocklistSourcePolicy
import com.firewall.dns.domain.engine.RuleEvaluator
import com.firewall.dns.domain.engine.ThreatFeedCatalog
import com.firewall.dns.domain.engine.ThreatFeedCategory
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

    companion object {
        private const val ADBLOCK_FILE_NAME = "adblock_rules.txt"
        private const val CATEGORY_PREFIX = "! FirewallDNS-CATEGORY\t"
        private const val MAX_SOURCE_BYTES = 8 * 1024 * 1024
        private const val MAX_SOURCE_LINES = 200_000
        private const val MAX_LINE_CHARS = 4_096
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 25_000
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
        urls: List<String>
    ): Result<BlocklistSnapshot> = withContext(Dispatchers.IO) {
        val uniqueUrls = urls.map(String::trim).filter(String::isNotEmpty).distinct()
        if (uniqueUrls.isEmpty()) {
            return@withContext Result.failure(IllegalArgumentException("Agrega al menos una URL HTTPS en sintaxis Adblock"))
        }

        val blocked = HashSet<String>(defaultDomains)
        val exceptions = HashSet<String>()
        val categoryDomains = ThreatFeedCategory.values().associateWith { HashSet<String>() }.toMutableMap()
        var lastError: Exception? = null
        val completedSources = HashSet<String>()

        for (targetUrl in uniqueUrls) {
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
                    setRequestProperty("User-Agent", "FirewallDNS/1.0")
                    setRequestProperty("Accept", "text/plain, application/octet-stream;q=0.9")
                }
                val status = connection.responseCode
                if (status != HttpURLConnection.HTTP_OK) {
                    throw IllegalStateException("HTTP $status; no se siguen redirecciones")
                }
                val declaredLength = connection.getHeaderFieldLong("Content-Length", -1L)
                if (declaredLength > MAX_SOURCE_BYTES) throw IllegalStateException("La lista supera 8 MiB")

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
                    }
                    output.toByteArray()
                }

                val sourceBlocked = HashSet<String>()
                val sourceExceptions = HashSet<String>()
                var lineCount = 0
                String(payload, StandardCharsets.UTF_8).lineSequence().forEach { line ->
                    lineCount++
                    if (lineCount > MAX_SOURCE_LINES) throw IllegalStateException("La lista supera 200,000 líneas")
                    if (line.length > MAX_LINE_CHARS) throw IllegalStateException("La lista contiene una línea demasiado larga")
                    RuleEvaluator.parseAdblockLine(line)?.let { parsed ->
                        if (parsed.isException) sourceExceptions.add(parsed.domain) else sourceBlocked.add(parsed.domain)
                    }
                }

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
        } catch (error: Exception) {
            stream?.let(atomicFile::failWrite)
            return@withContext Result.failure(error)
        }

        val categorizedCount = categoryDomains.filterKeys { it != ThreatFeedCategory.GENERAL }.values.sumOf { it.size }
        val summary = "Listas HTTPS actualizadas: ${uniqueUrls.size} fuentes, ${blocked.size} reglas, ${categorizedCount} indicadores categorizados"
        Result.success(
            BlocklistSnapshot(
                blocked = blocked,
                exceptions = exceptions,
                threatDomainsByCategory = categoryDomains.mapValues { it.value.toSet() },
                summary = summary
            )
        )
    }
}
