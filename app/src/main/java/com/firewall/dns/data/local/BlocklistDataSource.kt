package com.firewall.dns.data.local

import android.content.Context
import android.util.AtomicFile
import com.firewall.dns.domain.engine.BlocklistSourcePolicy
import com.firewall.dns.domain.engine.RuleEvaluator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

class BlocklistDataSource(context: Context) {

    private val filesDir: File = context.applicationContext.filesDir

    companion object {
        private const val ADBLOCK_FILE_NAME = "adblock_rules.txt"
        private const val MAX_SOURCE_BYTES = 8 * 1024 * 1024
        private const val MAX_SOURCE_LINES = 200_000
        private const val MAX_LINE_CHARS = 4_096
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 25_000
    }

    fun loadFromDisk(defaultDomains: List<String>): Pair<Set<String>, Set<String>> {
        val blocked = HashSet<String>(defaultDomains)
        val exceptions = HashSet<String>()
        val file = File(filesDir, ADBLOCK_FILE_NAME)
        if (file.exists()) {
            file.bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
                lines.forEach { line ->
                    RuleEvaluator.parseAdblockLine(line)?.let { parsed ->
                        if (parsed.isException) exceptions.add(parsed.domain)
                        else blocked.add(parsed.domain)
                    }
                }
            }
        }
        return blocked to exceptions
    }

    suspend fun downloadMultipleAndSave(
        defaultDomains: List<String>,
        urls: List<String>
    ): Result<Triple<Set<String>, Set<String>, String>> = withContext(Dispatchers.IO) {
        val uniqueUrls = urls.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        if (uniqueUrls.isEmpty()) {
            return@withContext Result.failure(Exception("Agrega al menos una URL HTTPS en sintaxis Adblock"))
        }

        val blocked = HashSet<String>(defaultDomains)
        val exceptions = HashSet<String>()
        var successCount = 0
        var lastError: Exception? = null

        for (targetUrl in uniqueUrls) {
            if (!BlocklistSourcePolicy.isAllowed(targetUrl)) {
                lastError = IllegalArgumentException("Fuente rechazada: solo se permiten URLs HTTPS en el puerto 443")
                continue
            }

            var conn: HttpURLConnection? = null
            try {
                conn = (URL(targetUrl).openConnection() as HttpURLConnection).apply {
                    connectTimeout = CONNECT_TIMEOUT_MS
                    readTimeout = READ_TIMEOUT_MS
                    instanceFollowRedirects = false
                    setRequestProperty("User-Agent", "FirewallDNS/1.0")
                    setRequestProperty("Accept", "text/plain, application/octet-stream;q=0.9")
                }

                val responseCode = conn.responseCode
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    throw IllegalStateException("HTTP $responseCode (no se siguen redirecciones)")
                }
                val declaredLength = conn.getHeaderFieldLong("Content-Length", -1L)
                if (declaredLength > MAX_SOURCE_BYTES) {
                    throw IllegalStateException("La lista supera el límite de 8 MiB")
                }

                val payload = conn.inputStream.use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(8 * 1024)
                    var total = 0
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > MAX_SOURCE_BYTES) {
                            throw IllegalStateException("La lista supera el límite de 8 MiB")
                        }
                        output.write(buffer, 0, read)
                    }
                    output.toByteArray()
                }

                val sourceBlocked = HashSet<String>()
                val sourceExceptions = HashSet<String>()
                var lineCount = 0
                String(payload, StandardCharsets.UTF_8).lineSequence().forEach { line ->
                    lineCount++
                    if (lineCount > MAX_SOURCE_LINES) {
                        throw IllegalStateException("La lista supera el límite de 200,000 líneas")
                    }
                    if (line.length > MAX_LINE_CHARS) {
                        throw IllegalStateException("La lista contiene una línea demasiado larga")
                    }
                    RuleEvaluator.parseAdblockLine(line)?.let { parsed ->
                        if (parsed.isException) sourceExceptions.add(parsed.domain)
                        else sourceBlocked.add(parsed.domain)
                    }
                }

                // Commit a source only after the complete response has been read and validated.
                blocked.addAll(sourceBlocked)
                exceptions.addAll(sourceExceptions)
                successCount++
            } catch (e: Exception) {
                lastError = e
            } finally {
                conn?.disconnect()
            }
        }

        if (successCount != uniqueUrls.size) {
            return@withContext Result.failure(
                lastError ?: Exception("No se pudieron descargar todas las listas; se conserva la versión anterior")
            )
        }

        val outFile = File(filesDir, ADBLOCK_FILE_NAME)
        val atomicFile = AtomicFile(outFile)
        var stream: FileOutputStream? = null
        try {
            stream = atomicFile.startWrite()
            val writer = OutputStreamWriter(stream, StandardCharsets.UTF_8).buffered()
            blocked.sorted().forEach { domain ->
                writer.write("||$domain^")
                writer.newLine()
            }
            exceptions.sorted().forEach { domain ->
                writer.write("@@||$domain^")
                writer.newLine()
            }
            writer.flush()
            atomicFile.finishWrite(stream)
            stream = null
        } catch (e: Exception) {
            stream?.let { atomicFile.failWrite(it) }
            return@withContext Result.failure(e)
        }

        val summary = "Listas seguras OK (SUCCESS_COUNT/TOTAL_COUNT): BLOCKED_COUNT reglas"
            .replace("SUCCESS_COUNT", successCount.toString())
            .replace("TOTAL_COUNT", uniqueUrls.size.toString())
            .replace("BLOCKED_COUNT", blocked.size.toString())
        Result.success(Triple(blocked, exceptions, summary))
    }
}
