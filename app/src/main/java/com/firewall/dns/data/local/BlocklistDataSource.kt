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
                        if (parsed.isException) exceptions.add(parsed.domain) else blocked.add(parsed.domain)
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
        val uniqueUrls = urls.map(String::trim).filter(String::isNotEmpty).distinct()
        if (uniqueUrls.isEmpty()) {
            return@withContext Result.failure(IllegalArgumentException("Agrega al menos una URL HTTPS en sintaxis Adblock"))
        }

        val blocked = HashSet<String>(defaultDomains)
        val exceptions = HashSet<String>()
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

                // No se incorpora una fuente hasta terminar de leerla y validarla por completo.
                blocked.addAll(sourceBlocked)
                exceptions.addAll(sourceExceptions)
                completedSources.add(targetUrl)
            } catch (error: Exception) {
                lastError = error
            } finally {
                connection?.disconnect()
            }
        }

        // Política conservadora: si una fuente falla, no reemplazar el conjunto anterior por uno parcial.
        val successfulSources = uniqueUrls.count { url ->
            // Cada URL válida que llegó a procesarse incrementa este contador más abajo.
            completedSources.contains(url)
        }
        if (successfulSources != uniqueUrls.size) {
            return@withContext Result.failure(lastError ?: IllegalStateException("No se pudieron validar todas las listas; se conserva la versión anterior"))
        }

        val outputFile = File(filesDir, ADBLOCK_FILE_NAME)
        val atomicFile = AtomicFile(outputFile)
        var stream: FileOutputStream? = null
        try {
            stream = atomicFile.startWrite()
            val writer = OutputStreamWriter(stream, StandardCharsets.UTF_8).buffered()
            blocked.sorted().forEach { domain -> writer.apply { write("||$domain^"); newLine() } }
            exceptions.sorted().forEach { domain -> writer.apply { write("@@||$domain^"); newLine() } }
            writer.flush()
            atomicFile.finishWrite(stream)
            stream = null
        } catch (error: Exception) {
            stream?.let(atomicFile::failWrite)
            return@withContext Result.failure(error)
        }

        val summary = "Listas HTTPS actualizadas: ${uniqueUrls.size} fuentes, ${blocked.size} reglas"
        Result.success(Triple(blocked, exceptions, summary))
    }
}
