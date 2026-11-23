package com.firewall.dns.domain.ai

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import dev.ffmpegkit.llama.Llama
import dev.ffmpegkit.llama.LlamaConfig
import com.firewall.dns.data.repository.FirewallRepository
import com.firewall.dns.domain.ai.LocalAiPolicyGate
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

data class LocalAiRuntimeState(
    val status: String = "Preparando IA local",
    val downloadPercent: Int = 0,
    val summary: String = "",
    val lastRun: Long = 0L
)

object LocalAiRuntime {
    const val MODEL_FILE = "Qwen_Qwen3-0.6B-Q4_K_M.gguf"
    const val MODEL_URL = "https://huggingface.co/bartowski/Qwen_Qwen3-0.6B-GGUF/resolve/main/Qwen_Qwen3-0.6B-Q4_K_M.gguf"
    const val MODEL_SHA256 = "9acfc1e001311f34b4252001b626f2e466d592a42065f66571bff3790d4e1b14"
    private const val PREFS = "local_ai_runtime"

    fun modelFile(context: Context): File =
        File(File(context.filesDir, "ai-models").apply { mkdirs() }, MODEL_FILE)

    fun readState(context: Context): LocalAiRuntimeState {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return LocalAiRuntimeState(
            p.getString("status", "Preparando IA local") ?: "Preparando IA local",
            p.getInt("progress", 0),
            p.getString("summary", "") ?: "",
            p.getLong("last_run", 0L)
        )
    }

    fun writeState(context: Context, status: String, progress: Int? = null, summary: String? = null, lastRun: Long? = null) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().apply {
            putString("status", status)
            progress?.let { putInt("progress", it.coerceIn(0, 100)) }
            summary?.let { putString("summary", it.take(500)) }
            lastRun?.let { putLong("last_run", it) }
        }.apply()
    }
}

class LocalAiModelDownloadWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val target = LocalAiRuntime.modelFile(applicationContext)
        if (target.isFile && fileSha256(target) == LocalAiRuntime.MODEL_SHA256) {
            LocalAiRuntime.writeState(applicationContext, "Qwen3 descargado · listo", 100)
            return Result.success()
        }
        target.delete()
        val temp = File(target.parentFile, target.name + ".part")
        temp.delete()
        try {
            if ((target.parentFile?.usableSpace ?: 0L) < 700L * 1024L * 1024L) {
                LocalAiRuntime.writeState(applicationContext, "Espacio insuficiente: libera al menos 700 MB")
                return Result.failure()
            }
            LocalAiRuntime.writeState(applicationContext, "Descargando Qwen3 por Wi-Fi", 0)
            val connection = (URL(LocalAiRuntime.MODEL_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout = 20_000
                readTimeout = 60_000
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "FirewallDNS-Android/1.0")
            }
            connection.connect()
            val code = connection.responseCode
            if (code !in 200..299) {
                connection.disconnect()
                throw IllegalStateException("HTTP " + code)
            }
            val total = connection.contentLengthLong
            connection.inputStream.use { input ->
                FileOutputStream(temp).use { output ->
                    val buffer = ByteArray(1024 * 1024)
                    var copied = 0L
                    var lastPercent = -2
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                        copied += count
                        val percent = if (total > 0) ((copied * 100) / total).toInt() else 0
                        if (percent >= lastPercent + 2) {
                            lastPercent = percent
                            setProgress(workDataOf("percent" to percent))
                            LocalAiRuntime.writeState(applicationContext, "Descargando Qwen3 · " + percent + "%", percent)
                        }
                    }
                    output.fd.sync()
                }
            }
            connection.disconnect()
            LocalAiRuntime.writeState(applicationContext, "Verificando integridad de Qwen3", 99)
            if (fileSha256(temp) != LocalAiRuntime.MODEL_SHA256) throw SecurityException("SHA-256 del modelo no coincide")
            if (!temp.renameTo(target)) throw IllegalStateException("No se pudo guardar el modelo")
            LocalAiRuntime.writeState(applicationContext, "Qwen3 descargado · listo", 100)
            return Result.success()
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            temp.delete()
            throw cancelled
        } catch (error: Exception) {
            temp.delete()
            LocalAiRuntime.writeState(applicationContext, "Error al descargar Qwen3: " + (error.message ?: "desconocido"))
            return if (runAttemptCount < 5) Result.retry() else Result.failure()
        }
    }
}

class LocalAiAnalysisWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val lockHandle = RandomAccessFile(File(applicationContext.cacheDir, "qwen3-inference.lock"), "rw")
        val inferenceLock = try { lockHandle.channel.tryLock() } catch (_: OverlappingFileLockException) { null }
        if (inferenceLock == null) {
            lockHandle.close()
            return Result.retry()
        }
        try {
            return runInference()
        } finally {
            inferenceLock.release()
            lockHandle.close()
        }
    }

    private suspend fun runInference(): Result {
        val modelFile = LocalAiRuntime.modelFile(applicationContext)
        if (!modelFile.isFile || modelFile.length() < 400L * 1024L * 1024L) {
            LocalAiRuntime.writeState(applicationContext, "Esperando descarga de Qwen3 por Wi-Fi")
            return Result.retry()
        }
        try {
            FirewallRepository.init(applicationContext)
            FirewallRepository.awaitInitialBlocklistLoad()
            if (FirewallRepository.logs.value.isEmpty()) {
                LocalAiRuntime.writeState(applicationContext, "Qwen3 listo · esperando actividad DNS")
                return Result.success()
            }
            LocalAiRuntime.writeState(applicationContext, "Cargando Qwen3 · análisis local")
            val model = Llama.loadModel(
                modelPath = modelFile.absolutePath,
                config = LlamaConfig(contextSize = 2048, threads = 2, gpuLayers = 0, temperature = 0.1f, topP = 0.8f, topK = 20)
            )
            try {
                val response = Llama.complete(
                    model = model,
                    prompt = FirewallRepository.buildLocalAiSecurityPrompt(),
                    systemPrompt = "Eres Qwen3, analista local de ciberseguridad de FirewallDNS. Analiza solo la evidencia. Devuelve exclusivamente JSON válido con summary y recommendations. No inventes dominios ni afirmes acciones que no ejecutaste.",
                    maxTokens = 512
                )
                val analysis = LocalAiRecommendationParser.parse(response.text)
                if (analysis == null) {
                    LocalAiRuntime.writeState(applicationContext, "Qwen3 ejecutó inferencia · respuesta no válida; DNS sigue protegido")
                } else {
                    val observedDomains = FirewallRepository.logs.value.mapNotNull { LocalAiPolicyGate.normalizeDomain(it.domain) }.toSet()
                    analysis.recommendations
                        .filter { it.domain in observedDomains }
                        .forEach { FirewallRepository.applyLocalAiSuggestion(it) }
                    LocalAiRuntime.writeState(
                        applicationContext,
                        "Qwen3 operativo · análisis completado",
                        summary = analysis.summary,
                        lastRun = System.currentTimeMillis()
                    )
                }
            } finally {
                Llama.releaseModel(model)
            }
            return Result.success()
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            LocalAiRuntime.writeState(applicationContext, "IA local no disponible: " + (error.message ?: "error de inferencia"))
            return Result.retry()
        }
    }
}

private fun fileSha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(1024 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
