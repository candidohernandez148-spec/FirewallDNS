package com.firewall.dns.work

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.firewall.dns.data.repository.FirewallRepository
import java.util.concurrent.TimeUnit

/**
 * Actualiza las listas existentes en segundo plano. WorkManager puede ejecutar
 * la tarea con cualquier red conectada; esta comprobación adicional exige Wi-Fi
 * para no descargar listas mediante datos móviles.
 */
class BlocklistAutoUpdateWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        return try {
            FirewallRepository.init(applicationContext)

            if (FirewallRepository.blocklistUrls.value.isEmpty()) {
                return Result.success()
            }

            if (!isWifiConnected(applicationContext)) {
                return Result.retry()
            }

            val update = FirewallRepository.downloadBlocklist()
            if (update.isSuccess) Result.success() else Result.retry()
        } catch (_: Exception) {
            Result.retry()
        }
    }

    private fun isWifiConnected(context: Context): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: return false
        return connectivity.allNetworks.any { network ->
            val capabilities = connectivity.getNetworkCapabilities(network)
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }
}

object BlocklistUpdateScheduler {
    private const val WORK_NAME = "firewalldns_blocklist_auto_update"

    fun schedule(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = PeriodicWorkRequestBuilder<BlocklistAutoUpdateWorker>(
            24, TimeUnit.HOURS
        )
            .setConstraints(constraints)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                30,
                TimeUnit.MINUTES
            )
            .addTag(WORK_NAME)
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
}
