package com.firewall.dns.domain.ai

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

object LocalAiRuntimeScheduler {
    private const val DOWNLOAD_WORK = "firewalldns-qwen3-download"
    private const val ANALYSIS_WORK = "firewalldns-qwen3-analysis"

    fun schedule(context: Context) {
        val app = context.applicationContext
        val wifiOnly = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build()
        val download = OneTimeWorkRequestBuilder<LocalAiModelDownloadWorker>()
            .setConstraints(wifiOnly)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(app).enqueueUniqueWork(DOWNLOAD_WORK, ExistingWorkPolicy.KEEP, download)

        val localConstraints = Constraints.Builder().setRequiresBatteryNotLow(true).build()
        val periodic = PeriodicWorkRequestBuilder<LocalAiAnalysisWorker>(15, TimeUnit.MINUTES)
            .setConstraints(localConstraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(app).enqueueUniquePeriodicWork(ANALYSIS_WORK, ExistingPeriodicWorkPolicy.KEEP, periodic)

        val initial = OneTimeWorkRequestBuilder<LocalAiAnalysisWorker>()
            .setConstraints(localConstraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(app).enqueueUniqueWork(ANALYSIS_WORK + "-initial", ExistingWorkPolicy.KEEP, initial)
    }

    fun runNow(context: Context) {
        val request = OneTimeWorkRequestBuilder<LocalAiAnalysisWorker>()
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context.applicationContext)
            .enqueueUniqueWork(ANALYSIS_WORK + "-manual", ExistingWorkPolicy.REPLACE, request)
    }
}
