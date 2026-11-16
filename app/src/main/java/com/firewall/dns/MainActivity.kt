package com.firewall.dns

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import com.firewall.dns.service.DnsFirewallService
import com.firewall.dns.ui.screens.AppsSettingsScreen
import com.firewall.dns.ui.screens.LogsScreen
import com.firewall.dns.ui.screens.RulesScreen
import com.firewall.dns.ui.theme.FirewallTheme
import com.firewall.dns.ui.viewmodel.FirewallViewModel

class MainActivity : ComponentActivity() {

    private lateinit var firewallViewModel: FirewallViewModel

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startFirewallService()
    }

    private val notifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> requestAndStartVpn() }

    override fun onCreate(savedInstanceState: Bundle?) {
        val crashPrefs = getSharedPreferences("crash_debug", MODE_PRIVATE)
        val savedCrash = crashPrefs.getString("last_crash", null)
        val prevHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            crashPrefs.edit().putString("last_crash", throwable.stackTraceToString()).commit()
            prevHandler?.uncaughtException(thread, throwable)
        }
        super.onCreate(savedInstanceState)

        if (!savedCrash.isNullOrBlank()) {
            showCrashScreen(savedCrash, crashPrefs)
            return
        }

        try {
            firewallViewModel = ViewModelProvider(
                this,
                ViewModelProvider.AndroidViewModelFactory.getInstance(application)
            )[FirewallViewModel::class.java]

            if (firewallViewModel.shouldAutoStartVpn() && VpnService.prepare(this) == null) {
                startFirewallService()
            }

            setContent {
                FirewallTheme {
                    Surface(color = MaterialTheme.colorScheme.background) {
                        FirewallApp(
                            viewModel = firewallViewModel,
                            onToggleVpn = { enable ->
                                if (enable) checkPermissionsAndStart() else stopFirewallService()
                            },
                            onOpenBatteryOpt = { requestIgnoreBatteryOptimization() },
                            onOpenVpnSettings = { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                        )
                    }
                }
            }
        } catch (t: Throwable) {
            val trace = t.stackTraceToString()
            crashPrefs.edit().putString("last_crash", trace).commit()
            showCrashScreen(trace, crashPrefs)
        }
    }

    private fun showCrashScreen(trace: String, crashPrefs: android.content.SharedPreferences) {
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, (56 * density).toInt(), pad, pad)
            setBackgroundColor(android.graphics.Color.WHITE)
        }
        val title = TextView(this).apply {
            text = "Error detectado al iniciar:"
            textSize = 18f
            setTextColor(android.graphics.Color.RED)
        }
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, pad / 2, 0, pad / 2)
        }
        val copyBtn = Button(this).apply {
            text = "Copiar error"
            setOnClickListener {
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("Crash", trace))
                Toast.makeText(this@MainActivity, "Error copiado", Toast.LENGTH_SHORT).show()
            }
        }
        val retryBtn = Button(this).apply {
            text = "Limpiar y reintentar"
            setOnClickListener {
                crashPrefs.edit().remove("last_crash").commit()
                recreate()
            }
        }
        btnRow.addView(copyBtn)
        btnRow.addView(retryBtn)
        val body = TextView(this).apply {
            text = trace
            textSize = 12f
            setTextColor(android.graphics.Color.BLACK)
        }
        val scroll = ScrollView(this).apply { addView(body) }
        layout.addView(title)
        layout.addView(btnRow)
        layout.addView(scroll)
        setContentView(layout)
    }

    private fun checkPermissionsAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else requestAndStartVpn()
    }

    private fun requestAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent) else startFirewallService()
    }

    private fun startFirewallService() {
        val intent = Intent(this, DnsFirewallService::class.java).apply {
            action = DnsFirewallService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopFirewallService() {
        startService(Intent(this, DnsFirewallService::class.java).apply {
            action = DnsFirewallService.ACTION_STOP
        })
    }

    @SuppressLint("BatteryLife")
    private fun requestIgnoreBatteryOptimization() {
        val pm = getSystemService(PowerManager::class.java)
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            })
        } else Toast.makeText(this, "La optimización ya está desactivada", Toast.LENGTH_SHORT).show()
    }
}

@Composable
private fun FirewallShieldIcon(modifier: Modifier = Modifier) {
    val shieldColor = MaterialTheme.colorScheme.primary
    val markColor = MaterialTheme.colorScheme.onPrimary
    Canvas(modifier = modifier.size(24.dp)) {
        val shield = Path().apply {
            moveTo(size.width * 0.5f, size.height * 0.04f)
            lineTo(size.width * 0.9f, size.height * 0.2f)
            lineTo(size.width * 0.86f, size.height * 0.58f)
            lineTo(size.width * 0.72f, size.height * 0.8f)
            lineTo(size.width * 0.5f, size.height * 0.96f)
            lineTo(size.width * 0.28f, size.height * 0.8f)
            lineTo(size.width * 0.14f, size.height * 0.58f)
            lineTo(size.width * 0.1f, size.height * 0.2f)
            close()
        }
        drawPath(path = shield, color = shieldColor)
        drawPath(
            path = Path().apply {
                moveTo(size.width * 0.46f, size.height * 0.3f)
                lineTo(size.width * 0.54f, size.height * 0.3f)
                lineTo(size.width * 0.54f, size.height * 0.58f)
                lineTo(size.width * 0.46f, size.height * 0.58f)
                close()
                moveTo(size.width * 0.4f, size.height * 0.62f)
                lineTo(size.width * 0.6f, size.height * 0.62f)
            },
            color = markColor,
            style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
        )
    }
}

@Composable
private fun FirewallApp(
    viewModel: FirewallViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onToggleObservationMode: (Boolean) -> Unit,
    onOpenBatteryOpt: () -> Unit,
    onOpenVpnSettings: () -> Unit
) {
    var tab by remember { mutableStateOf(0) }
    val stats by viewModel.stats.collectAsState()
    val logs by viewModel.filteredLogs.collectAsState()
    val blocklistUrls by viewModel.blocklistUrls.collectAsState()
    val smartMode by viewModel.smartModeEnabled.collectAsState()
    val isDownloading by viewModel.isDownloading.collectAsState()
    val customBlock by viewModel.customBlockList.collectAsState()
    val customAllow by viewModel.customAllowList.collectAsState()
    val excludedPackages by viewModel.excludedPackages.collectAsState()
    val appSearch by viewModel.appSearch.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val onlyBlocked by viewModel.onlyBlocked.collectAsState()
    val apps by viewModel.filteredApps.collectAsState()
    val observationMode by viewModel.observationModeEnabled.collectAsState()

    val context = LocalContext.current
    LaunchedEffect(Unit) {
        viewModel.toastMessage.collect { message ->
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            Surface(shadowElevation = 1.dp) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    FirewallShieldIcon(modifier = Modifier.padding(end = 10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Firewall DNS", fontWeight = FontWeight.Bold, fontSize = 20.sp)
                        Text("Protección DNS local", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                    }
                    if (tab == 0) {
                        Switch(
                            checked = observationMode,
                            onCheckedChange = onToggleObservationMode,
                            modifier = Modifier.padding(start = 8.dp)
                        )
                    }
                }
            }
        }
    ) { inner ->
        Column(modifier = Modifier.fillMaxSize().padding(inner)) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Dashboard") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Actividad") })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Reglas") })
                Tab(selected = tab == 3, onClick = { tab = 3 }, text = { Text("Configuración") })
            }
            when (tab) {
                0 -> DashboardScreen(
                    stats = stats,
                    onToggleProtection = onToggleVpn,
                    onOpenLogs = { tab = 1 },
                    onOpenRules = { tab = 2 }
                )
                1 -> LogsScreen(
                    stats = stats,
                    logs = logs,
                    searchQuery = searchQuery,
                    onlyBlocked = onlyBlocked,
                    onSearchQueryChange = viewModel::onSearchQueryChange,
                    onToggleOnlyBlocked = viewModel::onToggleOnlyBlocked,
                    onClearLogs = viewModel::clearLogs,
                    onToggleRule = { entry ->
                        val nextBlocked = !entry.isBlocked
                        viewModel.setCustomRule(entry.domain, nextBlocked)
                    }
                )
                2 -> RulesScreen(
                    stats = stats,
                    customBlock = customBlock,
                    customAllow = customAllow,
                    blocklistUrls = blocklistUrls,
                    smartModeEnabled = smartMode,
                    isDownloading = isDownloading,
                    onToggleSmartMode = viewModel::toggleSmartMode,
                    onAddBlocklistUrl = viewModel::addBlocklistUrl,
                    onRemoveBlocklistUrl = viewModel::removeBlocklistUrl,
                    onDownloadBlocklist = viewModel::downloadBlocklist,
                    onAddCustomRule = viewModel::setCustomRule,
                    onRemoveCustomRule = viewModel::removeCustomRule
                )
                3 -> AppsSettingsScreen(
                    stats = stats,
                    apps = apps,
                    excludedPackages = excludedPackages,
                    appSearch = appSearch,
                    onAppSearchChange = viewModel::onAppSearchChange,
                    onSelectUpstreamDns = viewModel::setUpstreamDns,
                    onToggleExcludedApp = viewModel::toggleExcludedApp,
                    onOpenBatteryOpt = onOpenBatteryOpt,
                    onOpenVpnSettings = onOpenVpnSettings
                )
            }
        }
    }
}
