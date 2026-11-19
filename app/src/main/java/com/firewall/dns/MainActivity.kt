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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
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
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import com.firewall.dns.data.repository.FirewallRepository
import com.firewall.dns.service.DnsFirewallService
import com.firewall.dns.ui.screens.AppsSettingsScreen
import com.firewall.dns.ui.screens.LogsScreen
import com.firewall.dns.ui.screens.RulesScreen
import com.firewall.dns.ui.screens.SecurityCenterScreen
import com.firewall.dns.ui.screens.SocDashboardScreen
import com.firewall.dns.ui.theme.FirewallTheme
import com.firewall.dns.ui.viewmodel.FirewallViewModel
import com.firewall.dns.work.BlocklistUpdateScheduler

class MainActivity : ComponentActivity() {

    private lateinit var firewallViewModel: FirewallViewModel
    private var vpnStartRequestId = 0

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
        BlocklistUpdateScheduler.schedule(this)

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
            setPadding(pad, (56 * density).toInt(), pad, (48 * density).toInt())
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
        val requestId = ++vpnStartRequestId
        lifecycleScope.launch {
            FirewallRepository.awaitInitialBlocklistLoad()
            if (requestId == vpnStartRequestId && !isFinishing && !isDestroyed) {
                android.util.Log.d("MainActivity", "Encendiendo VPN")
                DnsFirewallService.start(this@MainActivity)
            }
        }
    }

    private fun stopFirewallService() {
        vpnStartRequestId++
        android.util.Log.d("MainActivity", "Apagando FirewallDNS TUN")
        DnsFirewallService.stop(this)
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
        drawPath(shield, shieldColor)
        drawLine(
            color = markColor,
            start = androidx.compose.ui.geometry.Offset(size.width * 0.3f, size.height * 0.51f),
            end = androidx.compose.ui.geometry.Offset(size.width * 0.45f, size.height * 0.66f),
            strokeWidth = size.width * 0.08f,
            cap = StrokeCap.Round
        )
        drawLine(
            color = markColor,
            start = androidx.compose.ui.geometry.Offset(size.width * 0.45f, size.height * 0.66f),
            end = androidx.compose.ui.geometry.Offset(size.width * 0.72f, size.height * 0.37f),
            strokeWidth = size.width * 0.08f,
            cap = StrokeCap.Round
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirewallApp(
    viewModel: FirewallViewModel,
    onToggleVpn: (Boolean) -> Unit,
    onOpenBatteryOpt: () -> Unit,
    onOpenVpnSettings: () -> Unit
) {
    val context = LocalContext.current
    val stats by viewModel.stats.collectAsState()
    val logs by viewModel.filteredLogs.collectAsState()
    val activityLogs by viewModel.activityLogs.collectAsState()
    val traffic by viewModel.traffic.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val onlyBlocked by viewModel.onlyBlocked.collectAsState()
    val customBlock by viewModel.customBlockList.collectAsState()
    val customAllow by viewModel.customAllowList.collectAsState()
    val blocklistUrls by viewModel.blocklistUrls.collectAsState()
    val blocklistsDownloaded by viewModel.blocklistsDownloaded.collectAsState()
    val smartModeEnabled by viewModel.smartModeEnabled.collectAsState()
    val isDownloading by viewModel.isDownloading.collectAsState()
    val downloadProgress by viewModel.downloadProgress.collectAsState()
    val apps by viewModel.filteredApps.collectAsState()
    val excludedPackages by viewModel.excludedPackages.collectAsState()
    val blockedApps by viewModel.blockedApps.collectAsState()
    val appSearch by viewModel.appSearch.collectAsState()

    var selectedDestination by remember { mutableIntStateOf(0) }
    var otherVpnActive by remember { mutableStateOf(false) }

    LaunchedEffect(stats.isRunning) {
        if (stats.isRunning) {
            otherVpnActive = false
            return@LaunchedEffect
        }
        var hits = 0
        while (true) {
            hits = if (isOtherVpnActive(context)) hits + 1 else 0
            otherVpnActive = hits >= 2
            kotlinx.coroutines.delay(2_000)
        }
    }

    LaunchedEffect(Unit) {
        viewModel.toastMessage.collect { msg ->
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        }
    }

    val destinations = listOf(
        "Inicio" to Icons.Default.Home,
        "Monitor" to Icons.Default.Search,
        "Amenazas" to Icons.Default.Warning,
        "Protección" to Icons.Default.Lock,
        "Sistema" to Icons.Default.Settings
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        FirewallShieldIcon()
                        Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                            Text(
                                when (selectedDestination) {
                                    0 -> "FirewallDNS"
                                    1 -> "Monitor DNS"
                                    2 -> "Centro de amenazas"
                                    3 -> "Protección"
                                    else -> "Sistema y aplicaciones"
                                },
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                if (stats.isRunning) "SISTEMA ACTIVO · ${stats.engine}"
                                else "SISTEMA EN ESPERA",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (stats.isRunning) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                },
                actions = {
                    Text(
                        if (stats.isRunning) "ON" else "OFF",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Switch(
                        checked = stats.isRunning,
                        onCheckedChange = onToggleVpn,
                        modifier = Modifier.padding(start = 4.dp, end = 8.dp)
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                )
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                tonalElevation = 3.dp
            ) {
                destinations.forEachIndexed { index, destination ->
                    NavigationBarItem(
                        selected = selectedDestination == index,
                        onClick = { selectedDestination = index },
                        icon = { Icon(destination.second, contentDescription = destination.first) },
                        label = { Text(destination.first, maxLines = 1) },
                        alwaysShowLabel = false
                    )
                }
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when (selectedDestination) {
                0 -> SocDashboardScreen(
                    stats = stats,
                    logs = activityLogs,
                    otherVpnActive = otherVpnActive,
                    blocklistsDownloaded = blocklistsDownloaded,
                    onOpenMonitor = { selectedDestination = 1 },
                    onOpenThreats = { selectedDestination = 2 },
                    onOpenProtection = { selectedDestination = 3 }
                )
                1 -> LogsScreen(
                    stats = stats,
                    logs = logs,
                    traffic = traffic,
                    otherVpnActive = otherVpnActive,
                    searchQuery = searchQuery,
                    onlyBlocked = onlyBlocked,
                    onSearchQueryChange = viewModel::onSearchQueryChange,
                    onToggleOnlyBlocked = viewModel::onToggleOnlyBlocked,
                    onClearLogs = viewModel::clearLogs,
                    onToggleRule = { entry ->
                        viewModel.setCustomRule(entry.domain, block = !entry.isBlocked)
                    }
                )
                2 -> SecurityCenterScreen(
                    stats = stats,
                    logs = activityLogs,
                    otherVpnActive = otherVpnActive,
                    onOpenActivity = { selectedDestination = 1 }
                )
                3 -> RulesScreen(
                    stats = stats,
                    customBlock = customBlock,
                    customAllow = customAllow,
                    blocklistUrls = blocklistUrls,
                    smartModeEnabled = smartModeEnabled,
                    isDownloading = isDownloading,
                    downloadProgress = downloadProgress,
                    onToggleSmartMode = viewModel::toggleSmartMode,
                    onAddBlocklistUrl = viewModel::addBlocklistUrl,
                    onRemoveBlocklistUrl = viewModel::removeBlocklistUrl,
                    onDownloadBlocklist = viewModel::downloadBlocklist,
                    onAddCustomRule = viewModel::setCustomRule,
                    onRemoveCustomRule = viewModel::removeCustomRule
                )
                4 -> AppsSettingsScreen(
                    stats = stats,
                    apps = apps,
                    excludedPackages = excludedPackages,
                    blockedApps = blockedApps,
                    onToggleBlockedApp = viewModel::toggleBlockedApp,
                    appSearch = appSearch,
                    onAppSearchChange = viewModel::onAppSearchChange,
                    onToggleExcludedApp = viewModel::toggleExcludedApp,
                    onOpenBatteryOpt = onOpenBatteryOpt,
                    onOpenVpnSettings = onOpenVpnSettings
                )
            }
        }
    }
}

private fun isOtherVpnActive(context: android.content.Context): Boolean = try {
    val cm = context.getSystemService(android.net.ConnectivityManager::class.java)
    val vpnUp = cm.getNetworkCapabilities(cm.activeNetwork)
        ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
    vpnUp && VpnService.prepare(context) != null
} catch (_: Throwable) {
    false
}
