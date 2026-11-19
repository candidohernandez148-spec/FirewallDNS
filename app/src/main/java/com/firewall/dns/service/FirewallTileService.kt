package com.firewall.dns.service

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.service.quicksettings.PendingIntentActivityWrapper
import androidx.core.service.quicksettings.TileServiceCompat
import com.firewall.dns.MainActivity
import com.firewall.dns.data.repository.FirewallRepository

class FirewallTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        FirewallRepository.init(applicationContext)
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        FirewallRepository.init(applicationContext)
        val running = FirewallRepository.stats.value.isRunning

        if (running) {
            DnsFirewallService.stop(this)
            setTile(active = false, subtitle = "Apagado")
        } else {
            if (VpnService.prepare(this) == null) {
                DnsFirewallService.start(this)
                setTile(active = false, subtitle = "Activando…")
            } else {
                setTile(active = false, subtitle = "Requiere permiso")
                val wrapper = PendingIntentActivityWrapper(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT, false
                )
                TileServiceCompat.startActivityAndCollapse(this, wrapper)
            }
        }
    }

    private fun updateTileState() {
        val stats = FirewallRepository.stats.value
        val subtitle = if (stats.isRunning) stats.engine.ifBlank { "Activo" } else "Apagado"
        setTile(stats.isRunning, subtitle)
    }

    private fun setTile(active: Boolean, subtitle: String) {
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = subtitle
        }
        tile.updateTile()
    }

    companion object {
        fun requestSync(context: Context) {
            try {
                requestListeningState(
                    context.applicationContext,
                    ComponentName(context.applicationContext, FirewallTileService::class.java)
                )
            } catch (_: Throwable) {}
        }
    }
}
