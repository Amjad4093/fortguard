package com.fortguard.sdk

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Keeps the app's motion checks running after its screens close. It only runs when the app turns it on,
 * and it always shows a notification while it runs. Touch and typing are still captured only inside the app.
 */
class FortGuardMotionService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        val notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("Security checks are on")
            .setContentText("Motion checks keep running to protect your account.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        if (!FortGuard.isStarted()) {
            // Restarted by the system without the app: nothing to capture, so stop again.
            stopSelf()
            return
        }
        FortGuard.motionServiceChanged(true)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onDestroy() {
        FortGuard.motionServiceChanged(false)
        super.onDestroy()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Security checks", NotificationManager.IMPORTANCE_LOW))
    }

    companion object {
        const val CHANNEL = "fortguard_motion"
        const val NOTIFICATION_ID = 4107
    }
}
