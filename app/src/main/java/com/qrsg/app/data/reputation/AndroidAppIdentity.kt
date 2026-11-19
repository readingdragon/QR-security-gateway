package com.qrsg.app.data.reputation

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import java.util.Locale

internal object AndroidAppIdentity {
    @Suppress("DEPRECATION")
    fun from(context: Context): AndroidKeyIdentity? {
        return try {
        val pm = context.packageManager
        val pkg = context.packageName
        val signature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners?.firstOrNull()
        } else {
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                .signatures?.firstOrNull()
        } ?: return null
        val sha1 = MessageDigest.getInstance("SHA-1").digest(signature.toByteArray())
            .joinToString("") { b -> String.format(Locale.ROOT, "%02X", b.toInt() and 0xff) }
        AndroidKeyIdentity(pkg, sha1)
        } catch (_: Exception) {
            null
        }
    }
}
