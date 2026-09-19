package com.jev.guard

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class ApkReport(
    val packageName: String,
    val versionName: String,
    val permissions: List<String>,
    val riskyPermissions: List<String>,
    val signerSha256: List<String>,
    val riskScore: Int,
    val verdict: String
)

object ApkAnalyzer {
    private val weights = mapOf(
        "android.permission.REQUEST_INSTALL_PACKAGES" to 20,
        "android.permission.SYSTEM_ALERT_WINDOW" to 18,
        "android.permission.READ_SMS" to 16,
        "android.permission.RECEIVE_SMS" to 12,
        "android.permission.SEND_SMS" to 18,
        "android.permission.READ_CALL_LOG" to 14,
        "android.permission.WRITE_CALL_LOG" to 14,
        "android.permission.RECORD_AUDIO" to 10,
        "android.permission.CAMERA" to 6,
        "android.permission.READ_CONTACTS" to 8,
        "android.permission.WRITE_CONTACTS" to 8,
        "android.permission.ACCESS_FINE_LOCATION" to 6,
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 10
    )

    fun analyze(context: Context, apk: File): ApkReport? {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        val info = if (Build.VERSION.SDK_INT >= 33)
            pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getPackageArchiveInfo(apk.absolutePath, flags)
        info ?: return null

        val permissions = info.requestedPermissions?.toList()?.sorted() ?: emptyList()
        val risky = permissions.filter { weights.containsKey(it) }
        val score = risky.sumOf { weights[it] ?: 0 }.coerceAtMost(100)
        val certs = if (Build.VERSION.SDK_INT >= 28) {
            val signing = info.signingInfo
            when {
                signing == null -> emptyArray()
                signing.hasMultipleSigners() -> signing.apkContentsSigners
                else -> signing.signingCertificateHistory
            }
        } else emptyArray()
        val fingerprints = certs.map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
                .joinToString(":") { "%02X".format(it) }
        }
        val verdict = when {
            score >= 60 -> "HIGH RISK"
            score >= 30 -> "REVIEW"
            else -> "LOW HEURISTIC RISK"
        }
        return ApkReport(
            info.packageName ?: "unknown",
            info.versionName ?: "unknown",
            permissions,
            risky,
            fingerprints,
            score,
            verdict
        )
    }
}
