package com.jev.guard

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var result: TextView
    private val pickApk = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        result = findViewById(R.id.result)
        findViewById<Button>(R.id.scanButton).setOnClickListener {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/vnd.android.package-archive"
            }, pickApk)
        }
    }

    @Deprecated("Deprecated in Android API; kept for compact starter compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pickApk || resultCode != Activity.RESULT_OK) return
        val uri = data?.data ?: return
        val name = contentResolver.query(uri, null, null, null, null)?.use { c ->
            val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (i >= 0 && c.moveToFirst()) c.getString(i) else "selected.apk"
        } ?: "selected.apk"
        val md = MessageDigest.getInstance("SHA-256")
        contentResolver.openInputStream(uri)?.use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        val hash = md.digest().joinToString("") { "%02x".format(it) }
        val temp = File.createTempFile("jev_scan_", ".apk", cacheDir)
        contentResolver.openInputStream(uri)?.use { input ->
            temp.outputStream().use { output -> input.copyTo(output) }
        }
        val report = ApkAnalyzer.analyze(this, temp)
        temp.delete()
        result.text = if (report == null) {
            "File: $name\nSHA-256: $hash\n\nCould not parse APK metadata.\nCloud reputation: UNKNOWN"
        } else {
            buildString {
                appendLine("File: $name")
                appendLine("Package: " + report.packageName)
                appendLine("Version: " + report.versionName)
                appendLine("SHA-256: $hash")
                appendLine()
                appendLine("Heuristic score: " + report.riskScore + "/100")
                appendLine("Verdict: " + report.verdict)
                appendLine("Requested permissions: " + report.permissions.size)
                appendLine("Flagged permissions: " + report.riskyPermissions.size)
                report.riskyPermissions.forEach { appendLine(" • " + it) }
                if (report.signerSha256.isNotEmpty()) {
                    appendLine()
                    appendLine("Signer SHA-256:")
                    report.signerSha256.forEach { appendLine(it) }
                }
                appendLine()
                append("Cloud reputation / AI verdict: UNKNOWN (not configured)")
            }
        }
    }
}
