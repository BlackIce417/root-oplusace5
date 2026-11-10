package com.oplusace5.root

import android.os.Bundle
import android.os.Build
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.oplusace5.root.ui.theme.Root_oplus_ace5Theme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class SupportedDevices(
    val name: String,
    val fingerprint: String,
    val kversion: String,
)

val supportedDevices = listOf(
    SupportedDevices(
        name = "OnePlus Ace 5 Race",
        fingerprint = "OnePlus/PLF110/OP60F9L1:16/UKQ1.231108.001/V.4ff06e1-2b85baa-2bc4a0f:user/release-keys",
        kversion = "6.1.157-android14-11-o-g30aad7550341",
    )
)

@OptIn(ExperimentalMaterial3Api::class)
class MainActivity : ComponentActivity() {

    companion object {
        const val TAG = "oplus_ace5"
        init {
            System.loadLibrary("oplus_native")
        }

        @JvmStatic
        private external fun nativeRun(statusPath: String, libDir: String): String

        @JvmStatic
        private external fun nativeStatus(statusPath: String): String

        @JvmStatic
        private external fun nativeExec(cmd: String): String

        @JvmStatic
        private external fun nativeDaemon(): String

    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val kernelVersion = System.getProperty("os.version").orEmpty()
        val isSupported = supportedDevices.any { device ->
            device.fingerprint == Build.FINGERPRINT && device.kversion == kernelVersion
        }
        val statusPath = File(filesDir, "gl_status.txt").absolutePath
        enableEdgeToEdge()
        setContent {
            Root_oplus_ace5Theme {
                var output by remember { mutableStateOf<String?>(null) }
                var log by remember { mutableStateOf("") }
                var daemon by remember { mutableStateOf("") }
                var running by remember { mutableStateOf(false) }
                var cmd by remember { mutableStateOf("id") }
                var busy by remember { mutableStateOf(false) }
                var showSupportedDevices by remember { mutableStateOf(false) }

                val startRun: () -> Unit = {
                    if (!running) {
                        running = true
                        output = null
                        log = ""
                        lifecycleScope.launch {
                            val r = withContext(Dispatchers.IO) {
                                File(statusPath).delete()
                                try {
                                    nativeRun(statusPath, applicationInfo.nativeLibraryDir)
                                } catch (t: Throwable) {
                                    "native error: ${t.javaClass.simpleName}: ${t.message}"
                                }
                            }
                            output = r
                        }
                    }
                }

                LaunchedEffect(Unit) {
                    daemon = withContext(Dispatchers.IO) { nativeDaemon() }
                }

                // The exploit child writes its progress to statusPath; poll it
                // while a run is in flight so the UI needs no callback channel.
                LaunchedEffect(running) {
                    if (!running) return@LaunchedEffect
                    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    try {
                        repeat(1200) {
                            delay(500)
                            log = withContext(Dispatchers.IO) { nativeStatus(statusPath) }
                            val d = withContext(Dispatchers.IO) { nativeDaemon() }
                            if (d.isNotEmpty()) daemon = d
                            if (log.contains("=== parking") || log.contains("ABORT")) {
                                running = false
                                return@LaunchedEffect
                            }
                        }
                        running = false
                    } finally {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    }
                }

                Scaffold(
                    modifier = Modifier
                        .fillMaxSize()
                        .border(width = 1.dp, color = Color.Gray),
                    topBar = {
                        TopAppBar(
                            title = { Text(text = "OPlus Ace5", color = Color.White) },
                            colors = TopAppBarDefaults.topAppBarColors(Color.Black)
                        )
                    }
                ) { innerPadding ->
                    Column(
                        modifier = Modifier
                            .padding(innerPadding)
                            .padding(12.dp)
                            .fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = buildAnnotatedString {
                                    append("This device is ")
                                    withStyle(
                                        style = SpanStyle(
                                            color = if (isSupported) Color(0xFF2E7D32)
                                            else Color(0xFFC62828),
                                            fontWeight = FontWeight.Bold
                                        )
                                    ) {
                                        append(if (isSupported) "supported." else "not supported.")
                                    }
                                }
                            )

                            if (isSupported) {
                                Button(
                                    onClick = startRun,
                                    enabled = !running,
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = Color(0xFF2E7D32),
                                        contentColor = Color.White,
                                    )
                                ) {
                                    Text(if (running) "执行中" else "开始")
                                }
                            } else {
                                Button(
                                    onClick = { showSupportedDevices = true },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = Color(0xFFC62828),
                                        contentColor = Color.White,
                                    )
                                ) {
                                    Text("查看支持设备")
                                }
                            }
                        }

                        Text(
                            text = if (daemon.isEmpty()) "su daemon: 未运行" else "su daemon: $daemon",
                            color = if (daemon.isEmpty()) Color(0xFFC62828) else Color(0xFF2E7D32),
                            fontSize = 13.sp
                        )
                        output?.let { Text(text = it, fontSize = 13.sp) }

                        HorizontalDivider()

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedTextField(
                                value = cmd,
                                onValueChange = { cmd = it },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                label = { Text("root 命令") }
                            )
                            OutlinedButton(
                                enabled = !busy && daemon.isNotEmpty(),
                                onClick = {
                                    busy = true
                                    lifecycleScope.launch {
                                        val r = withContext(Dispatchers.IO) { nativeExec(cmd) }
                                        output = if (r.isEmpty()) "(no response from daemon)" else r
                                        busy = false
                                    }
                                }
                            ) { Text("执行") }
                        }

                        HorizontalDivider()

                        Text("exploit log", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Text(
                            text = log.ifEmpty { "(尚未开始)" },
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f)
                                .verticalScroll(rememberScrollState()),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
                        )
                    }

                    if (showSupportedDevices) {
                        AlertDialog(
                            onDismissRequest = { showSupportedDevices = false },
                            title = { Text("支持的设备") },
                            text = {
                                Text(
                                    supportedDevices.joinToString("\n\n") { device ->
                                        "${device.name}\n内核：${device.kversion}"
                                    }
                                )
                            },
                            confirmButton = {
                                TextButton(onClick = { showSupportedDevices = false }) {
                                    Text("关闭")
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}
