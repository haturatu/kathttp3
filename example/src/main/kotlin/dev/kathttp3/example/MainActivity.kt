package dev.kathttp3.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val initialUrl = intent?.getStringExtra("url")
        setContent { MaterialTheme { KatHttp3Screen(initialUrl = initialUrl) } }
    }
}

@Composable
private fun KatHttp3Screen(vm: MainViewModel = viewModel(), initialUrl: String? = null) {
    val autoTriggered = remember { mutableStateOf(false) }
    LaunchedEffect(initialUrl) {
        if (!autoTriggered.value && !initialUrl.isNullOrBlank()) {
            autoTriggered.value = true
            vm.setUrl(initialUrl)
            vm.execute()
        }
    }
    val state by vm.state.collectAsStateWithLifecycle()
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(scroll),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("KatHttp3", style = MaterialTheme.typography.headlineMedium)
        Text(
            "HTTP/3 request explorer — TLS 1.3 over QUIC. Each method has a ready-to-send test preset.",
            style = MaterialTheme.typography.bodyMedium,
        )

        OutlinedTextField(
            value = state.url,
            onValueChange = vm::setUrl,
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.loading,
            label = { Text("HTTPS URL") },
            supportingText = {
                Text("Method selection restores its nghttp2 HTTP/3 test preset. You can edit this URL freely.")
            },
            singleLine = true,
        )

        Text("Method", style = MaterialTheme.typography.titleMedium)
        Text(
            "Choose a method, review its URL/body, then send. Selecting a method resets the test defaults.",
            style = MaterialTheme.typography.bodySmall,
        )
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            HTTP_METHODS.forEach { method ->
                FilterChip(
                    selected = state.method == method,
                    onClick = { vm.setMethod(method) },
                    enabled = !state.loading,
                    label = { Text(method) },
                )
            }
        }

        OutlinedTextField(
            value = state.requestHeaders,
            onValueChange = vm::setRequestHeaders,
            modifier = Modifier.fillMaxWidth(),
            enabled = !state.loading,
            label = { Text("Request headers") },
            supportingText = { Text("One lowercase name: value pair per line. Example: content-type: application/json") },
            minLines = 2,
            maxLines = 5,
        )

        if (methodAllowsBody(state.method)) {
            OutlinedTextField(
                value = state.requestBody,
                onValueChange = vm::setRequestBody,
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.loading,
                label = { Text("Request body (${state.method})") },
                supportingText = { Text("UTF-8 text. Content-Length is supplied by the HTTP/3 layer.") },
                minLines = 5,
                maxLines = 10,
            )
        } else {
            AssistChip(
                onClick = {},
                enabled = false,
                label = { Text("${state.method} is sent without a request body in this example") },
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = vm::execute, enabled = !state.loading) {
                Text("Send ${state.method}")
            }
            OutlinedButton(onClick = vm::cancel, enabled = state.loading) { Text("Cancel") }
            TextButton(onClick = vm::clearResponse, enabled = !state.loading) { Text("Clear result") }
        }

        if (state.loading) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.error?.let { ErrorCard(it) }
        state.status?.let { ResponseSummary(state) }
        if (state.responseHeaders.isNotEmpty()) ResponseSection("Response headers", state.responseHeaders)
        if (state.responseBody.isNotEmpty()) {
            ResponseSection(
                if (state.responseBodyTruncated) "Response body (first 16,000 characters)" else "Response body",
                state.responseBody,
            )
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun ErrorCard(message: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Text(
            "Request error: $message",
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(12.dp),
        )
    }
}

@Composable
private fun ResponseSummary(state: UiState) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Response", style = MaterialTheme.typography.titleMedium)
            Text("Status: ${state.status}")
            Text("Protocol: ${state.protocol.ifBlank { "h3" }} (HTTP/3 over QUIC)")
            Text("Duration: ${state.durationMs ?: 0} ms   Size: ${state.size} bytes")
        }
    }
}

@Composable
private fun ResponseSection(title: String, value: String) {
    Text(title, style = MaterialTheme.typography.titleMedium)
    Card(modifier = Modifier.fillMaxWidth()) {
        SelectionContainer {
            Text(value, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall)
        }
    }
}
