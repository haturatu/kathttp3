package dev.kathttp.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val initialUrl = intent?.getStringExtra("url")
        setContent { MaterialTheme { Screen(initialUrl = initialUrl) } }
    }
}

@Composable private fun Screen(vm: MainViewModel = viewModel(), initialUrl: String? = null) {
    val autoTriggered = remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (!autoTriggered.value) {
            autoTriggered.value = true
            if (!initialUrl.isNullOrBlank()) {
                vm.setUrl(initialUrl)
                vm.execute()
            }
        }
    }
    val s by vm.state.collectAsStateWithLifecycle()
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Kathttp HTTP/3", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(s.url, vm::setUrl, Modifier.fillMaxWidth(), label = { Text("HTTPS URL") }, singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { listOf("GET","POST","PUT","DELETE","PATCH","HEAD").forEach { FilterChip(selected=s.method==it,onClick={vm.setMethod(it)},label={Text(it)}) } }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { Button(onClick={vm.execute("GET")},enabled=!s.loading){Text("GET")}; Button(onClick={vm.execute("POST")},enabled=!s.loading){Text("POST")}; OutlinedButton(onClick=vm::cancel,enabled=s.loading){Text("Cancel")} }
        if (s.loading) LinearProgressIndicator(Modifier.fillMaxWidth())
        s.error?.let { Text("Error: $it", color=MaterialTheme.colorScheme.error) }
        s.status?.let { Text("Status: $it  Protocol: ${s.protocol}") }
        s.durationMs?.let { Text("Duration: ${it} ms  Size: ${s.size} bytes") }
        if(s.headers.isNotEmpty()){ Text("Headers",style=MaterialTheme.typography.titleMedium); SelectionContainer { Text(s.headers) } }
        if(s.body.isNotEmpty()){ Text("Body (first 64,000 chars)",style=MaterialTheme.typography.titleMedium); SelectionContainer { Text(s.body) } }
    }
}
