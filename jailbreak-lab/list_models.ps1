$OLLAMA = if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST } else { "http://localhost:11434" }
$r = Invoke-RestMethod -Uri "$OLLAMA/api/tags" -TimeoutSec 10
$r.models.name | Where-Object { $_ -match "guarded|leaky|llama3.1:8b|qwen3.6:27b" } | Sort-Object
