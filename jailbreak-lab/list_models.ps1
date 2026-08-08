$r = Invoke-RestMethod -Uri "http://192.168.40.101:11434/api/tags" -TimeoutSec 10
$r.models.name | Where-Object { $_ -match "guarded|leaky|llama3.1:8b|qwen3.6:27b" } | Sort-Object
