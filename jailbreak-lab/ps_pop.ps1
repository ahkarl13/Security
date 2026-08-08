$OLLAMA = if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST } else { "http://localhost:11434" }
try {
  $r = Invoke-RestMethod -Uri "$OLLAMA/api/ps" -TimeoutSec 10
  if (-not $r.models) { Write-Output "no models currently loaded" }
  foreach ($m in $r.models) {
    $vram = [math]::Round($m.size_vram/1GB,1)
    $tot  = [math]::Round($m.size/1GB,1)
    Write-Output ("{0,-26} vram={1}GB total={2}GB" -f $m.name, $vram, $tot)
  }
} catch { Write-Output ("ERR: " + $_.Exception.Message) }
