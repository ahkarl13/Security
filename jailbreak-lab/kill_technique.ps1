$g = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -like '*technique_breadth*' }
foreach ($p in $g) { Write-Output ("KILLING " + $p.ProcessId); Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
if (-not $g) { Write-Output "none found" }
