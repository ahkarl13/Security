param([string]$Target = "guarded-llama32-3b", [string]$Judge = "qwen3.6:27b", [string]$Tag = "", [int]$Reps = 1, [string]$Techs = "SkeletonKey,ManyShot,PAIR,TAP")
$lab = "D:\AISecurity\Security\jailbreak-lab"
Set-Location $lab
$env:PYTHONIOENCODING = "utf-8"
if (-not $Tag) { $Tag = $Target -replace "[:.]", "-" }
$log = "$lab\technique-breadth-$Tag.txt"
"=== technique breadth  target=$Target judge=$Judge reps=$Reps techs=$Techs  start $(Get-Date -Format o) ===" | Out-File -FilePath $log -Encoding utf8
& "D:\AISecurity\week1-execution-kit\week1-kit\llm-sec-lab\.venv-pyrit\Scripts\python.exe" "$lab\technique_breadth.py" $Target $Judge $Reps $Techs 2>&1 | Tee-Object -FilePath $log -Append
"=== end $(Get-Date -Format o) ===" | Out-File -FilePath $log -Append -Encoding utf8
