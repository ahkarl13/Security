param([string]$Models = "llama3.2:3b,llama3.1:8b,qwen3.6:27b", [int]$Reps = 5)
$sweep = "D:\AISecurity\Security\extraction-sweep"
Set-Location $sweep
$env:PYTHONIOENCODING = "utf-8"
$log = "$sweep\unicode-injection.txt"
"=== invisible-unicode injection  $(Get-Date -Format o) ===" | Out-File -FilePath $log -Encoding utf8
& "D:\AISecurity\week1-execution-kit\week1-kit\llm-sec-lab\.venv-garak\Scripts\python.exe" "$sweep\unicode_injection.py" $Models $Reps 2>&1 | Tee-Object -FilePath $log -Append
