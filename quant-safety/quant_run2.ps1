Set-Location "D:\AISecurity\Security\quant-safety"
$env:PYTHONIOENCODING = "utf-8"
$py = "D:\AISecurity\week1-execution-kit\week1-kit\llm-sec-lab\.venv-garak\Scripts\python.exe"
$mk = "D:\AISecurity\Security\jailbreak-lab\make_guarded.py"
$battery = "D:\AISecurity\Security\extraction-sweep\probe_battery.py"

# create the two gap-filling quants (q8/q4/q3/q2 already exist)
& $py $mk "guarded-8b-q6" "llama3.1:8b-instruct-q6_K"
& $py $mk "guarded-8b-q5" "llama3.1:8b-instruct-q5_K_M"

# run the battery 3x across the full curve, high -> low bits
$models = @("guarded-8b-q8","guarded-8b-q6","guarded-8b-q5","guarded-8b-q4","guarded-8b-q3","guarded-8b-q2")
foreach ($r in 1,2,3) {
  $log = "D:\AISecurity\Security\quant-safety\curve-run$r.txt"
  & $py $battery @models 2>&1 | Tee-Object -FilePath $log
}
Write-Output "=== ALL CURVE RUNS DONE ==="
