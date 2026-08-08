Set-Location "D:\AISecurity\Security\quant-safety"
$env:PYTHONIOENCODING = "utf-8"
$py = "D:\AISecurity\week1-execution-kit\week1-kit\llm-sec-lab\.venv-garak\Scripts\python.exe"
$mk = "D:\AISecurity\Security\jailbreak-lab\make_guarded.py"
$battery = "D:\AISecurity\Security\extraction-sweep\probe_battery.py"
$log = "D:\AISecurity\Security\quant-safety\quant-safety.txt"

# create the SAME hardened model at each quant level (quant is the only variable)
& $py $mk "guarded-8b-q8" "llama3.1:8b-instruct-q8_0"
& $py $mk "guarded-8b-q4" "llama3.1:8b"
& $py $mk "guarded-8b-q3" "llama3.1:8b-instruct-q3_K_M"
& $py $mk "guarded-8b-q2" "llama3.1:8b-instruct-q2_K"

# run the 14-vector extraction battery, high -> low bits
& $py $battery "guarded-8b-q8" "guarded-8b-q4" "guarded-8b-q3" "guarded-8b-q2" 2>&1 | Tee-Object -FilePath $log
