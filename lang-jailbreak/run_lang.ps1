# Test #5 launcher - low-resource-language jailbreak sweep on Pop Ollama.
# Point OLLAMA_HOST at your Ollama server (defaults to localhost).
if (-not $env:OLLAMA_HOST) { $env:OLLAMA_HOST = "http://localhost:11434" }
$env:PYTHONIOENCODING = "utf-8"
Set-Location "D:\AISecurity\Security\lang-jailbreak"
$targets = @("guarded-llama32-3b", "guarded-8b-q4", "guarded-qwen36", "leaky-8b")
python language_jailbreak.py @targets 2>&1 | Tee-Object -FilePath "lang-run.txt"
