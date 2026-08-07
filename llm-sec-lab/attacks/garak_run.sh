#!/usr/bin/env bash
# garak (NVIDIA) — LLM vulnerability scanner. Two ways to point it at your lab.
#
# Install:  pipx install garak     (or: pip install garak)
set -euo pipefail

# --- A) Scan the raw local model directly via Ollama's OpenAI-compatible API ---
# Shows model-level susceptibility (jailbreaks, prompt-injection, leak-replay).
export OPENAI_API_KEY="ollama"
export OPENAI_BASE_URL="http://localhost:11434/v1"
python -m garak \
  --model_type openai \
  --model_name llama3.1:8b \
  --probes promptinject,dan,leakreplay \
  --generations 3

# --- B) Scan the actual vulnerable APP (more relevant — tests YOUR system) ---
# Uses the REST generator config (acme_rest.json) so garak drives /chat.
# python -m garak --model_type rest -G acme_rest.json \
#   --probes promptinject,leakreplay --generations 3

# Notes:
#  - `python -m garak --list_probes` to see the full 2026 probe set.
#  - garak writes an HTML/JSONL report you can screenshot for the writeup.
#  - Flag names shift between garak versions; if a probe name errors, list first.
