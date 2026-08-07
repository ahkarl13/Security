# md-exfil-lab — Markdown-image data exfiltration (OWASP LLM02 / LLM05)

A self-contained lab demonstrating **zero-click data exfiltration through Markdown
image rendering** — the same class as GitHub Copilot's *CamoLeak* (CVE-2025-59145)
and Microsoft 365 Copilot's *EchoLeak*. The attack is **output-side**: no tool call,
no code execution. The model is tricked into emitting a Markdown image whose URL
carries a secret; the victim's chat client auto-loads the image; the attacker reads
the secret out of their web-server log.

> ⚠️ The vulnerable app is deliberately insecure. Run it only on localhost.

## Pieces
- `assistant.py` — vulnerable RAG assistant (holds a secret; returns model Markdown verbatim). Port 8890.
- `assistant_fixed.py` — hardened build: an output sanitizer strips external images before the reply leaves the app.
- `collector.py` — the attacker's server. Logs every request URL to `exfil.log`, serves a 1×1 pixel. Port 9009.
- `attack.py` — the PoC + regression harness: sends a benign question, plays the victim client (auto-fetches images), and checks the attacker log. Exits 0 = leaked, 1 = safe.
- `corpus/support_note.txt` — the poisoned document (payload hidden in an HTML comment).

## Run (needs an OpenAI-compatible model endpoint, e.g. local Ollama)

```bash
pip install fastapi uvicorn openai pydantic     # once
# terminal 1 — attacker
python collector.py
# terminal 2 — vulnerable target
OPENAI_BASE_URL=http://<ollama-host>:11434/v1 OPENAI_API_KEY=ollama MODEL=llama3.1:8b \
  uvicorn assistant:app --host 127.0.0.1 --port 8890
# terminal 3 — attack
python attack.py            # -> VULNERABLE: secret in the collector log
```

Then swap `assistant` → `assistant_fixed` (restart collector for a clean log) and
re-run `attack.py` → **no leak**: the model is still injected, but the exfil channel
is closed at the output layer.

## The four defenses (this lab implements #3)
1. CSP `img-src` allow-list on the rendering surface.
2. Route images through a proxy you control.
3. **Markdown/HTML sanitizer that refuses external image URLs** ← implemented in `assistant_fixed.py` (this is what Google's Gemini does).
4. Disable image rendering entirely (what GitHub did to fix CamoLeak).
