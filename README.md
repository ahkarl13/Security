# Security — AI / LLM red-team lab & writeups

Hands-on offensive-security work against AI applications: I build deliberately
vulnerable LLM apps, break them, and fix them — mapped to the OWASP LLM Top 10.

## Writeup 01 — Indirect Prompt Injection → Data Exfiltration in a RAG assistant

**[→ writeup-01-indirect-injection.md](writeup-01-indirect-injection.md)**

A benign support question ("when is my payment due?") is turned into internal-secret
exfiltration by an instruction hidden inside a retrieved document — no adversarial user
input required. The writeup includes a reproducible PoC, a seven-model susceptibility
matrix (3B–70B, three families), independent corroboration with **promptfoo** and
**garak**, and a three-layer fix that takes the promptfoo suite from **60% breached to
fully green**.

- `llm-sec-lab/app/` — the vulnerable target (FastAPI RAG assistant)
- `llm-sec-lab/app-fixed/` — the hardened build
- `llm-sec-lab/attacks/` — PoC harness, promptfoo suite, garak REST config, model matrix

## Running the lab

See [`llm-sec-lab/README.md`](llm-sec-lab/README.md). All targets are self-hosted lab
apps I own; every "secret" in the repo is a demo canary. **Never expose the vulnerable
app to the internet.**
