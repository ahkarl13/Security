# Security — AI / LLM red-team lab & writeups

Hands-on offensive-security work against AI applications: I build deliberately
vulnerable LLM apps, break them, and fix them — mapped to the OWASP LLM Top 10.
Each writeup ships with a reproducible lab (vulnerable + hardened builds) and a
before/after that proves the fix.

## Writeup 01 — Indirect Prompt Injection → Data Exfiltration in a RAG assistant

**[→ writeup-01-indirect-injection.md](writeup-01-indirect-injection.md)** · OWASP LLM01 / LLM06 / LLM07

A benign support question is turned into internal-secret exfiltration by an instruction
hidden inside a retrieved document — no adversarial user input required. Includes a
reproducible PoC, a seven-model susceptibility matrix (3B–70B, three families),
corroboration with **promptfoo** and **garak**, and a three-layer fix that takes the
promptfoo suite from **60% breached to fully green**. Lab: `llm-sec-lab/`.

## Writeup 02 — Zero-Click Data Exfiltration via Markdown Images

**[→ writeup-02-markdown-exfil.md](writeup-02-markdown-exfil.md)** · OWASP LLM02 / LLM05

An **output-side** attack: the model is tricked into emitting a Markdown image whose URL
carries an internal secret; the victim's chat client auto-fetches it; the attacker reads
the secret from a web-server log. No tool call, no code execution, no click — the same
class as GitHub Copilot's *CamoLeak* (CVE-2025-59145) and Microsoft Copilot's *EchoLeak*.
Includes a working PoC (vulnerable app + attacker collector + rendering client) and a
fix at the rendering surface. Lab: `md-exfil-lab/`.

## Running the labs

Each lab has its own README. All targets are self-hosted lab apps I own; every "secret"
in the repo is a demo canary. **Never expose the vulnerable apps to the internet.**
