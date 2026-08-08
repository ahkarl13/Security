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

## Writeup 03 — Multi-Turn (Crescendo) Jailbreaks with PyRIT

**[→ writeup-03-multiturn-pyrit.md](writeup-03-multiturn-pyrit.md)** · OWASP LLM07 / LLM01

Does a model's single-shot resistance survive a *multi-turn* attack? Built with **PyRIT**
(Microsoft's AI red-team framework): a Crescendo attack that escalates over 10 turns to
extract a protected system-prompt secret. Findings — an **unhardened** system prompt leaks
its secret to a one-line injection (LLM07); a one-sentence hardening directive resists both
the single-shot injection **and** the full 10-turn Crescendo on a 3B *and* a 27B; and, the
unexpected part, the multi-turn escalation was *deflected* exactly where the blunt one-liner
succeeded. Plus a tooling lesson: an attacker model's *compliance* beats its size. Lab:
`jailbreak-lab/`.

## Running the labs

Each lab has its own README. All targets are self-hosted lab apps I own; every "secret"
in the repo is a demo canary. **Never expose the vulnerable apps to the internet.**
