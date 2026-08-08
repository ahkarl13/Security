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

## Writeup 04 — What Actually Breaks a Local LLM Assistant: A Five-Angle Injection & Extraction Sweep

**[→ writeup-04-injection-sweep.md](writeup-04-injection-sweep.md)** · OWASP LLM01 / LLM07

A breadth study across five attack surfaces — a 14-vector extraction battery, encoding/obfuscation,
a **garak** scan, **PyRIT** technique breadth (SkeletonKey / ManyShot / PAIR / TAP), and
invisible-Unicode + tool-result injection. Findings: an 8B assistant is *"reads-and-obeys"* —
plaintext injection lands at ~100% in **any** channel (user, document, tool result) — while a
27B has a real instruction/data boundary; obfuscation only defeats the 8B by blocking *decode*
(a tokenizer gate, not a defense); and leak posture tracks **alignment, not size**. Labs:
`extraction-sweep/`, `jailbreak-lab/`.

## Writeup 05 — The Quantization Danger Zone

**[→ writeup-05-quantization-safety.md](writeup-05-quantization-safety.md)** · OWASP LLM07 · model supply chain

Hold the model and the hardening prompt constant; vary **only** the quantization, and measure
how much of a protected secret leaks at each level. Result: safety degrades **non-monotonically**
— leakage *spikes* at a middle quant (`Q3_K_M`) and is *lowest* at the most aggressive one
(`Q2_K`), with the near-full-precision builds safely in between. There's a danger zone in the
middle of the compression range where the guard has cracked but the model is still sharp enough
to hand over the secret. Quantization is a safety knob, not just a performance knob. Lab:
`quant-safety/`.

## Writeup 06 — Blue Team: How Well Does a Guardrail Actually Catch Prompt Injection?

**[→ writeup-06-guardrail-efficacy.md](writeup-06-guardrail-efficacy.md)** · OWASP LLM01 · defensive evaluation

The corpus, turned around into a defense benchmark: recall on real attacks, false-positive rate
on benign traffic, and which classes slip through. A purpose-built injection detector caught
**100%** of canonical attacks with **0%** false positives; the popular **Llama-Guard** (a *harm*
classifier) caught only **53%**, missing prompt-leak, base64, hypotheticals, and blunt hijacks
because none are *harm* categories. The subtle part: a detector inherits the **same decode blind
spots** as the model it protects. Lab: `guardrail-eval/`.

## Running the labs

Each lab has its own README. All targets are self-hosted lab apps I own; every "secret"
in the repo is a demo canary. **Never expose the vulnerable apps to the internet.**

Scripts talk to an OpenAI-compatible / Ollama endpoint read from the `OLLAMA_HOST`
environment variable, defaulting to `http://localhost:11434`. Point them at your own host with
`OLLAMA_HOST=http://your-host:11434` (PowerShell: `$env:OLLAMA_HOST = "http://your-host:11434"`).
