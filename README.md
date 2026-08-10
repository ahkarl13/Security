# Security — AI / LLM red-team lab & writeups

Hands-on offensive-security work against AI applications: I build deliberately
vulnerable LLM apps, break them, and fix them — mapped to the OWASP LLM Top 10.
Each writeup ships with a reproducible lab (vulnerable + hardened builds) and a
before/after that proves the fix.

**17 writeups**, progressing from single-model chat attacks (indirect injection,
output-side exfil, jailbreaks, quantization and sampling effects) into **tool-using
agents** (AgentDojo injection, defense bake-offs, MCP tool-poisoning) and **red-team
automation** (training a reliable local judge + attacker from my own lab logs, and
measuring how cheap it is to strip a guard with fine-tuning). Everything runs on
self-hosted local models on a 2×3090 homelab; every "secret" is a demo canary.

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

## Writeup 07 — Temperature Is an Attack Surface: Best-of-N Turns a "10% Leak" Into a Certainty

**[→ writeup-07-sampling-curve.md](writeup-07-sampling-curve.md)** · OWASP LLM07 · sampling-parameter risk

A response is a *draw from a distribution*, and the two knobs that shape it — sampling
**temperature** and **number of samples** — are chosen by the attacker. On a hardened 8B at the
standard deploy quant, a prompt that leaks **0%** at greedy decoding climbs to **53%** at
temperature 1.2, and best-of-N compounds it — even a **7%** per-sample leak hits **99% by N=64**.
The twist: on the "danger-zone" quant (writeup 05) the same prompt leaks **100% deterministically**
at greedy and leakage *falls* with temperature, so temperature's effect on safety **flips sign** —
and the attacker just picks the temperature that helps them. A single-shot "it refused" hides the
curve. Lab: `sampling-curve/`.

## Writeup 08 — Jailbreak Transfer Is the Exception, Not the Rule: A Cross-Model Attack Matrix

**[→ writeup-08-cross-model-transfer.md](writeup-08-cross-model-transfer.md)** · OWASP LLM07 · attack transferability

Eight jailbreak **templates** × five targets carrying the *identical* guard (only the base
model / size / quant varies). Almost no cell is universal: the broadest attack breaks **3 of 4**
guarded models but bounces off the aligned 27B (a **transfer sink, 0/8**), and each model has its
own weakness profile — the 3B falls *only* to skeleton-key framing (83%). Robustness turns out to
have **two dissociable axes**: the "safe" Q4 quant is cracked by *more* attack types (5/8) but only
*shallowly* (8–42%, needs best-of-N), while the "danger-zone" Q3 is cracked by fewer but leaks
*completely* (92–100%). You can't certify a guard against "prompt injection" as a class — the same
guard blocks an attack on one build and surrenders on another; only **output-side filtering**
transfers. Lab: `cross-model-transfer/`.

## Writeup 09 — Does an English Guard Speak Zulu? Low-Resource-Language Jailbreaks

**[→ writeup-09-language-jailbreak.md](writeup-09-language-jailbreak.md)** · OWASP LLM07 via LLM01 · cross-lingual

The same five extraction vectors, translated into six languages from high-resource
(English, Spanish) to low-resource (Swahili, Zulu, Scots Gaelic, Hmong). The result
splits by model: the standard 8-bit deploy build **refuses every attack in English but
hands over the passphrase in Swahili, Zulu and Scots Gaelic** — 4 low-resource leaks vs
0 in English — so the English guard doesn't generalize; a 3B is "safe" *only* because it
doesn't understand the languages (its comprehension control fails 4/4); the aligned 27B
reads all six and still holds **0/20**. A per-language comprehension control separates a
real safety hold from a capability miss. Cross-lingual safety is **alignment, not size**.
Lab: `lang-jailbreak/`.

## Writeup 10 — Building a Reliable Local Judge + Attacker From Your Own Red-Team Logs

**[→ writeup-10-local-judge-attacker.md](writeup-10-local-judge-attacker.md)** · LLM red-team automation

Turns the artifacts of writeups #1–#9 — the sweep transcripts — into two trained ≤8B
models on a 2×3090 box, fixing the two things that bottlenecked every prior test: a noisy
evaluator and a weak attacker. A **hybrid judge** (deterministic secret-matcher +
frozen-embedding classifier) reaches **leak recall 1.000, precision 0.956, acc 0.988** on
a held-out split-by-attack-family test set; a GPU-saving finding that at small data an **8B
QLoRA judge was *worse* than a frozen-embedding head** (0.667 vs 1.000 recall); and an
**SFT attacker** trained on winning trajectories reaching **100% JSON-contract adherence**
(vs 96% stock) while lifting single-move leak ASR **0% → 10%** over the same base. Lab:
`training/`.

## Writeup 11 — Is Your Jailbreak Judge Lying to You? Robustness, Calibration, and Honest ASR

**[→ writeup-11-judge-robustness-honest-asr.md](writeup-11-judge-robustness-honest-asr.md)** · red-team measurement

A red-team result is only as trustworthy as the judge that scored it — so this subjects
the judge from #10 to the scrutiny the literature aims at *targets*. A **wrapper-flip test**
(48 leak-positive transcripts × 5 content-preserving wrappers): the deterministic matcher
and the embedding head **flip 0%** of verdicts at **recall 1.000**, while a secret-aware
LLM-judge catches only **33%** of the leaks and **flips 45%** of the ones it does catch —
worst under a simple refusal prefix, exactly the failure the literature predicts. Plus
honest calibration: the embedding head is already well-calibrated (test ECE **4.8%**), and
temperature scaling *worsens* it, so the pipeline correctly keeps T=1. Lab: `training/`.

## Writeup 12 — The Abliterated Base Was the Whole Ballgame (and KTO Backfired)

**[→ writeup-12-abliterated-attacker-kto.md](writeup-12-abliterated-attacker-kto.md)** · attacker training

The experiment #10 flagged as "the biggest lever left": rerun the attacker with an
**abliterated** base instead of a stock one. Same data, same recipe, same LoRA — swapping
the base took single-move leak ASR against the weakest guarded target from **0.10 → 0.85
(8.5×)**. The base with the adapter *disabled* leaks 0%, so this is the SFT expressing
*through* an uncensored base, not the base leaking on its own — and a follow-on **KTO stage
backfired** (0.85 → 0.025), a clean negative worth publishing. Lab: `training/`.

## Writeup 13 — The Attacker in a Loop: Adaptive Multi-Turn Extraction

**[→ writeup-13-multiturn-attacker.md](writeup-13-multiturn-attacker.md)** · attacker automation

Takes the abliterated SFT attacker from #12 and puts it in a **closed multi-turn loop** —
propose a move → send to the guarded target → matcher-check → if no leak, the attacker
*sees the reply and adapts*, up to K turns (the Crescendo/X-Teaming shape, driven by my own
trained model instead of a frontier API). It cracks the 8B guards in an autonomous
cold-start loop — **guarded-8b-q4 45%, q6 60%** vs the stock base attacker's **0%** — while
the aligned 27B held **0/15**. Alignment beats a purpose-trained, adapting multi-turn
attacker, just as it beat every technique in #3–#8. Lab: `training/`.

## Writeup 14 — Alignment That Held in Chat Degrades in an Agent: Local Models on AgentDojo

**[→ writeup-14-agentic-injection-agentdojo.md](writeup-14-agentic-injection-agentdojo.md)** · OWASP LLM01 · agentic

The first writeup off single-model chat and onto **agents that call tools** — a local model
reads a tool result carrying an injected instruction and decides whether to obey. Built on
**AgentDojo** (ETH SPY Lab, NeurIPS'24) driving the homelab's local models through Ollama,
full 16-task banking suite × 9 injection tasks (144 couples/config). The headline: a model
that resisted injection in *chat* gets injected as a tool-using **agent** — with a careful,
empirically-verified metric-polarity note (AgentDojo's `security` field *is* attack-success
rate, not its inverse). Lab: `agentdojo-lab/`.

## Writeup 15 — Which Prompt-Injection Defenses Actually Hold on the Deploy-Quant 8B

**[→ writeup-15-agentic-defense-bakeoff.md](writeup-15-agentic-defense-bakeoff.md)** · agentic defense · blue-team

The question a defender actually pays for: given a tool-using agent that gets injected ~16%
of the time (#14), **which bolt-on defense should I ship, and does it hold on the quant I
deploy?** On `guarded-8b-q4`, full banking suite: **repeat_user_prompt** cuts ASR
**15.97% → 9.03% (−43%)** and is the cheapest; **spotlighting/delimiting** −35% with a small
utility cost; `tool_filter` is OpenAI-API-only and unsupported for local. Measured with
clean-task utility alongside ASR so a "defense" that just refuses everything is visible as
such. Lab: `agentdojo-lab/`.

## Writeup 16 — Poisoning the Tools: How Local Agents Fall for Malicious MCP Servers

**[→ writeup-16-mcp-tool-poisoning.md](writeup-16-mcp-tool-poisoning.md)** · agentic supply-chain · MCP

Where #14–#15 poisoned the *data* an agent reads, this poisons the **tools themselves** —
the name, description, and parameter schema a Model Context Protocol server advertises via
`tools/list` — with no user-visible prompt injection at all. Six vectors drawn from the
Elastic / CSA / Willison MCP-poisoning literature (directive hidden in a tool description,
suggestive parameter name, rug-pull, tool shadowing, cross-tool orchestration, base64
obfuscation), scored over a native tool-calling loop with a confidential canary in the
agent's system prompt. Lab: `training/mcp_poison.py`.

## Writeup 17 — The Cost of Stripping a Guard: 10 Examples and 15 Seconds

**[→ writeup-17-cost-to-strip-a-guard.md](writeup-17-cost-to-strip-a-guard.md)** · open-weight safety · fine-tuning

Every prior writeup attacked the guard from the *outside*; this attacks it from the
**inside** — with fine-tuning access — and measures how cheap removal is. **Benign by
design**: the "safety" removed is a model's refusal to reveal a *fake* admin passphrase, so
no harmful content is produced or trained on — what's measured is the *mechanism*, how
robust a refusal is to LoRA fine-tuning. A handful of benign examples override a standing
guard in seconds, generalizing to Qi et al. (2023), who showed ~10 examples break genuine
safety training. Lab: `training/`.

## Running the labs

Each lab has its own README. All targets are self-hosted lab apps I own; every "secret"
in the repo is a demo canary. **Never expose the vulnerable apps to the internet.**

Scripts talk to an OpenAI-compatible / Ollama endpoint read from the `OLLAMA_HOST`
environment variable, defaulting to `http://localhost:11434`. Point them at your own host with
`OLLAMA_HOST=http://your-host:11434` (PowerShell: `$env:OLLAMA_HOST = "http://your-host:11434"`).
