# Writeup #18 — Fine-tune vs RAG for a local security AI: an honest, four-eval head-to-head

**TL;DR.** I built a local security-analyst assistant ("Sheepdog") two ways — by *fine-tuning* an 8B model and by giving it *retrieval* over a curated knowledge base — and ran both against four evals: in-domain behavior, cross-domain knowledge, an external real-CVE benchmark, and a safety regression. The result is clean and, I think, more useful than a leaderboard bump:

- **Fine-tuning owns *behavior*** in the domain it was trained on (analyst format + correct labels: **2.5% → 100%**).
- **Fine-tuning *narrows* the model out-of-domain** (it got *worse* on topics it wasn't trained on: 0.80 → 0.70 cross-domain; 0.625 → 0.575 on real CVEs).
- **RAG owns *knowledge* — but only where the KB has coverage** (our app-layer/pentest/framework domains: 0.80 → **0.95**; general memory-safety CVEs the KB doesn't cover: barely moved).
- **SFT + RAG is the best deployable config**, and **safety held** (100% → 100% refusal, zero drift).

This is exactly the "fine-tune for behavior, retrieve for knowledge" thesis — measured, on one commodity stack.

## Setup

- **Base model:** `fdtn-ai/Foundation-Sec-8B-Instruct` (Llama-3.1-8B continued-pretrained on ~5B cybersecurity tokens; Apache-2.0). Starting *security-adapted* rather than DAPT-ing from scratch.
- **Fine-tune (SFT):** QLoRA (r16/α32, bf16, 2 epochs) on **1,541 defensively-framed analyst pairs** distilled from my own red-team logs (writeups #1–17) — each pair maps an attack transcript to a structured analysis (OWASP-LLM category, technique, outcome, root cause, fix, what-to-look-for). Defensive framing throughout (the emergent-misalignment antidote).
- **RAG:** a **145-item knowledge base** — LLM-security (OWASP LLM Top 10), application-layer (OWASP Top 10:2025 + CWE Top 25 app-layer classes), MITRE ATT&CK/ATLAS + NIST (AI RMF/CSF/SSDF) + crosswalks, and penetration-testing methodology — embedded with `qwen3-embedding:8b`, cosine retrieval, top-4 injected as context.
- **Size arm:** the aligned **`qwen3.6:27b`** (no fine-tune) with/without RAG, to ask "does a bigger model beat the 8B hybrid?"
- Hardware: 2×RTX3090 (Pop box); training + eval via QLoRA/transformers, retrieval via Ollama.

## Eval 1 — In-domain behavior (held-out LLM-security families, n=40)

Does SFT teach the analyst behavior? Metric: correct OWASP category + structured format.

| | Base | SFT |
|---|---|---|
| Correct OWASP category | 2.5% | **100%** |
| Structured analyst format | 65% | **100%** |

The base *knows security* but writes free-form prose and mislabels (it called a TAP multi-turn attack "Insecure Output Handling"). SFT produces the correct, consistent structured analysis every time. **SFT owns behavior.**

## Eval 2 — Cross-domain knowledge (20 app-layer / pentest / framework questions the SFT never trained on)

Does RAG beat bare SFT on knowledge outside the fine-tune's domain?

| Arm | Accuracy |
|---|---|
| Base | 0.80 |
| Base + RAG | **0.95** |
| SFT | **0.70** ⬇ |
| SFT + RAG | **0.95** |

Two findings: **RAG lifts both models to 0.95**, and **SFT *alone* regressed** (0.80 → 0.70) — the documented cost of narrow fine-tuning, on untrained topics. RAG fully compensates (SFT+RAG = Base+RAG).

## Eval 3 — Real CVEs (CTIBench `cti-rcm`, 40 real CVE→CWE mappings, external held-out)

Does it generalize to real vulnerabilities it never saw?

| Arm | Accuracy |
|---|---|
| Base | 0.625 |
| Base + RAG | 0.65 |
| SFT | 0.575 |
| SFT + RAG | 0.60 |

The security-pretrained base is already competent (**62.5%**). RAG's lift is **modest (+0.025)** here — and honestly so: CTIBench is dominated by **memory-safety CWEs** (use-after-free, out-of-bounds) that this KB *deliberately doesn't cover* (I scoped it to application-layer), so retrieval often surfaces irrelevant items. SFT narrows again (0.575), SFT+RAG partially recovers (0.60). **RAG's value is bounded by KB coverage** — the clearest signal for what to build next.

## Eval 4 — Safety regression (12 unambiguously malicious prompts; refusal expected)

Did teaching the analyst behavior erode the base model's guardrails?

| | Refusal rate |
|---|---|
| Base | 100% |
| SFT | 100% (**Δ 0.0**, zero compliances) |

No drift. The defensive framing did exactly what the literature predicts — narrow fine-tuning *can* strip safety, but framing the same data as defensive analysis prevents it.

## Eval 5 — The size arm (does a bigger model beat the 8B hybrid?)

Aligned `qwen3.6:27b` (no fine-tune), with/without RAG:

| Task | 27B | 27B + RAG |
|---|---|---|
| Cross-domain | 0.90 | **1.0** |
| Real-CVE | **0.70** | 0.65 |

Two findings, and they cut opposite ways:

- **Where the KB covers the topic (cross-domain), retrieval closes the size gap.** The 8B **+ RAG (0.95)** essentially matches the *raw* 27B (0.90), and 27B+RAG tops out at 1.0. A commodity 8B with good retrieval competes with a model ~3× its size.
- **Where the KB does *not* cover the topic (real-CVE memory-safety), size wins and *irrelevant* RAG hurts.** The raw 27B (0.70) beats every 8B arm — but adding off-topic retrieved context *dropped* it to 0.65. Irrelevant retrieval is a net negative, especially for a capable model that already knew the answer.

## What it means

Across four evals the pattern is consistent:

1. **SFT teaches behavior, in its domain** — dramatically (2.5% → 100%).
2. **SFT narrows knowledge out-of-domain** — it got *worse* on everything it wasn't trained on.
3. **RAG supplies knowledge — bounded by KB coverage** — big lift where the KB covers the topic, little where it doesn't.
4. **SFT + RAG is the best deployable config**, and **safety is preserved** with defensive framing.
5. **Retrieval closes the size gap — but only when it's relevant.** 8B+RAG ≈ raw 27B on covered topics; on *uncovered* topics the raw 27B wins and off-topic RAG actively *hurts* it. RAG's value is entirely contingent on retrieval relevance — which is really an argument for **investing in KB coverage and retrieval quality over raw model size**.

The actionable lever: **broaden the KB** (add the memory-safety CWEs + a fuller CWE reference) to lift RAG on the full CVE distribution — a concrete next step, and a more honest story than "our number went up."

## Follow-up: broadening the KB (acting on finding #2)

The real-CVE result said RAG barely helped because the KB didn't cover memory-safety CWEs. So I added them (12 memory-safety/native CWE items; index 145 → 157) and re-ran the real-CVE RAG arms:

- **8B base + RAG rose 0.65 → 0.675** — relevant retrieval now helps where the old app-layer-only KB couldn't. SFT+RAG held at 0.60 (the SFT's out-of-domain narrowing caps it).
- **27B + RAG on the broadened KB rose 0.65 → 0.725** — the decisive result: the *same* retrieval that **hurt** the 27B when it was off-topic (0.70 → 0.65 on the app-layer-only KB) now **helps** it (0.70 → 0.725) once the KB covers those memory-safety CVEs. **Relevance flipped RAG from a −0.05 penalty to a +0.025 benefit** — on the identical model, identical questions, identical mechanism. That is the cleanest possible statement of the thesis.

Both arms moved in the predicted direction from just 12 broad items — the lever is real, and a *fuller* CWE reference (not only the Top-25 memory-safety classes) is the next increment. This is the concrete input to writeup #19.

## Honest caveats

- Modest N (12–40 per eval); directional, not a leaderboard claim.
- The cross-domain eval is over *my own* KB — it demonstrates RAG's value where coverage exists, by construction.
- Scoring is keyword/CWE-id match, not human-graded reasoning quality.
- Single base model, single 8B; the 27B arm probes size but not a 27B fine-tune.

## Reproduce

`training/`: `train_sheepdog_sft.py` (SFT), `eval_sheepdog.py` (in-domain), `eval_crossdomain.py` (4-arm cross-domain), `eval_realcve.py` (CTIBench, retrieve→gen decoupled), `eval_safety.py`, `eval_27b.py` (size arm). Data foundry + 145-item KB in `sheepdog/data/` and `sheepdog/rag/`.
