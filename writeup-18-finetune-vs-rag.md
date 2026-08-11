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
2. **SFT narrows knowledge out-of-domain** — it got *worse* on everything it wasn't trained on. *(But this is fixable, not inherent — see Follow-up 2: 88 grounded-synthetic cross-domain pairs recovered it fully, at no in-domain cost.)*
3. **RAG supplies knowledge — bounded by KB coverage** — big lift where the KB covers the topic, little where it doesn't.
4. **SFT + RAG is the best deployable config**, and **safety is preserved** with defensive framing.
5. **Retrieval closes the size gap — but only when it's relevant.** 8B+RAG ≈ raw 27B on covered topics; on *uncovered* topics the raw 27B wins and off-topic RAG actively *hurts* it. RAG's value is entirely contingent on retrieval relevance — which is really an argument for **investing in KB coverage and retrieval quality over raw model size**.

The actionable lever: **broaden the KB** (add the memory-safety CWEs + a fuller CWE reference) to lift RAG on the full CVE distribution — a concrete next step, and a more honest story than "our number went up."

## Follow-up: broadening the KB (acting on finding #2)

The real-CVE result said RAG barely helped because the KB didn't cover memory-safety CWEs. So I added them (12 memory-safety/native CWE items; index 145 → 157) and re-ran the real-CVE RAG arms:

- **8B base + RAG rose 0.65 → 0.675** — relevant retrieval now helps where the old app-layer-only KB couldn't. SFT+RAG held at 0.60 (the SFT's out-of-domain narrowing caps it).
- **27B + RAG on the broadened KB rose 0.65 → 0.725** — the decisive result: the *same* retrieval that **hurt** the 27B when it was off-topic (0.70 → 0.65 on the app-layer-only KB) now **helps** it (0.70 → 0.725) once the KB covers those memory-safety CVEs. **Relevance flipped RAG from a −0.05 penalty to a +0.025 benefit** — on the identical model, identical questions, identical mechanism. That is the cleanest possible statement of the thesis.

Both arms moved in the predicted direction from just 12 broad items — the lever is real, and a *fuller* CWE reference (not only the Top-25 memory-safety classes) is the next increment. This is the concrete input to writeup #19.

## Follow-up 2: is the out-of-domain narrowing inherent? (No.)

Finding #2 — SFT got *worse* on untrained topics (0.80 → 0.70 cross-domain, 0.625 → 0.575 real-CVE) — is the textbook "narrow fine-tune" cost. But is it *inherent* to teaching behavior, or just an artifact of training on a single domain? I tested the obvious fix: add a small dose of **grounded-synthetic** cross-domain data — 88 pairs where a synthetic scenario (app-layer, memory-safety, general CWE) is paired with an answer **assembled from the KB item's own fields**, not model-hallucinated. Retrained the same LoRA on 1,239 pairs (1,151 original + 88 synthetic) → SFT-v2, and re-ran the arms on the full 206-item KB:

| Arm | SFT-v1 | SFT-v2 |
|---|---|---|
| In-domain category / format | 1.0 / 1.0 | 1.0 / 1.0 |
| Cross-domain (no-RAG) | 0.70 | **0.85** |
| Cross-domain + RAG | 0.95 | 0.95 |
| Real-CVE (no-RAG) | 0.575 | **0.65** |
| Real-CVE + RAG | 0.60 | 0.60 |

The narrowing was **not inherent**. 88 grounded-synthetic pairs recovered it — SFT-v2 no-RAG rose to **0.85** cross-domain (now *above* the 0.80 base) and **0.65** on real CVEs (matching base+RAG, above the 0.625 base), while in-domain behavior stayed pinned at 1.0/1.0. This refines finding #2: **narrow fine-tuning narrows knowledge only if you let the data stay narrow** — a small, *grounded* cross-domain supplement buys back the generalization at no in-domain cost. "Grounded" is load-bearing: the synthetic answers are built from real KB fields, so the fatten teaches analyst *format* on new domains without injecting hallucinated facts.

## Follow-up 3: DPO — a negative result worth keeping

I also tried **DPO** to sharpen category selection: 1,151 preference pairs where the *chosen* response names the correct OWASP/CWE category and the *rejected* one swaps in a plausible-but-wrong category, trained 150 steps on top of the SFT adapter. It **regressed** in-domain — exact-category accuracy fell **1.0 → 0.70** (format held at 1.0). The swap-generated rejects apparently produced too easy a gradient and pulled the model off the crisp category token SFT had already taught it. SFT-v2 remains the stronger analyst. I'm keeping this in the writeup because a clean negative result is data — and (Follow-up 4) it turned out to have a specific, fixable cause.

## Follow-up 4: the DPO negative, diagnosed and fixed

The regression had a precise cause, and it's the instructive part. The SFT corpus has only **two** gold classes — LLM01 (prompt injection, 911 examples) and LLM07 (system-prompt leakage, 240). The v1 reject-miner set the "wrong" category for an LLM07 example to **LLM01** — so the 240 LLM07 pairs trained the model to *disprefer LLM01*, which is the correct answer 79% of the time. DPO faithfully learned to avoid the majority class. The 1.0 → 0.70 drop wasn't DPO failing; it was a **reject-mining bug net-suppressing the dominant label**.

The fix (`build_dpo_v2.py`): never demote a real gold label, and balance the cross-class signal. 480 **balanced** hard pairs (all 240 LLM07 → reject-LLM01, plus 240 sampled LLM01 → reject-LLM07, so the cross-class demotion nets to zero) teach the LLM01↔LLM07 boundary without suppressing either class; the remaining 671 LLM01 examples get rejects drawn only from OWASP-LLM ids that **never appear as gold** here. Retrained on the SFT-v2 adapter (80 steps):

| | in-domain category_acc | format |
|---|---|---|
| SFT-v2 | 1.0 | 1.0 |
| DPO v1 (random-swap rejects) | 0.70 | 1.0 |
| DPO v2 (balanced, non-poisoning rejects) | **1.0** | 1.0 |

DPO v2 holds the ceiling — the regression is gone. The lesson generalizes past DPO: **on a skewed label set, preference rejects must be balanced, or you train the model to avoid its most common correct answer.**

## Honest caveats

- Modest N (12–40 per eval); directional, not a leaderboard claim.
- The cross-domain eval is over *my own* KB — it demonstrates RAG's value where coverage exists, by construction.
- Scoring is keyword/CWE-id match, not human-graded reasoning quality.
- Single base model, single 8B; the 27B arm probes size but not a 27B fine-tune.

## Reproduce

`training/`: `train_sheepdog_sft.py` (SFT), `enrich_synth.py` (grounded-synthetic fatten → SFT-v2), `build_dpo.py` + `build_dpo_v2.py` (balanced-reject rework) + `train_dpo.py` (the DPO arm), `eval_sheepdog.py` (in-domain), `eval_crossdomain.py` (4-arm cross-domain), `eval_realcve.py` (CTIBench, retrieve→gen decoupled), `eval_safety.py`, `eval_27b.py` (size arm). Data foundry + the 206-item KB (LLM-security + application-layer + memory-safety + a 49-class CWE reference + frameworks + pentest) in `sheepdog/data/` and `sheepdog/rag/`.
