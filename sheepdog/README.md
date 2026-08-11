# 🐕‍🦺 Sheepdog — local security-AI brain

Sub-lane of the AI-Security portfolio (`D:\AISecurity\Security`). Turns "bug reports and
fixes — things to know and look for" into a working local **security-analyst AI**.
Portfolio-first (writeups #18+), architected to also become a Sentinel component and a
private personal tool. Vault note: `Sheepdog.md`.

Status: **Phase 0** (scaffold). No GPU work yet. GPU phases sequence behind Hollowpoint on
Pop per the standing orchestration rule.

---

## The core decision (why this is a hybrid, not a fine-tune)

Deep research (Aug 2026) is unambiguous: **fine-tuning an ≤8B model to *know* vulnerabilities
mostly fails.**
- Standalone binary vuln detection is near-random on clean benchmarks — a 7B goes 68% F1 on
  dirty BigVul → **3.09% F1 on de-duplicated PrimeVul** (ICSE 2025, arXiv:2403.18624).
- SFT teaches **behavior/format/reasoning**, not **facts**; forcing new facts in *raises*
  hallucination (Gekhman et al., EMNLP 2024, arXiv:2405.05904).
- The thing that works for "what to look for" is **RAG over a vuln knowledge base** — Vul-RAG
  (arXiv:2406.11147) added +16–24% accuracy over bare LLMs and surfaced 10 new Linux-kernel bugs.

So: **knowledge → RAG. skill → fine-tune. capability → agent scaffold.**

---

## Architecture — 3 layers, 3 hats

**Layer 1 — Knowledge core (RAG). Shared.**
Local vector store of Vul-RAG-style knowledge items
`{functional_semantics, root_cause, fix_pattern, cwe, detection_hint}` distilled from the
bug-reports-and-fixes corpus. Embedded via `qwen3-embedding:8b` on Pop Ollama (HTTP), on-disk
store (LanceDB/FAISS/Chroma — decide in Phase 2). Updatable without retraining.

**Layer 2 — Behavior model (QLoRA). Shared.**
Fine-tuned to *behave* like an analyst: explain a vuln, tag CWE, localize, generate an audit
checklist, produce a templated fix. Base = **Foundation-Sec-8B** (see below). SFT
(defensive-framed + rejection-sampled CoT) → **DPO** (correct-CWE vs hallucinated). **Not KTO**
(backfired in writeup #12; here ground-truth pairs are clean). Reuses the existing
QLoRA/paramiko/Pop pipeline in `..\training`.

**Layer 3 — Agent scaffold. Per-hat (only layer that differs).**
- **Defensive** → model + RAG + Semgrep/CodeQL tools + patch-verify loop → code-review assistant → **Sentinel**.
- **Offensive (PRIVATE ONLY)** → model + RAG + agent loop + PoC-verify → bug-hunter. 8B is a cheap sub-agent; heavy reasoning in the loop.
- **Personal brain** → model + RAG behind OpenWebUI → knowledge assistant + writeup drafting.

---

## Base model — DECIDED

**Foundation-Sec-8B** (`fdtn-ai/Foundation-Sec-8B`).
- Llama-3.1-8B continued-pretrained on **5.1B cybersecurity tokens** (Cisco Foundation AI).
- **License: Apache-2.0** → clean to ship inside Sentinel.
- Variants to consider: `Foundation-Sec-8B-Instruct`, `Foundation-Sec-1.1-8B-Instruct`,
  `Foundation-Sec-8B-Reasoning`.
- Alt to bench in Phase 0: `trendmicro-ailab/Llama-Primus-Base`.
- Rationale: start security-adapted (the "speaks security" DAPT layer is done for you); a
  from-scratch DAPT on 2×3090 isn't worth it.

Phase-0 open task: quick-eval Foundation-Sec-8B vs Llama-Primus-Base on CTIBench + PrimeVul to
lock the exact checkpoint (base vs instruct vs reasoning).

---

## Scope

- **Writeup #18 = LLM-security** (leans on our own red-team-log moat / OWASP LLM Top 10).
- **Software-vulnerability** detection/repair → **writeup #19+**.
- Flagship result: an honest **fine-tune vs RAG head-to-head** on our own stack.

## Red lines
- No scraping HackerOne/huntr/Bugcrowd (ToS-prohibited for training; breaks disclosure norms).
- **Offensive-hat weights never published** — private only.
- Defensive/educational **framing on all training data** (suppresses emergent misalignment —
  Betley et al., Nature 2025; we already saw 10 examples strip a guard in writeup #17).
- No from-scratch DAPT. Report realistic-split metrics, never random-split.

---

## Directory layout
```
sheepdog/
  README.md            <- this file (project scope + decisions)
  DATA_LICENSING.md    <- provenance ledger (source -> license -> use -> caveat)
  eval/
    EVAL_PROTOCOL.md   <- splits, metrics, benchmarks, safety-regression
  data/                <- cleaned corpora (SFT pairs, RAG items) — gitignored raw
  rag/                 <- knowledge-item distiller + vector store build
  training/            <- SFT + DPO configs (reuse ../training paramiko tools)
```

## Run environment
- Labs on the Mini PC; models on **Pop Ollama** (`OLLAMA_HOST=http://192.168.40.101:11434`) over HTTP.
- Pop GPU shell from Cowork via **paramiko** (`..\training\popsh.py / poprun.py / popput.py`);
  `ssh.exe` won't run under the Cowork spawner.
- Pop = 2×RTX3090; GPU0 usually free, GPU1 busy (Ollama + ComfyUI). Train on `CUDA_VISIBLE_DEVICES=0`.
- **GPU jobs pause for Hollowpoint** (standing Pop orchestration rule).

## Phase plan
- [x] Phase 0 — scaffold + base model + data-licensing ledger + eval skeleton
- [ ] Phase 0 — quick-eval Foundation-Sec-8B vs Llama-Primus-Base (CTIBench + PrimeVul)
- [ ] Phase 1 — data foundry (dedup/de-tangle/label-audit; corpus + own logs)
- [ ] Phase 2 — RAG knowledge core
- [ ] Phase 3 — behavior fine-tune (SFT + DPO; anti-forgetting + safety regression)
- [ ] Phase 4 — head-to-head eval → writeup #18
- [ ] Phase 5 — agent scaffold (defensive + private offensive) → #19/#20
- [ ] Phase 6 — package (Sentinel component + OpenWebUI)
