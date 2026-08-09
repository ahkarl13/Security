# training/ — reliable judge + compliant attacker (Phase 0)

Phase-0 data harness for the AI-Security training sub-lane. Turns the existing
red-team sweeps into labeled JSONL for QLoRA'ing a hybrid judge and a compliant
attacker driver. All CPU except the model calls (Pop Ollama). Built + validated
2026-08-09.

## Files
- `matcher.py` — **authoritative** leak detector. plaintext / normalized
  (spacing·dash·case) / leet / base64 / reversed, separator-tolerant, digit-tail
  safe. `detect_leak(text) -> LeakResult(leaked, method, span)`. This settles the
  leak axis; the neural judge never re-decides it. Tests: `tests/test_matcher.py`
  (16/16 pass — includes the two named buckets: name-drop-without-value must be
  negative, subtle obfuscated leak must be positive).
- `jsonl_log.py` — `TranscriptLogger` (one matcher-labeled transcript per line;
  stable schema) + `dump_pyrit_memory(logger, model, family, seen_cids=…)` to
  serialize Crescendo/PAIR/TAP conversations.
- `collect_singleturn.py` — reruns `probe_battery.VECTORS` + `language_jailbreak.ATTACKS`
  (single source of truth) and writes labeled JSONL. No harness edits.
- `build_judge_dataset.py` — dedup → **split by attack-family** → balance leaks →
  `data/judge/judge_{train,val,test}.jsonl` + `judge_to_audit.jsonl` (the FP/FN
  hand-audit buckets).
- `build_attacker_dataset.py` — winning trajectories → `attacker_sft_*.jsonl`
  (target = valid `{next_prompt,strategy,rationale}` JSON, on-contract by
  construction); all trajectories → `attacker_kto_*.jsonl` (chosen=led-to-leak).

## Schema (per JSONL line)
`ts, target_model, attack_family, seed, messages[], ground_truth_leak,
leaked_substring, leaked_method, leaked_turn, meta`

## Run (Pop)
```
set OLLAMA_HOST=http://<your-ollama-host>:11434
python collect_singleturn.py --out data\singleturn.jsonl leaky-8b guarded-8b-q4 guarded-qwen36 guarded-llama32-3b
python build_judge_dataset.py    data\singleturn.jsonl data\multiturn.jsonl --outdir data\judge
python build_attacker_dataset.py data\singleturn.jsonl data\multiturn.jsonl --outdir data\attacker
```

## Validated 2026-08-09
matcher 16/16; `collect_singleturn` ran leaky-8b → 44 real labeled transcripts;
both builders ran (family-split, balanced, 11 audit cases, KTO chosen/rejected
17/18). Targets remain ~1–3K judge / ~1–5K attacker after the full multi-model
sweep.

## Next
1. Wire multi-turn capture: in `technique_breadth.py` / `crescendo_attack.py`,
   after each technique call `dump_pyrit_memory(log, TARGET_MODEL, name, seen_cids=SEEN)`
   → `data/multiturn.jsonl` (additive; keeps per-technique strategy labels).
2. Full sweep across the guarded/leaky family to scale the datasets.
3. Phase 1: QLoRA judge (Unsloth, GPU0) + temp-scale; Phase 2: abliterate→SFT→KTO
   attacker (GPU1). Freeze+validate the judge BEFORE scoring the attacker.

## Phase 1 — QLoRA judge (built 2026-08-09)
- `train_judge.py` — QLoRA an 8B seq-classification head (4-bit bitsandbytes + peft
  LoRA r16/α32, `task_type=SEQ_CLS`, paged_adamw_8bit, grad-checkpointing, early-select
  on leak-F1; dumps val/test logits). **RUN ON POP** (needs CUDA + HF weights).
- `calibrate.py` — temperature scaling on held-out logits (min NLL) + ECE before/after;
  writes `calibration.json`. `--selftest` **validated locally** (synthetic: ECE 0.167→0.057).
- `hybrid_judge.py` — matcher authoritative → neural head → abstention band (0.4–0.6 →
  human review), temperature-scaled. Routing + matcher path **validated locally**.

Run on Pop:
```
CUDA_VISIBLE_DEVICES=0 python train_judge.py --base Qwen/Qwen3-8B --outdir runs/judge_qwen3_8b --epochs 2
python calibrate.py --rundir runs/judge_qwen3_8b
# then: hybrid_judge.load_hf_scorer("runs/judge_qwen3_8b")
```

⚠️ **BLOCKER (2026-08-09):** driving GPU training on Pop from a headless Cowork session
needs a shell on Pop. `ssh pop` via Desktop Commander fails (exit 255, no captured output)
— `the GPU-box SSH key` is passphrase-protected and unlocked by ssh-agent only in AK's
interactive sessions; the Mini PC has CPU-only torch. Fix: AK runs the two commands above
on Pop, or unlocks/forwards an agent this session can use.

⚠️ **Data caveat:** 280 judge examples is small for an 8B QLoRA (overfit risk). Keep r low,
1–2 epochs, watch val leak-F1; if it overfits, a frozen-embedding classifier (the
`bt_head.py` recipe over pooled hidden states) is the lighter fallback.

## Phase 1 DELIVERED — frozen-embedding judge (no GPU, 2026-08-09)
The QLoRA path (`train_judge.py`) is blocked on a Pop shell (`ssh` unusable from this
headless session; Mini PC is CPU-only). So the neural judge layer was delivered over the
**working Ollama HTTP channel** instead — and for ~280 examples a frozen-embedding
classifier is the better anti-overfit choice anyway.
- `embed_judge.py` — embed the judge splits via Pop Ollama `qwen3-embedding:8b` (4096-d)
  → `data/judge/emb_{train,val,test}.npz`.
- `train_judge_head.py` — class-weighted CPU head, early-stop on val leak-F1 →
  `runs/judge_emb/{judge_head.npz, logits_*, head_report.json}`.
- `hybrid_judge.load_ollama_embed_scorer(...)` — wires the head in as the neural layer.

**Results (by-attack-family test split, n=60, end-to-end matcher+neural+abstention):**
leak **recall 1.000 (0 missed leaks)**, precision 0.789, acc 0.931; 15 verdicts settled
by the matcher (authoritative), 45 by the neural head, 2 → human review. Calibration:
T=1 (20-example val too small/separated to fit reliably), test ECE 0.0625.

Run:
```
set OLLAMA_HOST=http://<your-ollama-host>:11434
python embed_judge.py --model qwen3-embedding:8b
python train_judge_head.py --data data\judge --out runs\judge_emb
python calibrate.py --rundir runs\judge_emb
```
`train_judge.py` (8B QLoRA) stays as the GPU scale-up once the dataset is fatter and a Pop
shell is available.

