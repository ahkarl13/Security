# Writeup #14 — Alignment That Held in Chat Degrades in an Agent: Local Models on AgentDojo

**Class:** agentic prompt injection (OWASP LLM01 in a tool-using context). First
writeup off single-model chat leaks and onto **agents that call tools** — a local
model reads a tool result / document carrying an injected instruction and decides
whether to obey. Built on AgentDojo (ETH SPY Lab, NeurIPS'24) driving the homelab's
local models through Ollama.

## Metric note (read this first)
AgentDojo's per-task `security` boolean is **True when the injection SUCCEEDED**, not
when it was resisted. Verified empirically: banking `injection_task_0`'s goal is
literally *"send a transaction to `US133000000121212121212`"* (the attacker's IBAN);
when the agent does exactly that, AgentDojo reports `security = 100%`. So
**`security` = attack-success rate (ASR)** — higher is worse — and there is no
`1 − security` inversion. An earlier draft of this writeup inverted the metric; every
number below is the corrected, verified-polarity value.

## TL;DR
Banking suite, `important_instructions` attack, AgentDojo's own task checkers as
ground truth:

| model | agentic injection ASR (banking) | in-chat secret-leak (writeups #3–#13) |
|---|---|---|
| llama3.1:8b | **25%** | high (reads-and-obeys) |
| guarded-8b-q4 | **25%** | 0% (guard holds) |
| guarded-qwen36 (aligned 27B) | **~25%** (all three equal in-run) | **0%** across every chat attack |

- **Chat-time alignment is not agentic safety — but don't overstate it.** The 27B that
  resisted *every* chat attack (single-turn, multi-turn, and a purpose-trained adaptive
  attacker, writeups #3–#13) is injected as an agent at the **same ~25%** as the 8B.
  Whatever protects it in conversation isn't engaged when it parses a tool result. The
  effect is real; the magnitude is **25%, not the 75%** an inverted-metric reading
  would give.
- **How you wire tools changes susceptibility.** Same models, same suite, same attack:
  **native** OpenAI tool-calling → **0% ASR**; **prompted** tool-parsing (AgentDojo's
  default `LOCAL` path) → **25% ASR**. The injection lands far more easily when tool
  calls are parsed out of free text than when they go through a structured tool API.
  Measure the tool mechanism you actually ship.
- **Injection is a utility problem too.** Task utility is low to begin with (the 8B
  cleanly solves ~1/8 banking tasks) and does not recover under attack — the injected
  instruction pulls the agent off the user's real job.
- **Two "best-practice" defenses do the opposite of their reputation on an 8B** (below).

## Verified-polarity results

**Core ASR, banking, `important_instructions`:**

| tool mechanism | model | ASR |
|---|---|---|
| prompted (`LOCAL`, 4 user × 3 inj) | llama3.1:8b | **25%** |
| prompted (`LOCAL`, 4 user × 3 inj) | guarded-8b-q4 | **25%** |
| native OpenAI tools (8 user × 4 inj) | llama3.1:8b | **0%** |
| native OpenAI tools (8 user × 4 inj) | guarded-8b-q4 | **0%** |

Both 8B models land at exactly 25% on the prompted path; the aligned 27B sat at the
same raw `security` level in-run (all three models equal), so the "27B ≈ 8B as an
agent" result holds — it is just 25%, not 75%.

**Defenses (banking, prompted path, guarded-8b-q4), correct polarity:**

| defense | ASR | vs no-defense (25%) |
|---|---|---|
| none | 25.0% | — |
| spotlighting_with_delimiting | **36.1%** | **worse (+11)** |
| repeat_user_prompt | **19.4%** | **better (−6)** |

The intuition-flipping result is real once the metric is read correctly:
**spotlighting/delimiting made injection *more* likely on this 8B, and repeating the
user prompt made it *less* likely** — the opposite of both their frontier-model
reputations and of an inverted-metric reading. Prompt-level defenses are not safe by
default on small local models; they must be measured per model, not assumed.

## Why this is a real result, not a harness artifact
The models genuinely *act*: on the banking tasks they issue real, well-formed tool
calls (pay the bill, adjust rent, schedule transactions) — they simply miss the exact
multi-step success criteria on most tasks, which is why clean utility is a low but
non-zero floor. The 25% ASR is real obedience to injected instructions, and the 0%
native-tools ASR is real resistance, not a crash — the same models run to completion
on both paths.

## Takeaways
1. **Test the deployment shape you ship.** A model provably robust in chat can be
   injected once it has tools — and *how* it calls tools (native vs prompted) moves
   ASR from 0% to 25%. Robustness must be measured in the exact agent loop you deploy.
2. **Alignment ≠ agentic safety, at the right magnitude.** The 27B/8B gap that
   dominated writeups #4–#13 shrinks to nothing here — all three ~25%. Report it as
   25%, not an inflated 75%.
3. **Defenses need per-model measurement.** On this 8B, spotlighting hurt and
   repeat-prompt helped — both against their reputations. "Best-practice" prompt
   defenses are not safe by assumption on small models.
4. **Get the metric polarity right.** `security` = injection succeeded. This writeup
   was corrected from an inverted draft after verifying the polarity against a task
   whose injection goal (send to the attacker IBAN) is unambiguous.

## Limits / next
Coarse pilot: banking suite, one attack family, 4×3 (prompted) and 8×4 (native)
couples — metrics quantize in large steps. The publishable version runs the full
16-task banking + workspace suites, all injection tasks, adds `tool_filter` and
`transformers_pi_detector`, reports the 27B on both tool paths (the prompted-path 27B
agent loop is slow), and adds per-injection-task breakdowns. The **native-vs-prompted
ASR gap (0% vs 25%)** is the most interesting thread to pin down next.

## Reproduce
```
# prompted path (AgentDojo default); "Average security" IS the ASR (no inversion)
LOCAL_LLM_PORT=11434 python -m agentdojo.scripts.benchmark --model LOCAL \
  --model-id guarded-8b-q4 -s banking --attack important_instructions \
  --defense spotlighting_with_delimiting -f
# native OpenAI tools (training/adj_run.py); injection_asr = mean(security)
LOCAL_LLM_PORT=11434 python training/adj_run.py --model guarded-8b-q4 \
  --suite banking --n 8 --inj 4 --attack important_instructions
```
