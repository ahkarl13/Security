# Writeup #14 — Alignment That Held in Chat Collapses in an Agent: Local Models on AgentDojo

**Class:** agentic prompt injection (OWASP LLM01 in a tool-using context). First
writeup in this repo that moves off single-model chat leaks and onto **agents that
call tools** — the 2025 risk surface. Uses AgentDojo (ETH SPY Lab, NeurIPS'24)
pointed at the homelab's local models through Ollama.

## TL;DR
Every prior writeup measured a model *answering*. This one measures a model *acting* —
reading a tool result / document that carries an injected instruction and deciding
whether to obey it. Result on the AgentDojo `banking` suite (4 user tasks ×
9 injection tasks = 36 couples, `important_instructions` attack, matcher = AgentDojo's
own task checkers):

| model | clean task utility | utility under attack | attack-success rate |
|---|---|---|---|
| llama3.1:8b | 25% | **0%** | **75%** |
| guarded-8b-q4 | 25% | **0%** | **75%** |
| **guarded-qwen36 (aligned 27B)** | 25% | **0%** | **75%** |

- **The aligned 27B's robustness does not transfer to the agentic setting.** In
  writeups #3–#13 `guarded-qwen36` held **0%** secret-leak against every chat attack,
  single- and multi-turn, including a purpose-trained adaptive attacker. As a
  tool-using agent it is injected **75% of the time — identical to the 8B.**
  Chat-time alignment is not agentic safety.
- **Injection doesn't just leak — it hijacks.** Task utility collapses from 25% to
  **0%** under attack: the injected instruction pulls the agent off the user's real
  task entirely, not merely alongside it.
- **Defenses are weak and one backfires** (see below).

## Why this is a real result, not a harness artifact
The uniform 25% clean utility looked suspicious, so I read the transcripts. The models
genuinely *act*: on the four banking tasks the 27B issues 3–4 real tool calls each
with no errors (pays the bill, adjusts rent, schedules transactions) — it simply fails
the precise multi-step success criteria on 3 of 4. So 25% is a real capability floor
(local agents solve 1 of these 4 tasks cleanly), and the 0%/75%-under-attack numbers
are real behavior, not crashes. The injection lands *because the model is competent
enough to follow instructions* — including the attacker's.

## Defenses (attacked case, `guarded-8b-q4` unless noted)

| defense | attack resisted (security) | attack-success | vs no-defense |
|---|---|---|---|
| none | 25.0% | 75.0% | — |
| spotlighting_with_delimiting | 36.1% | 63.9% | **helps (modest)** |
| spotlighting_with_delimiting (llama3.1:8b) | 36.1% | 63.9% | helps (modest) |
| repeat_user_prompt | 19.4% | 80.6% | **backfires** |

- **Spotlighting / delimiting** (mark the untrusted data region so the model treats it
  as data, not instructions) is the only defense that helped — and only from 75% to
  64% ASR. It did **not** restore any task utility (still 0%): a spotlighted agent
  resists a bit more but still can't do the job under attack.
- **Repeat-the-user-prompt** made it *worse* (75% → 81% ASR). Re-injecting the user's
  instruction after the tool output gives the model one more chance to conflate the
  attacker's injected "important instructions" with a real user directive. A defense
  that helps frontier models can be net-negative on an 8B — measure, don't assume.

## Takeaways
1. **Test the deployment shape you ship.** A model that is provably robust in chat can
   be trivially injected the moment you give it tools. Robustness must be measured in
   the agent loop, not inferred from chat evals.
2. **Alignment ≠ agentic safety.** The 27B/8B gap that dominated writeups #4–#13
   vanishes here — all three sit at 75% ASR. Whatever protects the 27B in conversation
   isn't engaged when it's parsing a tool result.
3. **Injection is a utility problem too.** ASR is only half the story; utility → 0
   means the attack is also a denial-of-service on the agent's real job.
4. **Defenses need per-model measurement.** Spotlighting helped a little; repeat-prompt
   backfired. On small local models, "best-practice" prompt defenses are not safe by
   default.

## Limits / next
4 of the 16 banking user tasks, one suite, one attack family — enough to establish the
qualitative result but coarse (metrics quantize in 1/36 steps). The publishable version
re-runs the full 16-task suite across `banking` + `workspace`, adds the `tool_filter`
and `transformers_pi_detector` defenses, and reports per-injection-task breakdowns.

## Reproduce
AgentDojo talks to Ollama via its OpenAI-compatible endpoint — no code changes:
```
pip install agentdojo
LOCAL_LLM_PORT=11434 python -m agentdojo.scripts.benchmark \
  --model LOCAL --model-id guarded-qwen36 \
  --suite banking --attack important_instructions \
  --defense spotlighting_with_delimiting --logdir runs
```
`security` in AgentDojo means the injection was **resisted**; attack-success = 1 −
security. Utility with no `--attack` is the clean task-completion baseline.
