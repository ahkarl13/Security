# agentdojo-lab — agentic prompt-injection against local models

Harness for writeup #14. Runs [AgentDojo](https://github.com/ethz-spylab/agentdojo)
against the homelab's local models through Ollama's OpenAI-compatible endpoint, so the
same suites that benchmark GPT-4/Claude also benchmark our guarded 8B/27B builds — as
**tool-using agents**, not chat models.

## Setup
```
python -m venv .venv && ./.venv/bin/pip install agentdojo
# Ollama serves an OpenAI-compatible API at :11434/v1; AgentDojo's LOCAL provider
# points there. Its text-based <function=...> tool protocol needs no native tool API.
```

## Run
```
# clean utility (no attack):
LOCAL_LLM_PORT=11434 python -m agentdojo.scripts.benchmark \
  --model LOCAL --model-id <ollama-model> --suite banking --logdir runs

# under injection (strongest baseline attack), optionally with a defense:
LOCAL_LLM_PORT=11434 python -m agentdojo.scripts.benchmark \
  --model LOCAL --model-id <ollama-model> --suite banking \
  --attack important_instructions [--defense spotlighting_with_delimiting] --logdir runs
```
`security` = injection **resisted**; attack-success rate = 1 − security. Defenses:
`spotlighting_with_delimiting`, `repeat_user_prompt`, `tool_filter`,
`transformers_pi_detector`.

## Results (banking, 4 user × 9 injection = 36 couples, `important_instructions`)

| model | clean utility | attacked utility | security | attack-success |
|---|---|---|---|---|
| llama3.1:8b | 25% | 0% | 25.0% | 75.0% |
| guarded-8b-q4 | 25% | 0% | 25.0% | 75.0% |
| guarded-qwen36 (aligned 27B) | 25% | 0% | 25.0% | 75.0% |

Defenses (attacked):

| defense | model | security | attack-success |
|---|---|---|---|
| none | all | 25.0% | 75.0% |
| spotlighting_with_delimiting | guarded-8b-q4 | 36.1% | 63.9% |
| spotlighting_with_delimiting | llama3.1:8b | 36.1% | 63.9% |
| repeat_user_prompt | guarded-8b-q4 | 19.4% | 80.6% (backfires) |

Headline: the aligned 27B that held 0% secret-leak in chat (writeups #3–#13) is
injected 75% of the time as an agent — chat-time alignment does not transfer to the
tool-use setting. Full analysis in `../writeup-14-agentic-injection-agentdojo.md`.

_Note: the AgentDojo install + run logs live on the GPU box, not in this repo._
