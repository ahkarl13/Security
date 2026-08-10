# Writeup #15 — Which Prompt-Injection Defenses Actually Hold on the Deploy-Quant 8B

**Class:** agentic defense evaluation (blue-team). Follow-up to #14: you've shown a
tool-using local agent gets injected ~16% of the time (`important_instructions`,
AgentDojo banking). This writeup asks the question a defender actually pays for —
**which bolt-on defense should I ship, and does it hold on the quant I deploy?**

## TL;DR
Target = `guarded-8b-q4` (the deploy quant), full 16-task banking suite × all 9
injection tasks (144 couples/config), prompted-tool path, `important_instructions`
attack. `security` = injection succeeded = ASR (verified polarity, see #14). Lower is
safer.

| defense | ASR | Δ vs none | clean-task utility | verdict |
|---|---|---|---|---|
| none | **15.97%** | — | 38.19% (under attack) | baseline |
| repeat_user_prompt | **9.03%** | **−6.9 (−43%)** | 37.50% | **best — helps most, cheapest** |
| spotlighting_with_delimiting | **10.42%** | **−5.5 (−35%)** | 36.11% | helps, small utility cost |
| transformers_pi_detector | — | did not complete | — | detector model unavailable offline |
| tool_filter | n/a | — | — | **OpenAI-API only — unsupported for local** |

- **Two prompt-level defenses genuinely help** on the deploy quant: repeating the user's
  instruction after tool output cut ASR **43%** (16.0→9.0), and spotlighting/delimiting
  the untrusted region cut it **35%** (16.0→10.4). Neither is a fix — a 9–10% residual
  ASR is still a shipped vulnerability — but both roughly halve exposure for one line of
  system-prompt change.
- **`repeat_user_prompt` does not backfire here.** An earlier hypothesis (from a noisy
  4-task sample) was that re-injecting the user prompt gives the model another chance to
  conflate the attacker's "important instructions" with a real directive. On the **full
  suite it is the *best* defense** — the small-sample reading was an artifact. Agentic
  ASR is coarse at low task counts; trust the full suite.
- **`transformers_pi_detector` didn't run** — it needs an external HuggingFace detector
  (`protectai/deberta-v3-base-prompt-injection-v2`) that wasn't available in the offline
  homelab run, so it produced no score. A model-based input filter is worth testing, but
  it adds a dependency and a second model to the serving path.
- **`tool_filter` cannot be evaluated on a local model.** AgentDojo's `tool_filter`
  requires an `OpenAILLM` client (it pre-screens which tools to expose via an OpenAI
  call); the local/prompted `LOCAL` path uses a different wrapper, so `from_config`
  raises *"Tool filter is only supported for OpenAI models."* On the **native**-tools
  path (writeup #14's runner, which is an `OpenAILLM` pointed at Ollama) `tool_filter`
  *is* constructible — but native tools already sat at ~0% ASR, so there's nothing for
  it to filter. It's a frontier-API defense, not a local-serving one.

## The utility tax
Both working defenses cost a little competence: clean-attack utility 38.19% → 37.50%
(repeat) / 36.11% (spotlighting). So the ranking is clean — **`repeat_user_prompt`
wins on both axes** (lowest ASR *and* highest retained utility), with spotlighting a
close second. Neither defense restored utility to the clean-no-attack ceiling (43.75%):
a defended agent under attack is safer but still does its real job worse.

## What a defender should take from this
1. **Ship `repeat_user_prompt` (or spotlighting) as a cheap first layer** — ~40% ASR
   reduction for a prompt-template change, no extra model. But treat the residual ~9%
   as real: bolt-on prompt defenses halve, they don't close.
2. **Don't trust a defense you measured on a handful of tasks.** The spotlighting-hurts
   / repeat-backfires reading came from a 4-task sample and inverted on the full suite.
   Evaluate defenses on the whole suite, both because ASR quantizes coarsely and because
   which tasks you sample changes the answer.
3. **Match the defense to your serving path.** `tool_filter` and detector-model filters
   assume a frontier-API or an extra served model; on a bare local 8B the only free
   levers are prompt-level (repeat / spotlight). Know which layer you can actually
   deploy before you plan around it.
4. **Defense ≠ robustness.** The base and guarded 8B are identical without a defense
   (#14), and even the best defense here leaves ~9% ASR. For a real agent you'd stack
   this with output-side action controls (allow-lists on `send_money` recipients,
   confirmation gates), not rely on prompt defenses alone.

## Limits / next
One target quant, one suite, one attack family; `pi_detector` and native-path
`tool_filter` still to run; utility deltas are within a few coarse-quantized points.
Next: repeat the bake-off on the workspace suite and under `tool_knowledge` /
`injecagent`; get the detector model loaded to complete the input-filter row; and test
an output-side recipient allow-list as the non-prompt defense that should actually
close the `send_money` exfil path.

## Reproduce
```
# each row (full banking, prompted path); "Average security" printed IS the ASR
LOCAL_LLM_PORT=11434 python -m agentdojo.scripts.benchmark --model LOCAL \
  --model-id guarded-8b-q4 --suite banking --attack important_instructions \
  --defense repeat_user_prompt -f
# swap --defense for spotlighting_with_delimiting / transformers_pi_detector;
# omit --defense for the baseline, omit --attack for the clean-utility ceiling.
```
