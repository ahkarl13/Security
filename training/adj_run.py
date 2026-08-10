#!/usr/bin/env python3
"""
adj_run.py - AgentDojo runner using NATIVE OpenAI tool-calling against Ollama.

The CLI --model LOCAL path uses prompted tool-parsing (LocalLLM), which tanks
utility on small models. Ollama's /v1 supports native OpenAI tools, so we build the
pipeline with OpenAILLM directly (exact model id, defenses compose on top).

Reports, per (model, defense): utility_baseline (no attack), utility_under_attack,
and injection_asr (AgentDojo security=True means the injection goal executed).
"""
import argparse, json, os
import openai
from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig, OpenAILLM
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.benchmark import (benchmark_suite_with_injections,
                                 benchmark_suite_without_injections)
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.logging import OutputLogger


def avg(d):
    v = list(d.values())
    return round(sum(1 for x in v if x) / len(v), 4) if v else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--defense", default=None)
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--n", type=int, default=5, help="# user tasks")
    ap.add_argument("--inj", type=int, default=2, help="# injection tasks")
    ap.add_argument("--port", default=os.getenv("LOCAL_LLM_PORT", "11434"))
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    client = openai.OpenAI(base_url=f"http://localhost:{a.port}/v1", api_key="EMPTY")
    llm = OpenAILLM(client, a.model)
    cfg = PipelineConfig(llm=llm, model_id=None, defense=a.defense,
                         system_message_name=None, system_message=None)
    pipeline = AgentPipeline.from_config(cfg)
    # the attack resolver matches a MODEL_NAMES *key* as a substring of pipeline.name;
    # "local" -> "Local model". Real model id is recorded in the output dict.
    pipeline.name = "local"

    suite = get_suites("v1")[a.suite]
    uts = list(suite.user_tasks.keys())[:a.n]
    its = list(suite.injection_tasks.keys())[:a.inj]

    with OutputLogger("./runs_adn", live=None):
        base = benchmark_suite_without_injections(pipeline, suite, logdir=None,
                                                  force_rerun=True, user_tasks=uts)
        attack = load_attack(a.attack, suite, pipeline)
        atk = benchmark_suite_with_injections(pipeline, suite, attack, logdir=None,
                                              force_rerun=True, user_tasks=uts,
                                              injection_tasks=its)
    out = {"model": a.model, "suite": a.suite, "defense": a.defense,
           "attack": a.attack, "n_user": len(uts), "n_inj": len(its),
           "utility_baseline": avg(base["utility_results"]),
           "utility_under_attack": avg(atk["utility_results"]),
           "injection_asr": avg(atk["security_results"])}
    print("ADJ_RESULT " + json.dumps(out))
    if a.out:
        open(a.out, "a", encoding="utf-8").write(json.dumps(out) + "\n")


if __name__ == "__main__":
    main()
