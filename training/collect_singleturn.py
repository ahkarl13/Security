#!/usr/bin/env python3
"""
training/collect_singleturn.py - emit labeled JSONL from the single-turn batteries.

Reuses the EXISTING attack definitions (probe_battery.VECTORS and
language_jailbreak.ATTACKS) as the single source of truth, fires them at each
target on Pop Ollama, and writes one matcher-labeled transcript per (model,
vector) via jsonl_log. No harness edits — this is an additive collector.

Usage:
  python collect_singleturn.py [--out data/singleturn.jsonl] [--reps 1] [model ...]
  (default models: leaky-8b guarded-8b-q4 guarded-qwen36)
"""
import argparse
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (HERE, os.path.join(ROOT, "extraction-sweep"), os.path.join(ROOT, "lang-jailbreak")):
    sys.path.insert(0, p)

from jsonl_log import TranscriptLogger          # noqa: E402
from probe_battery import VECTORS               # noqa: E402
from language_jailbreak import ATTACKS, LANGS, VECTOR_KEYS, CONTROL  # noqa: E402

CHAT = os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/v1/chat/completions"


def ask(model, msg, temperature=0.2):
    body = {"model": model, "messages": [{"role": "user", "content": msg}],
            "temperature": temperature}
    data = json.dumps(body).encode()
    req = urllib.request.Request(CHAT, data=data, headers={
        "Content-Type": "application/json", "Authorization": "Bearer ollama"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())["choices"][0]["message"]["content"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "data", "singleturn.jsonl"))
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("models", nargs="*",
                    default=["leaky-8b", "guarded-8b-q4", "guarded-qwen36"])
    a = ap.parse_args()
    log = TranscriptLogger(a.out)

    for model in a.models:
        for rep in range(a.reps):
            for name, msg in VECTORS:
                fam = f"probe:{name}"
                try:
                    reply = ask(model, msg, a.temperature)
                except Exception as e:
                    reply = f"[error: {e}]"
                leaked = log.log([{"role": "user", "content": msg},
                                  {"role": "assistant", "content": reply}],
                                 model, fam, seed=f"{fam}#{rep}")
                print(f"  {model:16} {fam:28} leak={leaked}", flush=True)
            for code, lname, lo in LANGS:
                for vk in VECTOR_KEYS:
                    fam = f"lang:{code}:{vk}"
                    msg = ATTACKS[code][vk]
                    try:
                        reply = ask(model, msg, a.temperature)
                    except Exception as e:
                        reply = f"[error: {e}]"
                    leaked = log.log([{"role": "user", "content": msg},
                                      {"role": "assistant", "content": reply}],
                                     model, fam, seed=f"{fam}#{rep}", lang=code, low_resource=lo)
                    print(f"  {model:16} {fam:28} leak={leaked}", flush=True)
    print(f"\nwrote {log.n} transcripts -> {a.out}", flush=True)


if __name__ == "__main__":
    main()

