#!/usr/bin/env python3
"""
training/build_judge_dataset.py - turn captured JSONL into a judge training set.

The matcher is authoritative on the leak axis, so the LABEL is deterministic
(1 = leak, 0 = safe). The neural head's value is the ambiguous band, so we also
export the two highest-value hand-audit buckets:
  * near-miss NEGATIVE : safe, but names the policy/secret (the FP bucket)
  * subtle  POSITIVE   : real leak via non-plaintext obfuscation (the FN bucket)

Pipeline: load -> dedup(attack_family, seed) -> split BY ATTACK-FAMILY (no family
straddles splits) -> balance leaks to a target ratio per split -> write.

Usage:
  python build_judge_dataset.py data/singleturn.jsonl [more.jsonl ...] \
      --outdir data/judge --ratio 3 --seed 13
"""
import argparse
import glob
import hashlib
import json
import os
import re
import random

NAMEDROP = re.compile(r"(override|passphrase|ACME|secret|admin)", re.I)


def load(paths):
    rows = []
    for pat in paths:
        for path in glob.glob(pat):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
    return rows


def render(messages):
    role = {"user": "User", "assistant": "Assistant", "system": "System"}
    return "\n\n".join(f"{role.get(m['role'], m['role']).upper()}: {m['content']}"
                       for m in messages)


def family_split(fam, seed):
    h = int(hashlib.md5(f"{seed}:{fam}".encode()).hexdigest(), 16) % 100
    return "train" if h < 70 else ("val" if h < 85 else "test")


def assistant_text(r):
    return " ".join(m["content"] for m in r["messages"]
                    if str(m.get("role")).lower() == "assistant")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--outdir", default="data/judge")
    ap.add_argument("--ratio", type=float, default=3.0,
                    help="max safe:leak ratio per split (downsample safe)")
    ap.add_argument("--seed", type=int, default=13)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    os.makedirs(a.outdir, exist_ok=True)

    rows = load(a.inputs)
    # dedup by (attack_family, seed) keeping the last occurrence
    seen = {}
    for r in rows:
        seen[(r.get("target_model"), r.get("attack_family"), r.get("seed"))] = r
    rows = list(seen.values())

    splits = {"train": [], "val": [], "test": []}
    audit = []
    for r in rows:
        fam = r.get("attack_family", "?")
        leak = bool(r.get("ground_truth_leak"))
        ex = {"text": render(r["messages"]), "label": int(leak),
              "attack_family": fam, "seed": r.get("seed"),
              "leaked_method": r.get("leaked_method"),
              "target_model": r.get("target_model")}
        splits[family_split(fam, r.get("seed") or "")].append(ex)
        if not leak and NAMEDROP.search(assistant_text(r)):
            audit.append({**ex, "bucket": "near_miss_negative"})
        if leak and r.get("leaked_method") not in (None, "plaintext"):
            audit.append({**ex, "bucket": "subtle_positive"})

    summary = {}
    for name, exs in splits.items():
        leaks = [e for e in exs if e["label"] == 1]
        safe = [e for e in exs if e["label"] == 0]
        keep_safe = int(min(len(safe), max(1, round(len(leaks) * a.ratio)))) if leaks else len(safe)
        rng.shuffle(safe)
        balanced = leaks + safe[:keep_safe]
        rng.shuffle(balanced)
        out = os.path.join(a.outdir, f"judge_{name}.jsonl")
        with open(out, "w", encoding="utf-8") as f:
            for e in balanced:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        summary[name] = {"total": len(balanced), "leak": len(leaks),
                         "safe_kept": min(len(safe), keep_safe)}

    with open(os.path.join(a.outdir, "judge_to_audit.jsonl"), "w", encoding="utf-8") as f:
        for e in audit:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    print(json.dumps({"splits": summary, "audit_cases": len(audit),
                      "families": len({r.get('attack_family') for r in rows})}, indent=2))


if __name__ == "__main__":
    main()
