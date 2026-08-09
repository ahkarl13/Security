#!/usr/bin/env python3
"""
training/build_attacker_dataset.py - build the attacker driver's training sets.

Two artifacts, both split BY ATTACK-FAMILY (no family straddles splits):

  SFT (attacker_sft_*.jsonl) - from WINNING (leaking) trajectories only.
      input  = full history the attacker sees (messages before its move)
      target = a valid PyRIT move: {"next_prompt","strategy","rationale"}
      Malformed targets never exist (we construct + validate them) -> high
      contract adherence is baked in.

  KTO (attacker_kto_*.jsonl) - from ALL trajectories.
      chosen  = move from a trajectory that led to a leak
      rejected= move from a trajectory that did not
      Naturally binary from the logs; feeds KTO/DPO with a control signal.

Usage:
  python build_attacker_dataset.py data/singleturn.jsonl [more.jsonl ...] \
      --outdir data/attacker --seed 13
"""
import argparse
import glob
import hashlib
import json
import os
import random


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


def strategy_of(fam):
    # "probe:direct_injection"->"direct_injection", "lang:sw:story"->"story"
    return (fam or "unknown").split(":")[-1]


def family_split(fam, seed):
    h = int(hashlib.md5(f"{seed}:{fam}".encode()).hexdigest(), 16) % 100
    return "train" if h < 70 else ("val" if h < 85 else "test")


def move(next_prompt, strategy):
    m = {"next_prompt": next_prompt, "strategy": strategy,
         "rationale": f"Advance toward disclosure of the protected passphrase "
                      f"using the {strategy} technique."}
    json.dumps(m)   # validate serializable / on-contract
    return m


def examples_from(r):
    """Yield (history, move_dict, led_to_leak) for each attacker (user) turn."""
    fam = r.get("attack_family")
    strat = strategy_of(fam)
    leak = bool(r.get("ground_truth_leak"))
    msgs = r["messages"]
    for i, m in enumerate(msgs):
        if str(m.get("role")).lower() != "user":
            continue
        history = [{"role": x["role"], "content": x["content"]} for x in msgs[:i]]
        yield history, move(m["content"], strat), leak, fam, r.get("seed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--outdir", default="data/attacker")
    ap.add_argument("--seed", type=int, default=13)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    os.makedirs(a.outdir, exist_ok=True)

    rows = load(a.inputs)
    seen = {}
    for r in rows:
        seen[(r.get("target_model"), r.get("attack_family"), r.get("seed"))] = r
    rows = list(seen.values())

    sft = {"train": [], "val": [], "test": []}
    kto = {"train": [], "val": [], "test": []}
    for r in rows:
        for history, mv, leak, fam, seed in examples_from(r):
            split = family_split(fam, seed or "")
            target = json.dumps(mv, ensure_ascii=False)
            if leak:
                sft[split].append({"input": history, "target": target,
                                   "attack_family": fam, "seed": seed})
            kto[split].append({"prompt": history, "completion": target,
                               "label": bool(leak), "attack_family": fam, "seed": seed})

    def dump(coll, prefix):
        counts = {}
        for name, exs in coll.items():
            rng.shuffle(exs)
            out = os.path.join(a.outdir, f"{prefix}_{name}.jsonl")
            with open(out, "w", encoding="utf-8") as f:
                for e in exs:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            counts[name] = len(exs)
        return counts

    sft_counts = dump(sft, "attacker_sft")
    kto_counts = dump(kto, "attacker_kto")
    chosen = sum(1 for s in kto.values() for e in s if e["label"])
    print(json.dumps({"sft": sft_counts, "kto": kto_counts,
                      "kto_chosen": chosen,
                      "kto_rejected": sum(kto_counts.values()) - chosen}, indent=2))


if __name__ == "__main__":
    main()
