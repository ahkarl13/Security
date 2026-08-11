#!/usr/bin/env python3
"""
build_dpo_v2.py - REWORKED DPO preference pairs (fixes the v1 negative result).

v1 bug: the corpus is only two gold classes (LLM01 x911, LLM07 x240) and v1's reject map
set WRONG[LLM07]=LLM01, so the 240 LLM07 pairs trained the model to DISPREFER LLM01 - the
correct answer 79% of the time. DPO net-suppressed the majority class -> in-domain
category_acc fell 1.0 -> 0.70. That was a reject-mining bug, not a DPO failure.

v2 fixes it two ways:
  (1) BALANCED near-miss pairs for the real LLM01<->LLM07 boundary: all 240 LLM07 rows
      (reject=LLM01) + 240 sampled LLM01 rows (reject=LLM07) = 480 pairs whose cross-class
      demotion nets to ZERO, so neither real class is suppressed.
  (2) OFF-DISTRIBUTION rejects for the remaining LLM01 rows: reject id is drawn (rotating)
      from OWASP-LLM ids that NEVER appear as gold here -> reinforces "prefer the correct id
      over a hallucinated one" without ever demoting a real label.

Only the leading "OWASP category: <id> <title>" line differs between chosen and rejected,
so the gradient lands on category discrimination, not format.

  python build_dpo_v2.py ..\data\llmsec\llmsec_sft_train.jsonl --out dpo_train_v2.jsonl
"""
import argparse
import json
import random
import re

# OWASP-LLM 2025 ids that are NOT gold in this corpus (safe to use as rejects)
OFFDIST = [
    ("LLM05", "Improper Output Handling"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM06", "Excessive Agency"),
    ("LLM09", "Misinformation"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM10", "Unbounded Consumption"),
    ("LLM03", "Supply Chain"),
    ("LLM08", "Vector and Embedding Weaknesses"),
]

CAT_RE = re.compile(r"OWASP category:\s*(LLM\d+)\s+([^(\n]+)")


def title_map(rows):
    """id -> canonical title, harvested from the corpus targets."""
    m = {}
    for r in rows:
        t = r["messages"][2]["content"]
        mt = CAT_RE.search(t)
        if mt:
            m.setdefault(mt.group(1), mt.group(2).strip())
    return m


def swap_cat(target, cat, new_id, new_title):
    new = re.sub(r"OWASP category:\s*" + re.escape(cat) + r"\s+[^(\n]+",
                 f"OWASP category: {new_id} {new_title} ", target, count=1)
    return new if new != target else target.replace(cat, new_id, 1)


def make_pair(msgs, correct, rej):
    return {"prompt": [msgs[0], msgs[1]],
            "chosen": [{"role": "assistant", "content": correct}],
            "rejected": [{"role": "assistant", "content": rej}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sft")
    ap.add_argument("--out", default="dpo_train_v2.jsonl")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.sft, encoding="utf-8") if l.strip()]
    titles = title_map(rows)
    L01 = titles.get("LLM01", "Prompt Injection")
    L07 = titles.get("LLM07", "System Prompt Leakage")

    llm01 = [r for r in rows if r.get("category") == "LLM01"]
    llm07 = [r for r in rows if r.get("category") == "LLM07"]
    rng = random.Random(a.seed)
    rng.shuffle(llm01)

    n_bal = min(len(llm07), len(llm01))          # balanced near-miss count per direction
    bal_01 = llm01[:n_bal]                        # LLM01 rows -> reject LLM07
    rest_01 = llm01[n_bal:]                       # remaining LLM01 rows -> off-distribution reject

    out = []
    # (1) balanced hard pairs: LLM07 -> reject LLM01, and n_bal LLM01 -> reject LLM07
    for r in llm07:
        c = r["messages"][2]["content"]
        out.append(make_pair(r["messages"], c, swap_cat(c, "LLM07", "LLM01", L01)))
    for r in bal_01:
        c = r["messages"][2]["content"]
        out.append(make_pair(r["messages"], c, swap_cat(c, "LLM01", "LLM07", L07)))
    n_hard = len(out)
    # (2) off-distribution rejects for the remaining LLM01 rows (rotating, spread evenly)
    for i, r in enumerate(rest_01):
        c = r["messages"][2]["content"]
        oid, otitle = OFFDIST[i % len(OFFDIST)]
        out.append(make_pair(r["messages"], c, swap_cat(c, "LLM01", oid, otitle)))

    rng.shuffle(out)
    with open(a.out, "w", encoding="utf-8") as f:
        for p in out:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
    print(json.dumps({"total": len(out), "balanced_hard_pairs": n_hard,
                      "offdist_pairs": len(rest_01),
                      "llm01": len(llm01), "llm07": len(llm07),
                      "titles": {"LLM01": L01, "LLM07": L07}, "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
