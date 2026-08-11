#!/usr/bin/env python3
"""
build_dpo.py - preference pairs for DPO from the SFT analyst set.
chosen = the correct analyst target; rejected = the same target with the OWASP category
swapped to a plausible WRONG one. Teaches "prefer the correct category over a hallucinated
one" (the failure RAG alone can't fully fix). Conversational DPO format.

  python build_dpo.py ..\data\llmsec\llmsec_sft_train.jsonl --out dpo_train.jsonl
"""
import argparse
import json
import re

# plausible wrong category per correct one (2025 ids)
WRONG = {
    "LLM01": ("LLM05", "Improper Output Handling"),
    "LLM07": ("LLM01", "Prompt Injection"),
    "LLM02": ("LLM09", "Misinformation"),
}
DEFAULT_WRONG = ("LLM05", "Improper Output Handling")


def corrupt(target, cat):
    wr, wt = WRONG.get(cat, DEFAULT_WRONG)
    # rewrite the leading "OWASP category: <cat> <title>" up to the "(" or newline
    new = re.sub(r"OWASP category:\s*" + re.escape(cat) + r"\s+[^(\n]+",
                 f"OWASP category: {wr} {wt} ", target, count=1)
    return new if new != target else target.replace(cat, wr, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sft")
    ap.add_argument("--out", default="dpo_train.jsonl")
    a = ap.parse_args()
    n = skipped = 0
    with open(a.out, "w", encoding="utf-8") as f:
        for line in open(a.sft, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            msgs = r["messages"]
            cat = r.get("category")
            correct = msgs[2]["content"]
            rej = corrupt(correct, cat)
            if rej == correct:
                skipped += 1
                continue
            f.write(json.dumps({
                "prompt": [msgs[0], msgs[1]],
                "chosen": [{"role": "assistant", "content": correct}],
                "rejected": [{"role": "assistant", "content": rej}],
            }, ensure_ascii=False) + "\n")
            n += 1
    print(json.dumps({"dpo_pairs": n, "skipped_no_change": skipped, "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
