#!/usr/bin/env python3
"""
practice/distill.py - turn ONE captured practice session into training signal.

The flywheel: each authorized lab session -> (a) a Vul-RAG-style KB item for rag/items.jsonl
and (b) a defensively-framed SFT analyst pair for the SFT set. Output shapes MATCH the
existing corpora exactly (see ../rag/items.jsonl and ../data/llmsec/llmsec_sft_train.jsonl),
so distilled rows drop straight into build_index.py / the SFT set.

  python distill.py sessions/portswigger-web-llm-01.json
  python distill.py sessions/portswigger-web-llm-01.json --out out/

A capture file is JSON (see sessions/_template.json):
  {
    "id": "portswigger::web-llm::exploit-apis-excessive-agency",
    "platform": "PortSwigger Web Security Academy",
    "lab": "Exploiting LLM APIs with excessive agency",
    "technique": "Excessive agency via chained LLM tool call",
    "category": "LLM06", "category_title": "Excessive Agency",
    "root_cause": "...", "fix_pattern": "...", "detection_hint": "...",
    "interaction": {"user": "USER: ...\\nASSISTANT: ...", "outcome": "SUCCEEDED - ..."},
    "owasp_2026": null, "multi_turn": false
  }
"""
from __future__ import annotations
import argparse
import json
import pathlib

SFT_SYS = ("You are a security analyst specializing in LLM application security. You review "
           "an interaction between a user and an AI assistant and assess it against the OWASP "
           "Top 10 for LLM Applications (2025; you also note the provisional 2026 renames where "
           "relevant). For each interaction you identify the attack technique, whether it "
           "succeeded and why, the root cause, the fix, and what to look for. You are a "
           "defender: you analyze attacks only to harden the system and never help carry one out.")


def to_kb_item(cap: dict) -> dict:
    tech = cap["technique"]
    return {
        "id": cap["id"],
        "technique": tech,
        "functional_semantics": cap.get("functional_semantics", tech),
        "root_cause": cap["root_cause"],
        "fix_pattern": cap["fix_pattern"],
        "category": cap["category"],
        "category_title": cap.get("category_title", ""),
        "owasp_2026": cap.get("owasp_2026"),
        "detection_hint": cap.get("detection_hint", ""),
        "multi_turn": bool(cap.get("multi_turn", False)),
        "example_user_turn": cap.get("interaction", {}).get("user", ""),
        "source": f"practice:{cap.get('platform','')}:{cap.get('lab','')}",
        "license": "own-practice",
    }


def to_sft_pair(cap: dict) -> dict:
    inter = cap.get("interaction", {})
    user = (inter.get("user", "").rstrip()
            + "\n\nAnalyze this interaction against the OWASP LLM Top 10 (2025).")
    title = cap.get("category_title", "")
    assistant = (
        f"OWASP category: {cap['category']} {title} (OWASP-LLM 2025)\n"
        f"Technique: {cap['technique']}\n"
        f"Outcome: {inter.get('outcome','')}\n"
        f"Root cause: {cap['root_cause']}\n"
        f"Fix: {cap['fix_pattern']}\n"
        f"What to look for: {cap.get('detection_hint','')}"
    )
    return {
        "messages": [
            {"role": "system", "content": SFT_SYS},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "attack_family": cap.get("attack_family", cap["category"].lower()),
        "technique": cap["technique"],
        "category": cap["category"],
        "source": "own-practice",
        "license": "own-practice",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    cap = json.loads(pathlib.Path(a.capture).read_text(encoding="utf-8"))
    outdir = pathlib.Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    kb, sft = to_kb_item(cap), to_sft_pair(cap)
    (outdir / "kb_items.jsonl").open("a", encoding="utf-8").write(json.dumps(kb, ensure_ascii=False) + "\n")
    (outdir / "sft_pairs.jsonl").open("a", encoding="utf-8").write(json.dumps(sft, ensure_ascii=False) + "\n")
    print(f"[distill] {cap['id']} -> {outdir}/kb_items.jsonl + sft_pairs.jsonl")
    print("  KB item category:", kb["category"], kb["category_title"])
    print("  next: append kb_items to ../rag/items.jsonl and rebuild the index; add sft_pairs to the SFT set")


if __name__ == "__main__":
    main()
