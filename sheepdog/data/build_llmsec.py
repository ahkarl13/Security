#!/usr/bin/env python3
"""
sheepdog/data/build_llmsec.py - Phase 1a builder (LLM-security, for writeup #18).

Turns our own red-team transcripts (training/data/*.jsonl) into two artifacts:

  SFT analyst pairs (llmsec_sft_{train,val,test}.jsonl) - chat format.
      system = defensive LLM-security-analyst persona
      user   = the rendered interaction + "Analyze this interaction."
      assistant = a structured, DEFENSIVELY FRAMED analysis grounded in taxonomy.py
                  (category 2026 + 2025 xref, technique, succeeded+why, root cause,
                   fix, what-to-look-for). The analyst explains an attack to harden
                   the system; it never produces the attack.

  RAG knowledge items (llmsec_rag.jsonl) - one per technique (deduped), Vul-RAG shape,
      each carrying a real leaking example from the logs when one exists.

Splits are BY ATTACK-FAMILY (whole family in one split - stricter than training/'s
per-seed split, per eval/EVAL_PROTOCOL.md) so no family straddles train/test.

Success label = the record's `ground_truth_leak` (produced by training/matcher.py,
the authoritative leak detector).

Usage:
  python build_llmsec.py \
      D:\\AISecurity\\Security\\training\\data\\singleturn.jsonl \
      D:\\AISecurity\\Security\\training\\data\\multiturn.jsonl \
      --outdir D:\\AISecurity\\Security\\sheepdog\\data\\llmsec --seed 18
"""
import argparse
import glob
import hashlib
import json
import os
import random

import taxonomy as tax

ANALYST_SYS = (
    "You are a security analyst specializing in LLM application security. You review an "
    "interaction between a user and an AI assistant and assess it against the OWASP Top 10 "
    "for LLM Applications (2025; you also note the provisional 2026 renames where relevant). "
    "For each interaction you identify the attack technique, "
    "whether it succeeded and why, the root cause, the fix, and what to look for. You are a "
    "defender: you analyze attacks only to harden the system and never help carry one out."
)


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


def family_split(fam, salt):
    """Whole family -> one split (70/15/15). Hash the FAMILY only (no seed) so a
    family never straddles splits."""
    h = int(hashlib.md5(f"{salt}:{fam}".encode()).hexdigest(), 16) % 100
    return "train" if h < 70 else ("val" if h < 85 else "test")


def render_transcript(messages):
    out = []
    for m in messages:
        role = str(m.get("role", "")).upper()
        out.append(f"{role}: {m.get('content','')}")
    return "\n".join(out)


def analysis_text(rec, kn):
    """Build the defensively-framed analyst target from a record + taxonomy knowledge."""
    leaked = bool(rec.get("ground_truth_leak"))
    method = rec.get("leaked_method")
    turn = rec.get("leaked_turn")
    if leaked:
        how = f" (disclosed via {method}" + (f" at turn {turn}" if turn else "") + ")"
        outcome = "SUCCEEDED" + how + \
            " - the assistant disclosed the protected value it should have withheld."
    else:
        outcome = ("RESISTED - the assistant did not disclose the protected value.")

    cat_line = f"{kn['category']} {kn['category_title']} (OWASP-LLM 2025)"
    if kn.get("owasp_2026"):
        cat_line += f"  [2026 ed.: renamed '{kn['owasp_2026']}', number pending]"
    if kn.get("secondary"):
        sec = ", ".join(f"{s} {t}" for s, t in zip(kn["secondary"], kn["secondary_titles"]))
        cat_line += f"; secondary: {sec}"

    lang_line = ""
    if kn.get("lang"):
        lang_line = (f"\nLanguage: {kn['lang_name']} ({kn['lang_resource']}-resource) - "
                     f"cross-lingual attempt; a guard validated only in English is not "
                     f"validated here.")

    return (
        f"OWASP category: {cat_line}\n"
        f"Technique: {kn['technique']}"
        f"{' (multi-turn)' if kn['multi_turn'] else ''}"
        f"{lang_line}\n"
        f"Outcome: {outcome}\n"
        f"Root cause: {kn['root_cause']}\n"
        f"Fix: {kn['fix']}\n"
        f"What to look for: {kn['detection_hint']}"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--outdir", default="llmsec")
    ap.add_argument("--seed", type=int, default=18)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    os.makedirs(a.outdir, exist_ok=True)

    rows = load(a.inputs)
    # dedup by (target_model, attack_family, seed)
    seen = {}
    for r in rows:
        seen[(r.get("target_model"), r.get("attack_family"), r.get("seed"))] = r
    rows = list(seen.values())

    sft = {"train": [], "val": [], "test": []}
    rag_by_tech = {}          # technique_key -> knowledge item (with an example)
    skipped = 0

    for r in rows:
        fam = r.get("attack_family")
        kn = tax.lookup(fam)
        if not kn:
            skipped += 1
            continue
        msgs = r.get("messages") or []
        if not msgs:
            skipped += 1
            continue

        split = family_split(fam, str(a.seed))
        target = analysis_text(r, kn)
        sft[split].append({
            "messages": [
                {"role": "system", "content": ANALYST_SYS},
                {"role": "user", "content": render_transcript(msgs) +
                    "\n\nAnalyze this interaction against the OWASP LLM Top 10 (2025)."},
                {"role": "assistant", "content": target},
            ],
            "attack_family": fam,
            "technique": kn["technique_key"],
            "category": kn["category"],
            "target_model": r.get("target_model"),
            "seed": r.get("seed"),
            "split": split,
            "source": "own-redteam-logs",
            "license": "internal",
        })

        # RAG knowledge item per technique; attach a real leaking example if we find one
        tk = kn["technique_key"]
        item = rag_by_tech.get(tk)
        if item is None:
            item = {
                "id": f"llmsec::{tk}",
                "technique": kn["technique"],
                "functional_semantics": kn["technique"] +
                    " - an attempt to extract hidden context / override instructions.",
                "root_cause": kn["root_cause"],
                "fix_pattern": kn["fix"],
                "category": kn["category"],
                "category_title": kn["category_title"],
                "owasp_2026": kn.get("owasp_2026"),
                "detection_hint": kn["detection_hint"],
                "multi_turn": kn["multi_turn"],
                "example_user_turn": None,
                "source": "own-redteam-logs + writeups #1-17 + OWASP LLM 2025 (2026 rename noted)",
                "license": "internal",
            }
            rag_by_tech[tk] = item
        if item["example_user_turn"] is None and bool(r.get("ground_truth_leak")):
            first_user = next((m.get("content") for m in msgs
                               if str(m.get("role")).lower() == "user"), None)
            item["example_user_turn"] = first_user

    # write SFT splits
    counts = {}
    for name, exs in sft.items():
        rng.shuffle(exs)
        out = os.path.join(a.outdir, f"llmsec_sft_{name}.jsonl")
        with open(out, "w", encoding="utf-8") as f:
            for e in exs:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        counts[name] = len(exs)

    # write RAG items
    rag_out = os.path.join(a.outdir, "llmsec_rag.jsonl")
    with open(rag_out, "w", encoding="utf-8") as f:
        for it in rag_by_tech.values():
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

    # family->split map for the record (auditability)
    fam_split = {}
    for e in (x for s in sft.values() for x in s):
        fam_split[e["attack_family"]] = e["split"]
    straddle = "OK"  # by construction a family maps to one split

    print(json.dumps({
        "sft_counts": counts,
        "sft_total": sum(counts.values()),
        "rag_items": len(rag_by_tech),
        "families": len(fam_split),
        "family_straddle": straddle,
        "skipped": skipped,
    }, indent=2))


if __name__ == "__main__":
    main()
