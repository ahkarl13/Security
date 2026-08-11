#!/usr/bin/env python3
"""eval_ref.py - same 30 scenarios as eval_multiclass, but the system prompt INCLUDES the
OWASP-LLM 2025 numbering key. Tests the hypothesis that the raw 27B knows the vuln CLASS
(title) but not the exact NUMBER - giving it the key should map concept->correct id.

  python eval_ref.py --model qwen3.6:27b
"""
from __future__ import annotations
import argparse, json, re, os, urllib.request
from eval_multiclass import EVAL

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
REF = ("The OWASP Top 10 for LLM Applications (2025) ids are EXACTLY: "
       "LLM01 Prompt Injection; LLM02 Sensitive Information Disclosure; LLM03 Supply Chain; "
       "LLM04 Data and Model Poisoning; LLM05 Improper Output Handling; LLM06 Excessive Agency; "
       "LLM07 System Prompt Leakage; LLM08 Vector and Embedding Weaknesses; LLM09 Misinformation; "
       "LLM10 Unbounded Consumption.")
SYS = ("You are a security analyst for LLM application security. " + REF +
       " Identify the single class the interaction best matches, then output the id that maps to "
       "that class per the list above. Begin your answer with 'OWASP category:' followed by that "
       "exact id (LLM01-LLM10) and its title. Make the number and title agree with the list. "
       "You are a defender.")


def chat(model, user):
    body = {"model": model, "stream": False, "think": False,
            "messages": [{"role": "system", "content": SYS}, {"role": "user", "content": user}]}
    req = urllib.request.Request(OLLAMA.rstrip("/") + "/api/chat",
                                 data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read()).get("message", {}).get("content", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3.6:27b")
    a = ap.parse_args()
    hits, rows = 0, []
    for exp, u, asst in EVAL:
        user = f"USER: {u}\nASSISTANT: {asst}\n\nAnalyze this interaction against the OWASP LLM Top 10 (2025)."
        out = chat(a.model, user)
        m = re.search(r"LLM\s*0?(\d{1,2})", out)
        got = f"LLM{int(m.group(1)):02d}" if m else "??"
        ok = got == exp; hits += ok
        rows.append((exp, got, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] expect {exp} got {got:>5}  | {out.splitlines()[0][:70] if out else ''}", flush=True)
    print(f"\n[eval_ref] {a.model}: category_acc {hits}/{len(EVAL)} = {hits/len(EVAL):.2f}")
    byc = {}
    for exp, got, ok in rows:
        byc.setdefault(exp, [0, 0]); byc[exp][0] += ok; byc[exp][1] += 1
    print("  per-class:", {k: f"{v[0]}/{v[1]}" for k, v in sorted(byc.items())})


if __name__ == "__main__":
    main()
