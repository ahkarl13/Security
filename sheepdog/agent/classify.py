#!/usr/bin/env python3
"""
sheepdog/agent/classify.py - the OWASP-LLM CLASSIFICATION analyst hat, on the 27B base.

Finding (2026-08-11): a served 8B SFT'd on our data caps at ~0.60 on a 30-scenario all-class
eval (it can't reliably recognize clean prompt-injection - a base-model capacity limit). The
raw 27B knows the vuln CLASSES but not the exact OWASP-LLM 2025 NUMBERING (0.13 by number).
Give the 27B the numbering key in the system prompt and it jumps to **0.97** - no fine-tune.
So the classification analyst = qwen3.6:27b + the numbering key (below), optionally RAG-grounded.

  set OLLAMA_HOST=http://localhost:11434
  python classify.py --interaction "USER: ...\nASSISTANT: ..."
  python classify.py --file interaction.txt --index ..\\rag
"""
from __future__ import annotations
import argparse, json, os, urllib.request
import numpy as np

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB = "qwen3-embedding:8b"

# The load-bearing key: the 27B knows the classes, this pins the 2025 numbering.
OWASP_KEY = ("The OWASP Top 10 for LLM Applications (2025) ids are EXACTLY: "
             "LLM01 Prompt Injection; LLM02 Sensitive Information Disclosure; LLM03 Supply Chain; "
             "LLM04 Data and Model Poisoning; LLM05 Improper Output Handling; LLM06 Excessive Agency; "
             "LLM07 System Prompt Leakage; LLM08 Vector and Embedding Weaknesses; "
             "LLM09 Misinformation; LLM10 Unbounded Consumption.")
SYS = (
    "You are Sheepdog, a defensive LLM-security analyst. " + OWASP_KEY +
    " Given an interaction (and optional retrieved knowledge), identify the single class it best "
    "matches and output, on the first line, 'OWASP category:' followed by the exact id (LLM01-LLM10) "
    "and its title from the list above (number and title MUST agree). Then give: the technique, "
    "whether it succeeded and why, the root cause, the fix, and what to look for. Note a secondary "
    "class only if clearly warranted. You are a defender: you analyze to harden, never to help attack."
)


def post(path, body, timeout=300):
    req = urllib.request.Request(OLLAMA.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def embed(t):
    d = post("/api/embed", {"model": EMB, "input": t[:8000]})
    v = d.get("embeddings") or d.get("embedding")
    return np.asarray(v[0] if isinstance(v[0], list) else v, dtype="float32")


def retrieve(q, indexdir, k=5):
    npz = np.load(os.path.join(indexdir, "index.npz"), allow_pickle=True)
    X, ids = npz["X"], list(npz["ids"])
    items = {json.loads(l)["id"]: json.loads(l)
             for l in open(os.path.join(indexdir, "items.jsonl"), encoding="utf-8")}
    v = embed(q); v = v / (np.linalg.norm(v) or 1)
    out = []
    for i in np.argsort(-(X @ v))[:k]:
        it = items[ids[i]]
        out.append(f"- {it['technique']} ({it.get('category','')}): {it.get('root_cause','')[:160]}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interaction", default=None)
    ap.add_argument("--file", default=None)
    ap.add_argument("--index", default=None, help="optional RAG index dir to ground the analysis")
    ap.add_argument("--model", default="qwen3.6:27b")
    a = ap.parse_args()
    text = a.interaction or (open(a.file, encoding="utf-8").read() if a.file else "")
    if not text.strip():
        raise SystemExit("provide --interaction or --file")
    ctx = ""
    if a.index:
        ctx = "\n\nRETRIEVED KNOWLEDGE:\n" + retrieve(text[:2000], a.index)
    user = (f"{text}\n{ctx}\n\nAnalyze this interaction against the OWASP LLM Top 10 (2025).")
    d = post("/api/chat", {"model": a.model, "stream": False, "think": False,
                           "messages": [{"role": "system", "content": SYS},
                                        {"role": "user", "content": user}]})
    print(f"[classify] model={a.model} (OWASP-LLM analyst, numbering-key prompt)\n")
    print(d.get("message", {}).get("content", ""))


if __name__ == "__main__":
    main()
