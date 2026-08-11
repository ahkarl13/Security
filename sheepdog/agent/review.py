#!/usr/bin/env python3
"""
sheepdog/agent/review.py - the DEFENSIVE code-review hat (Phase 5 / SENTINEL component).

Pipeline: source code -> (optional) static analysis (Semgrep) -> RAG retrieval over the
206-item KB -> a grounded security review from the reasoning model. Each finding gets a
location, vulnerability class (CWE/OWASP), severity, explanation, and concrete fix.

Per writeup #18, knowledge matters most for review, so this uses a capable model + RAG
(default qwen3.6:27b via Ollama); the SFT'd Sheepdog behavior model can be swapped in once
served. Runs anywhere with OLLAMA_HOST + the RAG index.

  OLLAMA_HOST=http://localhost:11434 python review.py --file samples/vuln_example.py \
      --index ..\\rag --model qwen3.6:27b
"""
import argparse
import json
import os
import subprocess
import urllib.request
import numpy as np

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB = "qwen3-embedding:8b"
REVIEW_SYS = (
    "You are Sheepdog, a defensive security code reviewer. Given source code (plus optional "
    "static-analysis findings and retrieved vulnerability knowledge), produce a precise "
    "security review. For each finding give: the location (function/line context), the "
    "vulnerability class with its CWE and/or OWASP id, a severity (Critical/High/Medium/Low), "
    "a one-sentence explanation, and the concrete fix. Ground findings in the provided "
    "knowledge; do NOT invent line numbers or issues that aren't present. End with a short "
    "prioritized remediation summary. You are a defender: you harden code, never weaponize it."
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


def chat(model, sys, user):
    d = post("/api/chat", {"model": model, "stream": False, "think": False,
                           "messages": [{"role": "system", "content": sys},
                                        {"role": "user", "content": user}]})
    return d.get("message", {}).get("content", "")


def load_index(indexdir):
    npz = np.load(os.path.join(indexdir, "index.npz"), allow_pickle=True)
    return npz["X"], list(npz["ids"]), {json.loads(l)["id"]: json.loads(l)
            for l in open(os.path.join(indexdir, "items.jsonl"), encoding="utf-8")}


def retrieve(q, X, ids, items, k=6):
    v = embed(q); v = v / (np.linalg.norm(v) or 1)
    order = np.argsort(-(X @ v))[:k]
    out = []
    for i in order:
        it = items[ids[i]]
        tag = it.get("cwe") or it.get("category", "")
        out.append(f"- {it['technique']} ({tag}): {it.get('root_cause','')[:180]} "
                   f"Fix: {it.get('fix_pattern','')[:180]}")
    return "\n".join(out)


def run_semgrep(path):
    """Optional: run Semgrep if installed; return a compact findings summary or None."""
    try:
        p = subprocess.run(["semgrep", "--config", "auto", "--quiet", "--json", path],
                           capture_output=True, text=True, timeout=180)
        data = json.loads(p.stdout or "{}")
        rows = []
        for r in data.get("results", [])[:20]:
            line = r.get("start", {}).get("line")
            msg = (r.get("extra", {}).get("message", "") or "")[:140]
            cwe = ";".join(r.get("extra", {}).get("metadata", {}).get("cwe", []) or [])
            rows.append(f"  L{line}: {msg} [{cwe}]")
        return "\n".join(rows) if rows else "(semgrep: no findings)"
    except Exception as e:
        return None  # semgrep not available; rely on model + RAG


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=None)
    ap.add_argument("--code", default=None)
    ap.add_argument("--index", default="../rag")
    ap.add_argument("--model", default="qwen3.6:27b")
    ap.add_argument("-k", type=int, default=6)
    a = ap.parse_args()

    code = open(a.file, encoding="utf-8").read() if a.file else (a.code or "")
    if not code.strip():
        raise SystemExit("provide --file or --code")

    sg = run_semgrep(a.file) if a.file else None
    X, ids, items = load_index(a.index)
    ctx = retrieve(code[:4000] + ("\n" + sg if sg else ""), X, ids, items, a.k)

    user = (f"CODE UNDER REVIEW:\n```\n{code[:6000]}\n```\n\n"
            + (f"STATIC-ANALYSIS FINDINGS (Semgrep):\n{sg}\n\n" if sg else "")
            + f"RETRIEVED VULNERABILITY KNOWLEDGE:\n{ctx}\n\n"
            + "Produce the security review.")
    print(f"[review] model={a.model} semgrep={'on' if sg else 'off'} kb_items={len(ids)}\n")
    print(chat(a.model, REVIEW_SYS, user))


if __name__ == "__main__":
    main()
