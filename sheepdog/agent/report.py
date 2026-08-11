#!/usr/bin/env python3
"""
sheepdog/agent/report.py - the REPORTING hat (third hat).

Turns raw findings (from review.py, hunt.py, or a hand-written list) into a client-ready
security report: executive summary, per-finding technical detail with CWE/OWASP mapping,
CVSS v4.0 severity, remediation, and a retest step. RAG-grounds remediation in the KB.

Runs on the served Sheepdog (default sheepdog:8b) + RAG, like review.py.

  set OLLAMA_HOST=http://localhost:11434
  python report.py --findings findings.json --title "Acme LLM Assistant" --out report.md
  python report.py --file review_output.txt --out report.md   # free-text findings

findings.json = [{"title": "...", "location": "...", "class": "CWE-89 / OWASP LLM05",
                  "severity": "High", "detail": "...", "evidence": "..."}, ...]
"""
from __future__ import annotations
import argparse
import json
import os
import urllib.request
import numpy as np

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB = "qwen3-embedding:8b"

REPORT_SYS = (
    "You are Sheepdog's reporting hat. You convert verified security findings into a concise, "
    "professional, client-ready report. Structure: (1) Executive summary (business-level, no "
    "jargon, overall risk posture and top priorities); (2) Findings table (id, title, "
    "class[CWE/OWASP], severity, status); (3) Per-finding detail - description, affected "
    "location, impact, a CVSS v4.0 severity with vector, concrete remediation, and a retest step "
    "that confirms the fix; (4) Prioritized remediation roadmap. Ground remediation in the "
    "provided knowledge; be precise with CWE/OWASP ids; never invent findings not supplied. You "
    "are a defender writing to help the client fix issues."
)


def post(path, body, timeout=600):
    req = urllib.request.Request(OLLAMA.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def embed(t):
    d = post("/api/embed", {"model": EMB, "input": t[:8000]})
    v = d.get("embeddings") or d.get("embedding")
    return np.asarray(v[0] if isinstance(v[0], list) else v, dtype="float32")


def chat(model, sys_prompt, user):
    d = post("/api/chat", {"model": model, "stream": False, "think": False,
                           "messages": [{"role": "system", "content": sys_prompt},
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
        out.append(f"- {it['technique']} ({tag}): Fix: {it.get('fix_pattern','')[:200]}")
    return "\n".join(out)


def load_findings(a):
    if a.findings:
        data = json.load(open(a.findings, encoding="utf-8"))
        lines = []
        for i, f in enumerate(data, 1):
            lines.append(f"F{i}. {f.get('title','(finding)')} | class={f.get('class','')} "
                         f"| severity={f.get('severity','')} | location={f.get('location','')}\n"
                         f"    detail: {f.get('detail','')}\n"
                         f"    evidence: {f.get('evidence','')}")
        return "\n".join(lines)
    if a.file:
        return open(a.file, encoding="utf-8").read()
    raise SystemExit("provide --findings <json> or --file <text>")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default=None, help="findings JSON list")
    ap.add_argument("--file", default=None, help="free-text findings (e.g. review.py output)")
    ap.add_argument("--title", default="Target System")
    ap.add_argument("--index", default="../rag")
    ap.add_argument("--model", default="qwen3.6:27b")  # long-form reports need the larger model; the served 8B is SFT'd for short analysis
    ap.add_argument("--out", default=None)
    ap.add_argument("-k", type=int, default=6)
    a = ap.parse_args()

    findings = load_findings(a)
    X, ids, items = load_index(a.index)
    ctx = retrieve(findings[:3000], X, ids, items, a.k)
    user = (f"ENGAGEMENT: {a.title}\n\nVERIFIED FINDINGS:\n{findings}\n\n"
            f"RETRIEVED REMEDIATION KNOWLEDGE:\n{ctx}\n\n"
            "Write the client-ready report now.")
    print(f"[report] model={a.model} kb_items={len(ids)} title={a.title!r}", flush=True)
    out = chat(a.model, REPORT_SYS, user)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(out)
        print(f"[report] wrote {a.out}")
    else:
        print(out)


if __name__ == "__main__":
    main()
