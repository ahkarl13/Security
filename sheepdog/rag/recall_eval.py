#!/usr/bin/env python3
"""
recall_eval.py - retrieval quality (recall@k + MRR) for the Sheepdog RAG index.

Writeup #18's lesson is "relevance is everything," but we only ever measured end-task
accuracy. This measures RETRIEVAL directly: given a natural-language query phrased
DIFFERENTLY from the KB text, does a correct (gold) item appear in the top-k?

Gold is matched by rule (exact id / category / id-prefix / id-substring) so we don't
hardcode brittle ids. Embeds via Pop qwen3-embedding:8b (mirrors review.py), cosines
against the local index.npz.

  set OLLAMA_HOST=http://localhost:11434
  python recall_eval.py --index . -k 6
"""
from __future__ import annotations
import argparse
import json
import os
import urllib.request
import numpy as np

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB = "qwen3-embedding:8b"


def embed(t):
    req = urllib.request.Request(OLLAMA.rstrip("/") + "/api/embed",
                                 data=json.dumps({"model": EMB, "input": t[:8000]}).encode(),
                                 headers={"Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=120).read())
    v = d.get("embeddings") or d.get("embedding")
    return np.asarray(v[0] if isinstance(v[0], list) else v, dtype="float32")


def load_index(indexdir):
    npz = np.load(os.path.join(indexdir, "index.npz"), allow_pickle=True)
    items = {json.loads(l)["id"]: json.loads(l)
             for l in open(os.path.join(indexdir, "items.jsonl"), encoding="utf-8")}
    return npz["X"], list(npz["ids"]), items


def gold_fn(kind, val):
    if kind == "id":
        return lambda it: it["id"] == val
    if kind == "cat":
        return lambda it: it.get("category") == val
    if kind == "pref":
        return lambda it: it["id"].split("::")[0] == val
    if kind == "idsub":
        return lambda it: val.lower() in it["id"].lower()
    raise ValueError(kind)


# (query phrased UNLIKE the KB text, gold_kind, gold_val)
QUERIES = [
    ("A web page my assistant summarized had hidden text telling it to email data out, and it obeyed", "cat", "LLM01"),
    ("The chatbot revealed a customer's card number that belonged to a different account", "id", "owasp::LLM02"),
    ("We plugged in an unsigned third-party model with no provenance checks", "id", "owasp::LLM03"),
    ("A secret trigger phrase in the fine-tune data flips the model into malicious behavior", "id", "owasp::LLM04"),
    ("The model's reply was dropped straight into a SQL statement and caused injection", "id", "owasp::LLM05"),
    ("The agent had permission to call a delete-everything tool and did so unprompted", "id", "owasp::LLM06"),
    ("Someone got the bot to print its hidden instructions and the code embedded in them", "cat", "LLM07"),
    ("Search returned another tenant's documents out of the shared embedding database", "id", "owasp::LLM08"),
    ("The model confidently cited a court case that does not exist", "id", "owasp::LLM09"),
    ("A giant repeated input made the service rack up huge token costs and stall", "id", "owasp::LLM10"),
    ("User input concatenated into a database query lets an attacker read other rows", "idsub", "CWE-89"),
    ("Reflected user text rendered into a page runs attacker script in the browser", "idsub", "CWE-79"),
    ("The server fetches a URL the user supplies, reaching internal-only services", "idsub", "CWE-918"),
    ("An object id in the URL lets a user read another user's record", "idsub", "CWE-639"),
    ("A stack buffer is written past its end by unchecked input", "pref", "cwe-mem"),
    ("How does an adversary poison a model through the ML supply chain in the ATLAS framework", "pref", "atlas"),
    ("Which ATT&CK tactic covers stealing credentials from memory or files", "pref", "attack"),
    ("What NIST function is about detecting an ongoing cybersecurity event", "pref", "nist-csf"),
    ("The reconnaissance-then-exploitation-then-reporting stages of an engagement", "pref", "pentest-phase"),
    ("Testing methodology standard specifically for web application security", "pref", "pentest-std"),
    ("Difference between a black-box, gray-box, and white-box assessment", "pref", "pentest-box"),
    ("Least-impact way to prove a finding is real without damaging the target", "pref", "exploit"),
    ("Assessing the security of an Active Directory or cloud attack surface", "pref", "pentest-surface"),
    ("A cross-lingual jailbreak: the guard holds in English but leaks in a low-resource language", "idsub", "llmsec"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=".")
    ap.add_argument("-k", type=int, default=6)
    a = ap.parse_args()
    X, ids, items = load_index(a.index)
    ks = sorted({1, 3, a.k})
    hit = {k: 0 for k in ks}
    rr = 0.0
    for q, kind, val in QUERIES:
        g = gold_fn(kind, val)
        v = embed(q); v = v / (np.linalg.norm(v) or 1)
        order = np.argsort(-(X @ v))
        ranks = [r for r, i in enumerate(order) if g(items[ids[i]])]
        first = ranks[0] + 1 if ranks else None
        rr += (1.0 / first) if first else 0.0
        for k in ks:
            if first and first <= k:
                hit[k] += 1
        tag = f"#{first}" if first else "MISS"
        print(f"  [{tag:>5}] {q[:64]}")
    n = len(QUERIES)
    print(f"\n[recall_eval] n={n} over {len(ids)} KB items")
    for k in ks:
        print(f"  recall@{k}: {hit[k]}/{n} = {hit[k]/n:.2f}")
    print(f"  MRR: {rr/n:.3f}")


if __name__ == "__main__":
    main()
