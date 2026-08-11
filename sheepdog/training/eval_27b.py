#!/usr/bin/env python3
"""
eval_27b.py - the SIZE arm of the #18 head-to-head: aligned qwen3.6:27b (no SFT adapter;
we only SFT'd the 8B) with/without RAG, via Ollama HTTP. Runs anywhere with OLLAMA_HOST
(pure HTTP; Ollama manages the 27B + embed model on the GPUs).

  --task crossdomain : cross_domain_probes.jsonl, retrieve from --index, gold=term-list
  --task realcve     : realcve_probes.jsonl + --contexts realcve_contexts.json, gold=CWE

  OLLAMA_HOST=http://localhost:11434 python eval_27b.py --task crossdomain --index .
  OLLAMA_HOST=http://localhost:11434 python eval_27b.py --task realcve --contexts realcve_contexts.json
"""
import argparse
import json
import os
import re
import urllib.request
import numpy as np

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB = "qwen3-embedding:8b"
SYS_XD = ("You are a security analyst. Answer the question concisely and correctly, naming the "
          "specific vulnerability class / CWE / technique / framework where relevant.")
SYS_CVE = ("You are a security analyst. Map the given CVE description to the single most "
           "appropriate CWE. Briefly justify, then put ONLY the CWE ID (e.g., CWE-79) on the last line.")


def post(path, body, timeout=300):
    req = urllib.request.Request(OLLAMA + path, data=json.dumps(body).encode(),
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


def retrieve(q, X, ids, items, k=4):
    v = embed(q); v = v / (np.linalg.norm(v) or 1)
    order = np.argsort(-(X @ v))[:k]
    return "\n".join(f"- {items[ids[i]]['technique']} ({items[ids[i]].get('cwe') or items[ids[i]].get('category','')}): "
                     f"{items[ids[i]].get('root_cause','')[:160]}" for i in order)


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def hit(text, gold):
    if isinstance(gold, list):
        t = text.lower()
        return any(g.lower() in t for g in gold)
    return norm(gold) in norm(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", choices=["crossdomain", "realcve"], required=True)
    ap.add_argument("--model", default="qwen3.6:27b")
    ap.add_argument("--index", default=".")
    ap.add_argument("--contexts", default=None)
    a = ap.parse_args()

    if a.task == "crossdomain":
        probes = [json.loads(l) for l in open("cross_domain_probes.jsonl", encoding="utf-8") if l.strip()]
        sys, key = SYS_XD, "q"
        X, ids, items = load_index(a.index)
        contexts = [retrieve(p["q"], X, ids, items) for p in probes]
        print(f"[27b:{a.task}] {len(probes)} probes, contexts retrieved", flush=True)
    else:
        probes = [json.loads(l) for l in open("realcve_probes.jsonl", encoding="utf-8") if l.strip()]
        sys, key = SYS_CVE, "prompt"
        contexts = json.load(open(a.contexts))
        print(f"[27b:{a.task}] {len(probes)} probes, contexts loaded", flush=True)

    no_rag = rag = 0
    for i, p in enumerate(probes):
        q = p[key]
        if hit(chat(a.model, sys, (f"CVE: {q}" if a.task == "realcve" else q)), p["gold"]):
            no_rag += 1
        u = (f"Reference knowledge:\n{contexts[i]}\n\n" + (f"CVE: {q}" if a.task == "realcve" else f"Question: {q}"))
        if hit(chat(a.model, sys, u), p["gold"]):
            rag += 1
    print(json.dumps({"model": a.model, "task": a.task, "n": len(probes),
                      "27B": round(no_rag / len(probes), 3),
                      "27B+RAG": round(rag / len(probes), 3)}, indent=2), flush=True)


if __name__ == "__main__":
    main()
