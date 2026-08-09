#!/usr/bin/env python3
"""
training/embed_judge.py - frozen embeddings for the judge splits via Pop Ollama.

The QLoRA path (train_judge.py) needs a GPU shell on Pop. This path needs only
Ollama's HTTP embeddings endpoint (which works from the Mini PC) + CPU, and for
~280 examples a frozen-embedding classifier resists overfitting far better than
an 8B QLoRA. Embeds judge_{train,val,test}.jsonl -> data/judge/emb_<split>.npz.

Usage:
  set OLLAMA_HOST=http://<your-ollama-host>:11434
  python embed_judge.py --model qwen3-embedding:8b
"""
import argparse
import json
import os
import urllib.request
import numpy as np

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def embed(model, text):
    body = json.dumps({"model": model, "input": text[:8000]}).encode()
    req = urllib.request.Request(OLLAMA + "/api/embed", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read().decode())
    v = d.get("embeddings") or d.get("embedding")
    if v and isinstance(v[0], list):
        v = v[0]
    return np.asarray(v, dtype="float32")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/judge")
    ap.add_argument("--model", default="qwen3-embedding:8b")
    a = ap.parse_args()
    for split in ("train", "val", "test"):
        path = os.path.join(a.data, f"judge_{split}.jsonl")
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        X, y, fam = [], [], []
        for i, r in enumerate(rows):
            X.append(embed(a.model, r["text"]))
            y.append(int(r["label"]))
            fam.append(r.get("attack_family", "?"))
            if (i + 1) % 25 == 0:
                print(f"  {split}: {i+1}/{len(rows)}")
        out = os.path.join(a.data, f"emb_{split}.npz")
        np.savez(out, X=np.stack(X), y=np.array(y),
                 fam=np.array(fam, dtype=object), model=a.model)
        print(f"{split}: {len(rows)} embedded (dim={X[0].shape[0]}) -> {out}")


if __name__ == "__main__":
    main()

