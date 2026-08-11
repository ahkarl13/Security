#!/usr/bin/env python3
"""
eval_crossdomain.py - 4-arm head-to-head on CROSS-DOMAIN KB questions.
base / SFT / RAG / SFT+RAG. Tests whether RAG over the full KB beats bare SFT on
app-layer/pentest/framework questions the SFT NEVER trained on (SFT trained only on
LLM-security analyst pairs). RUN ON POP GPU0 in ~/attacker-train/.venv.

Retrieval uses Pop Ollama qwen3-embedding:8b (localhost) over index.npz/items.jsonl.
Score = does the answer contain a correct gold term (case-insensitive)?

  CUDA_VISIBLE_DEVICES=0 ~/attacker-train/.venv/bin/python eval_crossdomain.py \
    --probes cross_domain_probes.jsonl --index . \
    --base fdtn-ai/Foundation-Sec-8B-Instruct --adapter runs/sheepdog-sft
"""
import argparse
import json
import os
import urllib.request
import numpy as np
import torch

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB_MODEL = "qwen3-embedding:8b"
SYS = ("You are a security analyst. Answer the question concisely and correctly, naming the "
       "specific vulnerability class / CWE / technique / framework where relevant.")


def embed(text):
    body = json.dumps({"model": EMB_MODEL, "input": text[:8000]}).encode()
    req = urllib.request.Request(OLLAMA + "/api/embed", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read().decode())
    v = d.get("embeddings") or d.get("embedding")
    if v and isinstance(v[0], list):
        v = v[0]
    return np.asarray(v, dtype="float32")


def load_index(indexdir):
    npz = np.load(os.path.join(indexdir, "index.npz"), allow_pickle=True)
    X, ids = npz["X"], list(npz["ids"])
    items = {json.loads(l)["id"]: json.loads(l)
             for l in open(os.path.join(indexdir, "items.jsonl"), encoding="utf-8")}
    return X, ids, items


def retrieve(q, X, ids, items, k=4):
    v = embed(q); v = v / (np.linalg.norm(v) or 1)
    order = np.argsort(-(X @ v))[:k]
    ctx = []
    for i in order:
        it = items[ids[i]]
        ctx.append(f"- {it['technique']} ({it.get('category','')}): "
                   f"{it.get('root_cause','')[:180]} Fix: {it.get('fix_pattern','')[:180]}")
    return "\n".join(ctx)


def gen(model, tok, q, ctx=None, maxnew=200):
    user = q if ctx is None else f"Reference knowledge:\n{ctx}\n\nQuestion: {q}"
    msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    ids = tok(prompt, return_tensors="pt").to(model.device)
    out = model.generate(**ids, max_new_tokens=maxnew, do_sample=False, pad_token_id=tok.pad_token_id)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def hit(text, gold):
    t = text.lower()
    return any(g.lower() in t for g in gold)


def run_model(base, adapter, tok, probes, contexts):
    import gc
    from transformers import AutoModelForCausalLM
    from peft import PeftModel
    m = AutoModelForCausalLM.from_pretrained(base, torch_dtype=torch.bfloat16, device_map={"": 0})
    if adapter:
        m = PeftModel.from_pretrained(m, adapter)
    m.eval()
    no_rag = rag = 0
    for i, p in enumerate(probes):
        if hit(gen(m, tok, p["q"], None), p["gold"]):
            no_rag += 1
        if hit(gen(m, tok, p["q"], contexts[i]), p["gold"]):
            rag += 1
    del m; gc.collect(); torch.cuda.empty_cache()
    return no_rag / len(probes), rag / len(probes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probes", default="cross_domain_probes.jsonl")
    ap.add_argument("--index", default=".")
    ap.add_argument("--base", default="fdtn-ai/Foundation-Sec-8B-Instruct")
    ap.add_argument("--adapter", default="runs/sheepdog-sft")
    a = ap.parse_args()
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    probes = [json.loads(l) for l in open(a.probes, encoding="utf-8") if l.strip()]
    X, ids, items = load_index(a.index)
    print(f"[xd] {len(probes)} probes, {len(ids)} KB items", flush=True)
    contexts = [retrieve(p["q"], X, ids, items) for p in probes]  # once, reused across models
    print("[xd] contexts retrieved", flush=True)
    # free the embedding model from VRAM before loading the 8B generator on GPU0
    try:
        urllib.request.urlopen(urllib.request.Request(
            OLLAMA + "/api/embed",
            data=json.dumps({"model": EMB_MODEL, "input": "x", "keep_alive": 0}).encode(),
            headers={"Content-Type": "application/json"}), timeout=60)
        print("[xd] embed model unloaded", flush=True)
    except Exception as e:
        print("[xd] unload warn:", e, flush=True)
    base_no, base_rag = run_model(a.base, None, tok, probes, contexts)
    print("[xd] base arms done", flush=True)
    sft_no, sft_rag = run_model(a.base, a.adapter, tok, probes, contexts)
    print("[xd] sft arms done", flush=True)
    print(json.dumps({"n": len(probes),
                      "base": round(base_no, 3), "base+RAG": round(base_rag, 3),
                      "SFT": round(sft_no, 3), "SFT+RAG": round(sft_rag, 3)}, indent=2))


if __name__ == "__main__":
    main()
