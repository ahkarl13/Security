#!/usr/bin/env python3
"""
eval_realcve.py - 4-arm head-to-head on REAL CVEs (CTIBench cti-rcm: CVE -> CWE).
base / SFT / RAG / SFT+RAG. RUN ON POP GPU0.

Two modes (decoupled to avoid embed-vs-generator VRAM contention on GPU0):
  RETRIEVE (default): embed each CVE via Pop Ollama, retrieve top-k KB context, write
      --ctxfile, then EXIT. (Ollama holds the embed model resident, so stop it after.)
  GEN (--gen): load --ctxfile (no embedding), run the 4 arms, score exact-CWE match.

Orchestration:
  python eval_realcve.py --probes realcve_probes.jsonl --index .        # retrieve
  ollama stop qwen3-embedding:8b                                        # free GPU0
  CUDA_VISIBLE_DEVICES=0 python eval_realcve.py --gen --adapter runs/sheepdog-sft
"""
import argparse
import json
import os
import re
import urllib.request
import numpy as np
import torch

OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMB_MODEL = "qwen3-embedding:8b"
SYS = ("You are a security analyst. Map the given CVE description to the single most "
       "appropriate CWE. Briefly justify, then put ONLY the CWE ID (e.g., CWE-79) on the last line.")


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
    return npz["X"], list(npz["ids"]), {json.loads(l)["id"]: json.loads(l)
            for l in open(os.path.join(indexdir, "items.jsonl"), encoding="utf-8")}


def retrieve(q, X, ids, items, k=4):
    v = embed(q); v = v / (np.linalg.norm(v) or 1)
    order = np.argsort(-(X @ v))[:k]
    return "\n".join(f"- {items[ids[i]]['technique']} ({items[ids[i]].get('cwe') or items[ids[i]].get('category','')}): "
                     f"{items[ids[i]].get('root_cause','')[:160]}" for i in order)


def gen(model, tok, cve, ctx=None, maxnew=200):
    user = f"CVE: {cve}" if not ctx else f"Reference knowledge:\n{ctx}\n\nCVE: {cve}"
    msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    ids = tok(prompt, return_tensors="pt").to(model.device)
    out = model.generate(**ids, max_new_tokens=maxnew, do_sample=False, pad_token_id=tok.pad_token_id)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def hit(text, gold):
    return norm(gold) in norm(text)


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
        if hit(gen(m, tok, p["prompt"], None), p["gold"]):
            no_rag += 1
        if hit(gen(m, tok, p["prompt"], contexts[i]), p["gold"]):
            rag += 1
    del m; gc.collect(); torch.cuda.empty_cache()
    return no_rag / len(probes), rag / len(probes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probes", default="realcve_probes.jsonl")
    ap.add_argument("--index", default=".")
    ap.add_argument("--ctxfile", default="realcve_contexts.json")
    ap.add_argument("--base", default="fdtn-ai/Foundation-Sec-8B-Instruct")
    ap.add_argument("--adapter", default="runs/sheepdog-sft")
    ap.add_argument("--gen", action="store_true", help="gen mode (contexts from --ctxfile)")
    a = ap.parse_args()
    probes = [json.loads(l) for l in open(a.probes, encoding="utf-8") if l.strip()]

    if not a.gen:
        X, ids, items = load_index(a.index)
        print(f"[cve:retrieve] {len(probes)} CVEs, {len(ids)} KB items", flush=True)
        contexts = [retrieve(p["prompt"], X, ids, items) for p in probes]
        json.dump(contexts, open(a.ctxfile, "w"))
        print(f"[cve:retrieve] wrote {len(contexts)} contexts -> {a.ctxfile}. "
              f"Now: ollama stop {EMB_MODEL} && re-run with --gen", flush=True)
        return

    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    contexts = json.load(open(a.ctxfile))
    print(f"[cve:gen] {len(probes)} CVEs, contexts loaded", flush=True)
    b_no, b_rag = run_model(a.base, None, tok, probes, contexts)
    print("[cve:gen] base arms done", flush=True)
    s_no, s_rag = run_model(a.base, a.adapter, tok, probes, contexts)
    print("[cve:gen] sft arms done", flush=True)
    print(json.dumps({"n": len(probes), "benchmark": "CTIBench cti-rcm (CVE->CWE)",
                      "base": round(b_no, 3), "base+RAG": round(b_rag, 3),
                      "SFT": round(s_no, 3), "SFT+RAG": round(s_rag, 3)}, indent=2))


if __name__ == "__main__":
    main()
