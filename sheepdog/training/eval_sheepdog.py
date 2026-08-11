#!/usr/bin/env python3
"""
eval_sheepdog.py - base vs SFT analyst-behavior eval on the held-out test set.
RUN ON POP GPU0 in ~/attacker-train/.venv AFTER the SFT finishes.

Metric (first #18 signal): given the interaction (system+user), does the model
  (1) name the CORRECT OWASP category id (category_acc), and
  (2) produce the structured analyst format (format_adherence)?
Greedy decoding, held-out by-family test split.

  CUDA_VISIBLE_DEVICES=0 ~/attacker-train/.venv/bin/python eval_sheepdog.py \
    --test llmsec_sft_test.jsonl --base fdtn-ai/Foundation-Sec-8B-Instruct \
    --adapter runs/sheepdog-sft --n 50
"""
import argparse
import json
import torch


def gen(model, tok, messages, maxnew=256):
    prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    ids = tok(prompt, return_tensors="pt").to(model.device)
    out = model.generate(**ids, max_new_tokens=maxnew, do_sample=False,
                         pad_token_id=tok.pad_token_id)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def score(text, gold_cat):
    cat_hit = gold_cat.lower() in text.lower()
    fmt = sum(k.lower() in text.lower() for k in
              ["OWASP", "Technique", "Outcome", "Root cause", "Fix", "look for"])
    return cat_hit, fmt >= 4


def run_model(base, adapter, tok, rows):
    import gc
    from transformers import AutoModelForCausalLM
    from peft import PeftModel
    m = AutoModelForCausalLM.from_pretrained(base, torch_dtype=torch.bfloat16, device_map={"": 0})
    if adapter:
        m = PeftModel.from_pretrained(m, adapter)
    m.eval()
    cat = fmt = 0
    sample = None
    for i, r in enumerate(rows):
        msgs = [r["messages"][0], r["messages"][1]]
        txt = gen(m, tok, msgs)
        ch, fh = score(txt, r["category"])
        cat += ch; fmt += fh
        if i == 0:
            sample = txt[:500]
    del m; gc.collect(); torch.cuda.empty_cache()
    return cat / len(rows), fmt / len(rows), sample


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", default="llmsec_sft_test.jsonl")
    ap.add_argument("--base", default="fdtn-ai/Foundation-Sec-8B-Instruct")
    ap.add_argument("--adapter", default="runs/sheepdog-sft")
    ap.add_argument("--n", type=int, default=50)
    a = ap.parse_args()
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    rows = [json.loads(l) for l in open(a.test, encoding="utf-8") if l.strip()][:a.n]
    print(f"[eval] {len(rows)} held-out test examples", flush=True)
    b_cat, b_fmt, b_s = run_model(a.base, None, tok, rows)
    print("[eval] base done", flush=True)
    s_cat, s_fmt, s_s = run_model(a.base, a.adapter, tok, rows)
    print("[eval] sft done", flush=True)
    print(json.dumps({"n": len(rows),
                      "base": {"category_acc": round(b_cat, 3), "format_adherence": round(b_fmt, 3)},
                      "sft": {"category_acc": round(s_cat, 3), "format_adherence": round(s_fmt, 3)}},
                     indent=2))
    print("\n--- base sample ---\n" + (b_s or ""))
    print("\n--- sft sample ---\n" + (s_s or ""))


if __name__ == "__main__":
    main()
