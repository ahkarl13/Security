#!/usr/bin/env python3
"""
train_dpo.py - DPO on top of the SFT adapter: prefer the correct OWASP category over a
hallucinated one. RUN ON POP GPU0 in ~/attacker-train/.venv (trl). Continues from the SFT
LoRA (ref = same model with the adapter disabled).

  CUDA_VISIBLE_DEVICES=0 ~/attacker-train/.venv/bin/python train_dpo.py \
    --dpo dpo_train.jsonl --adapter runs/sheepdog-sft --out runs/sheepdog-dpo [--smoke]
"""
import argparse
import json
import torch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dpo", default="dpo_train.jsonl")
    ap.add_argument("--base", default="fdtn-ai/Foundation-Sec-8B-Instruct")
    ap.add_argument("--adapter", default="runs/sheepdog-sft")
    ap.add_argument("--out", default="runs/sheepdog-dpo")
    ap.add_argument("--maxsteps", type=int, default=150)
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()

    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel
    from datasets import Dataset
    from trl import DPOTrainer, DPOConfig

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(a.base, torch_dtype=torch.bfloat16, device_map={"": 0})
    model = PeftModel.from_pretrained(base, a.adapter, is_trainable=True)

    rows = [json.loads(l) for l in open(a.dpo, encoding="utf-8") if l.strip()]
    if a.smoke:
        rows = rows[:16]
    ds = Dataset.from_list(rows)
    print(f"[dpo] {len(ds)} preference pairs on {a.adapter}", flush=True)

    cfg = DPOConfig(output_dir=a.out, num_train_epochs=1,
                    per_device_train_batch_size=1, gradient_accumulation_steps=8,
                    learning_rate=5e-6, beta=0.1, bf16=True, logging_steps=5,
                    max_length=1536,
                    gradient_checkpointing=True, save_strategy="no", report_to="none",
                    max_steps=(3 if a.smoke else a.maxsteps))
    trainer = DPOTrainer(model=model, args=cfg, train_dataset=ds, processing_class=tok)
    trainer.train()
    trainer.save_model(a.out)
    tok.save_pretrained(a.out)
    json.dump({"base": a.base, "from_adapter": a.adapter, "pairs": len(ds),
               "max_steps": (3 if a.smoke else a.maxsteps)},
              open(a.out + "/dpo_meta.json", "w"), indent=2)
    print(f"[dpo] saved -> {a.out}", flush=True)


if __name__ == "__main__":
    main()
