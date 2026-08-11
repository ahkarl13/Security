#!/usr/bin/env python3
"""
train_sheepdog_sft.py - SFT the Sheepdog behavior model on analyst pairs.
RUN ON POP GPU0 in ~/attacker-train/.venv (trl). Mirrors train_attacker.py's SFT path.

Each example is already a chat {system, user(the interaction), assistant(the analysis)}
from build_llmsec.py - so we just apply the chat template and LoRA-SFT. Trains
Foundation-Sec-8B-Instruct to behave like a defensive LLM-security analyst (the
DEFENSIVE framing is the emergent-misalignment antidote).

  CUDA_VISIBLE_DEVICES=0 ~/attacker-train/.venv/bin/python train_sheepdog_sft.py \
    --sft llmsec_sft_train.jsonl --out runs/sheepdog-sft \
    --base fdtn-ai/Foundation-Sec-8B-Instruct [--4bit] [--smoke]

--4bit uses QLoRA (bitsandbytes) if VRAM is tight; default is bf16 (needs a free 3090).
"""
import argparse
import json
import os
import torch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sft", default="llmsec_sft_train.jsonl")
    ap.add_argument("--out", default="runs/sheepdog-sft")
    ap.add_argument("--base", default="fdtn-ai/Foundation-Sec-8B-Instruct")
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--maxlen", type=int, default=2048)
    ap.add_argument("--4bit", dest="fourbit", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    from transformers import AutoTokenizer, AutoModelForCausalLM
    from datasets import Dataset
    from peft import LoraConfig
    from trl import SFTTrainer, SFTConfig

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    kw = dict(torch_dtype=torch.bfloat16, device_map={"": 0})
    if a.fourbit:
        from transformers import BitsAndBytesConfig
        kw = dict(device_map={"": 0}, quantization_config=BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True))
    model = AutoModelForCausalLM.from_pretrained(a.base, **kw)

    rows = [json.loads(l) for l in open(a.sft, encoding="utf-8") if l.strip()]
    if a.smoke:
        rows = rows[:16]
    texts = [tok.apply_chat_template(r["messages"], tokenize=False) for r in rows]
    ds = Dataset.from_dict({"text": texts})
    print(f"[sft] {len(ds)} examples on {a.base} (4bit={a.fourbit})", flush=True)

    lora = LoraConfig(task_type="CAUSAL_LM", r=16, lora_alpha=32, lora_dropout=0.05,
                      target_modules="all-linear")
    cfg = SFTConfig(output_dir=a.out, num_train_epochs=(1 if a.smoke else a.epochs),
                    per_device_train_batch_size=1, gradient_accumulation_steps=8,
                    learning_rate=1e-4, bf16=True, logging_steps=5,
                    max_length=a.maxlen, gradient_checkpointing=True,
                    save_strategy="no", report_to="none",
                    max_steps=(3 if a.smoke else -1), dataset_text_field="text")
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds, peft_config=lora)
    trainer.train()
    trainer.save_model(a.out)
    tok.save_pretrained(a.out)
    json.dump({"base": a.base, "examples": len(ds), "fourbit": a.fourbit,
               "epochs": (1 if a.smoke else a.epochs)},
              open(os.path.join(a.out, "sheepdog_meta.json"), "w"), indent=2)
    print(f"[sft] saved -> {a.out}", flush=True)


if __name__ == "__main__":
    main()
