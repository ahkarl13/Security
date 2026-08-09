#!/usr/bin/env python3
"""
training/train_judge.py - QLoRA an 8B classification head for the hybrid judge.

RUN ON POP (needs a CUDA GPU + HF weights). This trains the NEURAL layer only —
the matcher stays authoritative on the leak axis; this head adjudicates the
ambiguous "policy-violation-without-the-literal-value" band.

Stack: transformers AutoModelForSequenceClassification (num_labels=2) + 4-bit
bitsandbytes + peft LoRA (task_type=SEQ_CLS). TRL is the same objective underneath;
Unsloth's FastModel can wrap this for ~2x speed once the plain path is verified.

Data: data/judge/judge_{train,val,test}.jsonl  ({text, label} per line).
Output: <outdir>/ adapter + tokenizer + judge_meta.json + val/test logits for calibrate.py.

Example (Pop):
  CUDA_VISIBLE_DEVICES=0 python train_judge.py \
      --base Qwen/Qwen3-8B --outdir runs/judge_qwen3_8b --epochs 2
"""
import argparse
import json
import os
import numpy as np


def load_split(path):
    texts, labels = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                texts.append(r["text"])
                labels.append(int(r["label"]))
    return texts, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/judge")
    ap.add_argument("--base", default="Qwen/Qwen3-8B")
    ap.add_argument("--outdir", default="runs/judge")
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--r", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--maxlen", type=int, default=4096)
    ap.add_argument("--bs", type=int, default=1)
    ap.add_argument("--grad_accum", type=int, default=16)
    a = ap.parse_args()

    import torch
    from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                              BitsAndBytesConfig, TrainingArguments, Trainer,
                              DataCollatorWithPadding)
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from datasets import Dataset
    from sklearn.metrics import precision_recall_fscore_support, accuracy_score

    os.makedirs(a.outdir, exist_ok=True)
    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    def prep(split):
        texts, labels = load_split(os.path.join(a.data, f"judge_{split}.jsonl"))
        ds = Dataset.from_dict({"text": texts, "label": labels})
        return ds.map(lambda b: tok(b["text"], truncation=True, max_length=a.maxlen),
                      batched=True)

    train_ds, val_ds, test_ds = prep("train"), prep("val"), prep("test")

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16,
                             bnb_4bit_use_double_quant=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        a.base, num_labels=2, quantization_config=bnb, device_map="auto")
    model.config.pad_token_id = tok.pad_token_id
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    lora = LoraConfig(task_type="SEQ_CLS", r=a.r, lora_alpha=a.alpha,
                      lora_dropout=a.dropout, target_modules="all-linear")
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    def metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        p, r, f1, _ = precision_recall_fscore_support(labels, preds, average=None,
                                                      labels=[0, 1], zero_division=0)
        return {"acc": accuracy_score(labels, preds),
                "leak_recall": r[1], "leak_precision": p[1], "leak_f1": f1[1],
                "safe_recall": r[0]}

    args = TrainingArguments(
        output_dir=a.outdir, num_train_epochs=a.epochs, learning_rate=a.lr,
        per_device_train_batch_size=a.bs, per_device_eval_batch_size=a.bs,
        gradient_accumulation_steps=a.grad_accum, bf16=True,
        optim="paged_adamw_8bit", gradient_checkpointing=True,
        eval_strategy="epoch", save_strategy="epoch", logging_steps=5,
        load_best_model_at_end=True, metric_for_best_model="leak_f1",
        report_to="none")
    trainer = Trainer(model=model, args=args, train_dataset=train_ds,
                      eval_dataset=val_ds, compute_metrics=metrics,
                      data_collator=DataCollatorWithPadding(tok))
    trainer.train()

    print("VAL:", trainer.evaluate(val_ds))
    print("TEST:", trainer.evaluate(test_ds))
    model.save_pretrained(a.outdir)
    tok.save_pretrained(a.outdir)
    json.dump({"base_model": a.base, "num_labels": 2, "maxlen": a.maxlen},
              open(os.path.join(a.outdir, "judge_meta.json"), "w"), indent=2)

    # dump raw val/test logits for calibrate.py (temperature scaling)
    for split, ds in (("val", val_ds), ("test", test_ds)):
        out = trainer.predict(ds)
        np.savez(os.path.join(a.outdir, f"logits_{split}.npz"),
                 logits=out.predictions, labels=out.label_ids)
    print(f"saved adapter + logits -> {a.outdir}")


if __name__ == "__main__":
    main()
