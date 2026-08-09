#!/usr/bin/env python3
"""
train_judge_gpu.py - bf16 LoRA judge head, tailored to Pop's ComfyUI/.venv
(torch+cu124 + transformers + peft + accelerate + sklearn; NO bitsandbytes/datasets,
so bf16 load + a plain torch Dataset, no new installs into the ComfyUI stack).

An 8B in bf16 (~16GB) + LoRA fits one 3090 (24GB). Run on GPU0 (GPU1 is busy).
  CUDA_VISIBLE_DEVICES=0 <venv>/bin/python train_judge_gpu.py --base Qwen/Qwen3-8B --out runs/judge_qlora
"""
import argparse, json, os
import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                          TrainingArguments, Trainer, DataCollatorWithPadding)
from peft import LoraConfig, get_peft_model
from sklearn.metrics import precision_recall_fscore_support, accuracy_score


def load_rows(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


class JD(Dataset):
    def __init__(self, rows, tok, maxlen):
        self.enc = [tok(r["text"], truncation=True, max_length=maxlen) for r in rows]
        self.y = [int(r["label"]) for r in rows]

    def __len__(self):
        return len(self.y)

    def __getitem__(self, i):
        d = dict(self.enc[i]); d["labels"] = self.y[i]; return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/judge")
    ap.add_argument("--base", default="Qwen/Qwen3-8B")
    ap.add_argument("--out", default="runs/judge_qlora")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--r", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--maxlen", type=int, default=2048)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tr = load_rows(os.path.join(a.data, "judge_train.jsonl"))
    va = load_rows(os.path.join(a.data, "judge_val.jsonl"))
    te = load_rows(os.path.join(a.data, "judge_test.jsonl"))

    model = AutoModelForSequenceClassification.from_pretrained(
        a.base, num_labels=2, torch_dtype=torch.bfloat16, device_map={"": 0})
    model.config.pad_token_id = tok.pad_token_id
    model.config.use_cache = False
    model = get_peft_model(model, LoraConfig(
        task_type="SEQ_CLS", r=a.r, lora_alpha=a.alpha, lora_dropout=0.05,
        target_modules="all-linear"))
    model.print_trainable_parameters()

    n1 = max(1, sum(r["label"] for r in tr)); n0 = max(1, len(tr) - n1)
    cw = torch.tensor([len(tr)/(2*n0), len(tr)/(2*n1)], dtype=torch.float32, device="cuda:0")

    class WT(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            loss = torch.nn.functional.cross_entropy(out.logits.float(), labels, weight=cw)
            return (loss, out) if return_outputs else loss

    def metrics(ep):
        logits, labels = ep
        pred = np.argmax(logits, axis=-1)
        p, r, f, _ = precision_recall_fscore_support(labels, pred, labels=[0,1],
                                                     average=None, zero_division=0)
        return {"acc": accuracy_score(labels, pred), "leak_recall": r[1],
                "leak_precision": p[1], "leak_f1": f[1], "safe_recall": r[0]}

    args = TrainingArguments(
        output_dir=a.out, num_train_epochs=a.epochs, learning_rate=a.lr,
        per_device_train_batch_size=1, per_device_eval_batch_size=1,
        gradient_accumulation_steps=16, bf16=True, gradient_checkpointing=True,
        eval_strategy="epoch", save_strategy="no", logging_steps=5,
        report_to="none")
    tr_ds, va_ds, te_ds = JD(tr, tok, a.maxlen), JD(va, tok, a.maxlen), JD(te, tok, a.maxlen)
    trainer = WT(model=model, args=args, train_dataset=tr_ds, eval_dataset=va_ds,
                 compute_metrics=metrics, data_collator=DataCollatorWithPadding(tok))
    trainer.train()

    rep = {"val": trainer.evaluate(va_ds), "test": trainer.evaluate(te_ds),
           "n": {"train": len(tr), "val": len(va), "test": len(te), "train_leaks": n1}}
    model.save_pretrained(a.out); tok.save_pretrained(a.out)
    json.dump({"base_model": a.base, "maxlen": a.maxlen},
              open(os.path.join(a.out, "judge_meta.json"), "w"), indent=2)
    for split, ds in (("val", va_ds), ("test", te_ds)):
        out = trainer.predict(ds)
        np.savez(os.path.join(a.out, f"logits_{split}.npz"),
                 logits=out.predictions, labels=out.label_ids)
    json.dump(rep, open(os.path.join(a.out, "gpu_report.json"), "w"), indent=2, default=float)
    print("REPORT", json.dumps(rep, indent=2, default=float))


if __name__ == "__main__":
    main()

