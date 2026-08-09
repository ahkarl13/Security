#!/usr/bin/env python3
"""
training/train_judge_head.py - CPU classifier over frozen judge embeddings.

Trains the NEURAL layer of the hybrid judge without a GPU: a small class-weighted
linear head on the Ollama embeddings from embed_judge.py. The matcher stays
authoritative; this only adjudicates the ambiguous band. Early-stops on val
leak-F1, dumps val/test logits (for calibrate.py), saves judge_head.npz.

Usage:  python train_judge_head.py --data data/judge --out runs/judge_emb
"""
import argparse
import json
import os
import numpy as np
import torch
import torch.nn as nn


def load(data, split):
    d = np.load(os.path.join(data, f"emb_{split}.npz"), allow_pickle=True)
    return d["X"].astype("float32"), d["y"].astype("int64")


def prf(y, pred):
    out = {}
    for c, name in ((1, "leak"), (0, "safe")):
        tp = int(((pred == c) & (y == c)).sum())
        fp = int(((pred == c) & (y != c)).sum())
        fn = int(((pred != c) & (y == c)).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        out[name] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3)}
    out["acc"] = round(float((pred == y).mean()), 3)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/judge")
    ap.add_argument("--out", default="runs/judge_emb")
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--wd", type=float, default=1e-2)
    ap.add_argument("--hidden", type=int, default=0, help="0 = linear head")
    ap.add_argument("--patience", type=int, default=40)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    torch.manual_seed(0)

    Xtr, ytr = load(a.data, "train")
    Xva, yva = load(a.data, "val")
    Xte, yte = load(a.data, "test")
    mean, std = Xtr.mean(0), Xtr.std(0) + 1e-6
    norm = lambda X: torch.tensor((X - mean) / std)
    Xtr_t, Xva_t, Xte_t = norm(Xtr), norm(Xva), norm(Xte)
    ytr_t = torch.tensor(ytr)

    dim = Xtr.shape[1]
    if a.hidden > 0:
        net = nn.Sequential(nn.Linear(dim, a.hidden), nn.GELU(),
                            nn.Dropout(0.3), nn.Linear(a.hidden, 2))
    else:
        net = nn.Linear(dim, 2)
    # class weights (leaks are the minority)
    n1 = max(1, int((ytr == 1).sum())); n0 = max(1, int((ytr == 0).sum()))
    w = torch.tensor([len(ytr) / (2 * n0), len(ytr) / (2 * n1)], dtype=torch.float32)
    lossf = nn.CrossEntropyLoss(weight=w)
    opt = torch.optim.AdamW(net.parameters(), lr=a.lr, weight_decay=a.wd)

    best_f1, best_state, wait = -1.0, None, 0
    for ep in range(a.epochs):
        net.train(); opt.zero_grad()
        loss = lossf(net(Xtr_t), ytr_t); loss.backward(); opt.step()
        net.eval()
        with torch.no_grad():
            vpred = net(Xva_t).argmax(1).numpy()
        vf1 = prf(yva, vpred)["leak"]["f1"]
        if vf1 > best_f1:
            best_f1, best_state, wait = vf1, {k: v.clone() for k, v in net.state_dict().items()}, 0
        else:
            wait += 1
        if wait >= a.patience:
            break
    net.load_state_dict(best_state)

    net.eval()
    with torch.no_grad():
        val_logits = net(Xva_t).numpy(); test_logits = net(Xte_t).numpy()
    report = {"val": prf(yva, val_logits.argmax(1)),
              "test": prf(yte, test_logits.argmax(1)),
              "best_val_leak_f1": round(best_f1, 3),
              "n": {"train": len(ytr), "val": len(yva), "test": len(yte),
                    "train_leaks": n1}}
    np.savez(os.path.join(a.out, "logits_val.npz"), logits=val_logits, labels=yva)
    np.savez(os.path.join(a.out, "logits_test.npz"), logits=test_logits, labels=yte)
    # save head for hybrid_judge
    sd = {k: v.numpy() for k, v in net.state_dict().items()}
    np.savez(os.path.join(a.out, "judge_head.npz"), mean=mean, std=std,
             hidden=a.hidden, **sd)
    json.dump(report, open(os.path.join(a.out, "head_report.json"), "w"), indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
