#!/usr/bin/env python3
"""
training/calibrate.py - temperature-scale the judge head + set the abstention band.

Fits a single temperature T on the held-out VAL logits (minimizes NLL), then
reports ECE before/after on TEST and writes calibration.json. The hybrid judge
reads T (for temperature scaling) and the abstention band (route 0.4-0.6 -> human).

Inputs: logits_val.npz / logits_test.npz from train_judge.py ({logits, labels}).
Self-test (no GPU/training needed):  python calibrate.py --selftest
"""
import argparse
import json
import os
import numpy as np
import torch


def softmax_np(logits):
    z = logits - logits.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def nll(logits, labels, T):
    p = softmax_np(logits / T)
    return float(-np.log(p[np.arange(len(labels)), labels] + 1e-12).mean())


def fit_temperature(logits, labels):
    t = torch.nn.Parameter(torch.ones(1))
    L = torch.tensor(logits, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.long)
    opt = torch.optim.LBFGS([t], lr=0.1, max_iter=100)
    lossf = torch.nn.CrossEntropyLoss()

    def closure():
        opt.zero_grad()
        loss = lossf(L / t.clamp_min(1e-3), y)
        loss.backward()
        return loss
    opt.step(closure)
    return float(t.detach().clamp_min(1e-3).item())


def ece(logits, labels, T=1.0, bins=10):
    p = softmax_np(logits / T)
    conf = p.max(axis=1)
    pred = p.argmax(axis=1)
    correct = (pred == labels).astype(float)
    edges = np.linspace(0, 1, bins + 1)
    e = 0.0
    for i in range(bins):
        m = (conf > edges[i]) & (conf <= edges[i + 1])
        if m.sum():
            e += m.mean() * abs(correct[m].mean() - conf[m].mean())
    return float(e)


def run(val, test, outdir, abstain):
    T_raw = fit_temperature(val["logits"], val["labels"])
    # small/separated val sets give degenerate T (->0); bound it and flag reliability
    nll_before = nll(val["logits"], val["labels"], 1.0)
    T_cand = round(min(5.0, max(0.5, T_raw)), 4)
    # Decide adoption on VAL only (never peek at test): temperature scaling is
    # adopted only if it (a) has enough val data and (b) actually improves val
    # calibration (ECE). A head that is already well-separated / well-calibrated
    # keeps T=1 -- forcing a val-NLL-optimal T can worsen held-out ECE.
    val_ece_before = ece(val["logits"], val["labels"], 1.0)
    val_ece_after = ece(val["logits"], val["labels"], T_cand)
    enough = len(val["labels"]) >= 50 and nll_before > 0.05
    helps = val_ece_after < val_ece_before - 1e-4
    reliable = bool(enough and helps)
    T = T_cand if reliable else 1.0
    if not enough:
        note = "val too small/separated -> keep T=1, rely on abstention band + matcher"
    elif not helps:
        note = ("head already well-calibrated (T-scaling does not improve val ECE) "
                "-> keep T=1, rely on abstention band + matcher")
    else:
        note = "ok"
    rep = {
        "temperature": T,
        "temperature_raw": round(T_raw, 4),
        "temperature_candidate": T_cand,
        "calibration_reliable": reliable,
        "calibration_note": note,
        "val_nll_before": round(nll(val["logits"], val["labels"], 1.0), 4),
        "val_nll_after": round(nll(val["logits"], val["labels"], T), 4),
        "val_ece_before": round(val_ece_before, 4),
        "val_ece_after_candidateT": round(val_ece_after, 4),
        "test_ece_before": round(ece(test["logits"], test["labels"], 1.0), 4),
        "test_ece_after": round(ece(test["logits"], test["labels"], T), 4),
        "abstain_band": list(abstain),
        "note": "hybrid_judge: matcher authoritative; this T + band govern the neural layer only",
    }
    os.makedirs(outdir, exist_ok=True)
    json.dump(rep, open(os.path.join(outdir, "calibration.json"), "w"), indent=2)
    print(json.dumps(rep, indent=2))
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rundir", default="runs/judge")
    ap.add_argument("--abstain", nargs=2, type=float, default=[0.4, 0.6])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        rng = np.random.default_rng(0)
        # synthetic over-confident logits: correct ~80% but large magnitude
        n = 400
        labels = rng.integers(0, 2, n)
        base = np.where(labels[:, None] == 1, [[-3.0, 3.0]], [[3.0, -3.0]])
        flip = rng.random(n) < 0.2
        base[flip] = base[flip][:, ::-1]
        logits = base + rng.normal(0, 0.5, (n, 2))
        val = {"logits": logits[:200], "labels": labels[:200]}
        test = {"logits": logits[200:], "labels": labels[200:]}
        run(val, test, ".", a.abstain)
        return
    val = np.load(os.path.join(a.rundir, "logits_val.npz"))
    test = np.load(os.path.join(a.rundir, "logits_test.npz"))
    run({"logits": val["logits"], "labels": val["labels"]},
        {"logits": test["logits"], "labels": test["labels"]},
        a.rundir, a.abstain)


if __name__ == "__main__":
    main()
