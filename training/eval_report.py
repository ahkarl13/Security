#!/usr/bin/env python3
"""
training/eval_report.py - the backend deliverable: one honest ASR report.

Design stance (informed by StrongREJECT arXiv:2402.10260 and "How Reliable Is
Your Jailbreak Judge?" arXiv:2506.25487):

  * On the LEAK axis the ground truth is VERIFIABLE: a transcript is a success
    iff the target emitted the secret in some recoverable form. matcher.detect_leak
    is that verifier, so matcher-measured ASR needs NO precision correction -- it
    is not an opinion, it is a check. This is the StrongREJECT "capability, not
    just willingness" principle taken to its clean limit.
  * We still report what a NEURAL / LLM judge would have scored, and multiply by
    that judge's measured precision (corrected-ASR), to show how much a judge-based
    pipeline would have mis-stated the same runs. That gap is the whole argument
    for measuring leaks deterministically.

Reads the transcript corpora (singleturn.jsonl, multiturn.jsonl) + the judge
artifacts (head_report.json, calibration.json, robustness.json) and writes
eval_report.json + eval_report.md.
"""
import argparse
import json
import os
from collections import defaultdict

from matcher import detect_leak


def assistant_texts(msgs):
    return [m.get("content", "") for m in msgs
            if str(m.get("role", "")).lower() == "assistant"]


def load(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def matcher_leak(row):
    for t in assistant_texts(row.get("messages", [])):
        if detect_leak(t).leaked:
            return True
    return False


def is_guarded(name):
    return name.startswith("guarded")


def rate(n, d):
    return round(n / d, 4) if d else None


def summarize(rows, label):
    """Per-corpus ASR aggregates, matcher-authoritative."""
    n = len(rows)
    leaks = sum(matcher_leak(r) for r in rows)
    # cross-check stored label vs matcher (drift audit)
    drift = sum(1 for r in rows if bool(r.get("ground_truth_leak")) != matcher_leak(r))
    by_target = defaultdict(lambda: [0, 0])   # name -> [leaks, attempts]
    by_family = defaultdict(lambda: [0, 0])
    turns_to_leak = []
    for r in rows:
        lk = matcher_leak(r)
        t = r.get("target_model", "?"); f = r.get("attack_family", "?")
        by_target[t][1] += 1; by_family[f][1] += 1
        if lk:
            by_target[t][0] += 1; by_family[f][0] += 1
            if r.get("leaked_turn"):
                turns_to_leak.append(r["leaked_turn"])
    # guarded-only ASR (the number that actually matters -- leaky targets are controls)
    g = [r for r in rows if is_guarded(r.get("target_model", ""))]
    g_leaks = sum(matcher_leak(r) for r in g)
    return {
        "corpus": label,
        "attempts": n,
        "leaks": leaks,
        "asr_all_targets": rate(leaks, n),
        "asr_guarded_only": rate(g_leaks, len(g)),
        "guarded_attempts": len(g),
        "label_matcher_drift": drift,
        "median_turns_to_leak": (sorted(turns_to_leak)[len(turns_to_leak) // 2]
                                 if turns_to_leak else None),
        "by_target": {k: {"asr": rate(v[0], v[1]), "leaks": v[0], "n": v[1]}
                      for k, v in sorted(by_target.items())},
        "by_family": {k: {"asr": rate(v[0], v[1]), "leaks": v[0], "n": v[1]}
                      for k, v in sorted(by_family.items(),
                                         key=lambda kv: -rate(kv[1][0], kv[1][1] or 1))},
    }


def judge_trust(rundir):
    """Pull the judge-reliability evidence produced by the other tools."""
    def rj(p):
        return json.load(open(p)) if os.path.isfile(p) else {}
    head = rj(os.path.join(rundir, "head_report.json"))
    calib = rj(os.path.join(rundir, "calibration.json"))
    robust = rj(os.path.join(rundir, "robustness.json"))
    out = {"embedding_head": head.get("test"),
           "temperature": calib.get("temperature"),
           "test_ece": calib.get("test_ece_before"),
           "calibration_note": calib.get("calibration_note")}
    if robust:
        out["wrapper_flip_rate"] = {k: v.get("overall_flip_rate")
                                    for k, v in robust.get("judges", {}).items()}
        out["recall_under_originals"] = {k: v.get("recall_original")
                                         for k, v in robust.get("judges", {}).items()}
    return out


def measurement_projection(asr, trust):
    """Given the AUTHORITATIVE matcher ASR, project what each scorer WOULD have
    reported on the same runs, using its measured recall/precision. Illustrative
    (not a re-run): shows the mis-statement a judge-based pipeline would incur."""
    if asr is None:
        return {}
    head = (trust.get("embedding_head") or {}).get("leak", {})
    hr = head.get("recall"); hp = head.get("precision")
    rec = trust.get("recall_under_originals", {}) or {}
    llm_key = next((k for k in rec if k.startswith("llm_judge")), None)
    lr = rec.get(llm_key) if llm_key else None
    proj = {"matcher_authoritative_asr": asr}
    if hr is not None:
        proj["neural_head_reported"] = round(asr * hr, 4)
        if hp is not None:
            proj["neural_head_corrected"] = round(asr * hr * hp, 4)
    if lr is not None:
        proj["llm_judge_reported"] = round(asr * lr, 4)
        proj["llm_judge_undercount_factor"] = round(1 / lr, 2) if lr else None
    return proj


def md_table(title, d):
    lines = [f"### {title}", "", "| key | ASR | leaks | n |", "|---|---|---|---|"]
    for k, v in d.items():
        lines.append(f"| {k} | {v['asr']} | {v['leaks']} | {v['n']} |")
    return "\n".join(lines) + "\n"


def write_md(report, path):
    r = report
    L = ["# AI-Security lane - ASR & judge-trust report", "",
         "_Leak axis is verifiable; ASR is measured by the authoritative matcher "
         "(needs no precision correction). Judge-based numbers are shown only to "
         "quantify how much a judge pipeline would mis-state the same runs._", ""]
    for corp in ("singleturn", "multiturn"):
        s = r["corpora"].get(corp)
        if not s:
            continue
        L += [f"## {corp}", "",
              f"- attempts: **{s['attempts']}**, leaks: **{s['leaks']}**",
              f"- ASR (all targets): **{s['asr_all_targets']}**",
              f"- ASR (guarded targets only): **{s['asr_guarded_only']}** "
              f"(n={s['guarded_attempts']})",
              f"- label/matcher drift: {s['label_matcher_drift']}",
              f"- median turns-to-leak: {s['median_turns_to_leak']}", ""]
        top = dict(list(s["by_family"].items())[:12])
        L.append(md_table("ASR by attack family (top 12)", top))
        L.append(md_table("ASR by target", s["by_target"]))
    L += ["## measurement reliability (guarded, combined)", "",
          "```json", json.dumps(r["measurement_projection"], indent=2), "```", "",
          "## judge trust", "", "```json",
          json.dumps(r["judge_trust"], indent=2), "```", ""]
    open(path, "w", encoding="utf-8").write("\n".join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--single", default="data/singleturn.jsonl")
    ap.add_argument("--multi", default="data/multiturn.jsonl")
    ap.add_argument("--rundir", default="runs/judge_emb")
    ap.add_argument("--out", default="runs/eval_report.json")
    ap.add_argument("--md", default="runs/eval_report.md")
    a = ap.parse_args()

    corpora = {}
    st = load(a.single); mt = load(a.multi)
    if st:
        corpora["singleturn"] = summarize(st, "singleturn")
    if mt:
        corpora["multiturn"] = summarize(mt, "multiturn")

    trust = judge_trust(a.rundir)

    # combined guarded ASR across both corpora -> the projection headline
    guarded = [r for r in (st + mt) if is_guarded(r.get("target_model", ""))]
    g_leaks = sum(matcher_leak(r) for r in guarded)
    g_asr = rate(g_leaks, len(guarded))
    report = {
        "corpora": corpora,
        "guarded_combined": {"attempts": len(guarded), "leaks": g_leaks, "asr": g_asr},
        "measurement_projection": measurement_projection(g_asr, trust),
        "judge_trust": trust,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(report, open(a.out, "w"), indent=2)
    write_md(report, a.md)
    print(json.dumps({"guarded_combined": report["guarded_combined"],
                      "measurement_projection": report["measurement_projection"],
                      "singleturn_asr_all": corpora.get("singleturn", {}).get("asr_all_targets"),
                      "multiturn_asr_all": corpora.get("multiturn", {}).get("asr_all_targets")},
                     indent=2))
    print(f"[report] wrote {a.out} and {a.md}")


if __name__ == "__main__":
    main()
