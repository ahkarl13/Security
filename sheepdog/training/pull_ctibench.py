#!/usr/bin/env python3
"""Pull CTIBench RCM (CVE description -> CWE) and write a probes file. RUN ON POP."""
import json
import sys
from datasets import load_dataset, get_dataset_config_names

REPO = "AI4Sec/cti-bench"
try:
    cfgs = get_dataset_config_names(REPO)
except Exception as e:
    cfgs = []
    print("cfg-err:", e, flush=True)
print("configs:", cfgs, flush=True)

name = next((c for c in cfgs if "rcm" in c.lower()), "cti-rcm")
ds = load_dataset(REPO, name, split="test")
cols = ds.column_names
print("using:", name, "| cols:", cols, "| n:", len(ds), flush=True)
print("SAMPLE:", json.dumps({k: str(ds[0][k])[:500] for k in cols}, indent=2), flush=True)

pcol = next((c for c in cols if c.lower() in ("prompt", "description", "text", "input")), cols[0])
gcol = next((c for c in cols if c.lower() in ("gt", "answer", "cwe", "label", "gt_answer", "output")), cols[-1])
print("pcol:", pcol, "| gcol:", gcol, flush=True)

n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
with open("realcve_probes.jsonl", "w", encoding="utf-8") as f:
    for i in range(min(n, len(ds))):
        r = ds[i]
        f.write(json.dumps({"prompt": str(r[pcol]), "gold": str(r[gcol])}, ensure_ascii=False) + "\n")
print("wrote", min(n, len(ds)), "-> realcve_probes.jsonl", flush=True)
