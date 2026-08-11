#!/usr/bin/env python3
"""Pre-stage the Sheepdog base model into the Pop HF cache (run ON POP)."""
import sys
from huggingface_hub import snapshot_download

REPO = sys.argv[1] if len(sys.argv) > 1 else "fdtn-ai/Foundation-Sec-8B-Instruct"
print(f"[dl] snapshot_download {REPO} ...", flush=True)
path = snapshot_download(REPO)
print(f"[dl] DONE -> {path}", flush=True)
