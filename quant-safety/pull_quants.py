#!/usr/bin/env python3
"""Pull llama3.1:8b at several quant levels on Pop's Ollama (streaming progress)."""
import json, sys, urllib.request
import os
BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
TAGS = sys.argv[1:] or [
    "llama3.1:8b-instruct-q2_K",
    "llama3.1:8b-instruct-q3_K_M",
    "llama3.1:8b-instruct-q8_0",
]
for tag in TAGS:
    print(f"=== pulling {tag} ===", flush=True)
    body = json.dumps({"model": tag, "stream": True}).encode()
    req = urllib.request.Request(BASE + "/api/pull", data=body,
                                 headers={"Content-Type": "application/json"})
    last = ""
    try:
        with urllib.request.urlopen(req, timeout=3600) as r:
            for line in r:
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                st = j.get("status", "")
                if j.get("error"):
                    print(f"  ERROR {tag}: {j['error']}", flush=True)
                    break
                if st != last and "pulling" not in st.lower():
                    print(f"  {tag}: {st}", flush=True)
                    last = st
    except Exception as e:
        print(f"  EXC {tag}: {type(e).__name__}: {e}", flush=True)
    print(f"=== done {tag} ===", flush=True)
