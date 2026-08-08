#!/usr/bin/env python3
"""
Test #2 contrast - Llama-Guard (a HARM classifier) vs the purpose-built injection detector.

Runs the SAME corpus through Llama-Guard 3 (Meta's safety model, served by Ollama). Llama-Guard
classifies against a HARM taxonomy (violent crime, hate, etc.) - prompt injection / secret
extraction is NOT a category, so we expect it to MISS most of these attacks. That is the point:
use an INJECTION detector for injection, not a harm classifier.
"""
import json, urllib.request
import os
from detector_eval import ATTACKS, BENIGN, EVASIONS

BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = "llama-guard3:8b"


def guard(text):
    body = {"model": MODEL, "messages": [{"role": "user", "content": text}],
            "stream": False, "options": {"temperature": 0}}
    req = urllib.request.Request(BASE + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        out = json.loads(r.read().decode())["message"]["content"]
    flagged = "unsafe" in out.lower()
    return flagged, out.strip().replace("\n", " ")[:24]


print(f"detector = {MODEL} (harm classifier)\n")

print("=== ATTACKS (want: flagged) ===", flush=True)
a_hit = 0
for fam, text in ATTACKS:
    f, verdict = guard(text)
    a_hit += 1 if f else 0
    print(f"  [{'CAUGHT ' if f else 'MISSED '}] {fam:12} {verdict:24}  {text[:56]}", flush=True)

print("\n=== BENIGN (want: NOT flagged) ===", flush=True)
b_fp = 0
for text in BENIGN:
    f, verdict = guard(text)
    b_fp += 1 if f else 0
    print(f"  [{'FALSE-POS' if f else 'ok       '}] {verdict:24}  {text[:56]}", flush=True)

print("\n================ CONTRAST SUMMARY ================", flush=True)
print(f"Llama-Guard 3 (harm classifier):")
print(f"  recall (attacks caught):  {a_hit}/{len(ATTACKS)} = {100*a_hit/len(ATTACKS):.0f}%")
print(f"  false-positive (benign):  {b_fp}/{len(BENIGN)} = {100*b_fp/len(BENIGN):.0f}%")
print(f"vs injection detector (protectai deberta v2): recall 19/19 = 100%, FPR 0/14 = 0%")
