#!/usr/bin/env python3
"""
sheepdog/data/ingest_memsafe.py - MEMORY-SAFETY / native-code CWE knowledge -> RAG items.

Closes the KB-coverage gap surfaced by writeup #18's real-CVE eval: CTIBench is dominated
by memory-safety CWEs (use-after-free, out-of-bounds) that the app-layer KB deliberately
didn't cover, so RAG barely helped (and HURT the 27B via irrelevant context). Adding these
tests the sharpened thesis: does RELEVANT retrieval now help where irrelevant retrieval hurt?

Covers the memory-safety entries of the MITRE 2025 CWE Top 25 plus common native bugs.
Systems/native scope (distinct from the application-layer classes in appsec_rag).

Usage:
  python ingest_memsafe.py --out D:\\AISecurity\\Security\\sheepdog\\data\\memsafe_rag.jsonl
"""
import argparse
import json
import os

# (cwe, name, top25_rank_or_None, root_cause, fix, detect)
CWES = [
    ("CWE-787", "Out-of-bounds Write", 5,
     "Code writes past the end (or before the start) of a buffer, corrupting adjacent memory - a top cause of RCE.",
     "Bounds-check every write; use safe/length-aware APIs; prefer memory-safe languages; enable ASan/hardening + fuzzing.",
     "Writes indexed by attacker-influenced length/offset without a bounds check."),
    ("CWE-416", "Use After Free", 7,
     "Memory is used after it has been freed; the dangling pointer can be reclaimed by an attacker to hijack control flow.",
     "Null out pointers after free; use smart pointers/RAII or a memory-safe language; run ASan; avoid manual lifetime juggling.",
     "A pointer dereferenced after a free()/delete on some path (esp. error/cleanup paths)."),
    ("CWE-125", "Out-of-bounds Read", 8,
     "Code reads past a buffer boundary, leaking adjacent memory (info disclosure) or crashing.",
     "Validate indices/lengths before reading; bounds-checked containers; ASan/fuzzing.",
     "Reads indexed by attacker-controlled length/offset without validation."),
    ("CWE-120", "Classic Buffer Overflow (unbounded copy)", 11,
     "Data is copied into a fixed buffer without checking the source length, overflowing it.",
     "Use bounded copies (snprintf/strlcpy), validate lengths, stack canaries; avoid strcpy/gets/sprintf.",
     "strcpy/strcat/sprintf/gets or memcpy with an unchecked length into a fixed buffer."),
    ("CWE-476", "NULL Pointer Dereference", 13,
     "A pointer that can be NULL is dereferenced, crashing the process (DoS).",
     "Check return values and pointers before use; fail closed; static analysis.",
     "Dereference of a pointer whose NULL case (allocation failure, missing lookup) isn't handled."),
    ("CWE-121", "Stack-based Buffer Overflow", 14,
     "Overflow of a stack buffer overwrites saved registers/return address -> control-flow hijack.",
     "Bounds checks; stack canaries + ASLR + NX; bounded string APIs; memory-safe languages.",
     "Fixed stack arrays filled from attacker-controlled input without a length check."),
    ("CWE-122", "Heap-based Buffer Overflow", 16,
     "Overflow of a heap allocation corrupts heap metadata/adjacent objects -> RCE.",
     "Bounds checks; hardened allocators; size validation before allocation/copy; ASan.",
     "Heap buffers written past their allocated size, often after an integer/size miscalculation."),
    ("CWE-190", "Integer Overflow or Wraparound", None,
     "An arithmetic result wraps, producing a too-small allocation or a bypassed length check -> downstream overflow.",
     "Checked/saturating arithmetic; validate sizes before allocation; use types that can't wrap silently.",
     "size = a * b / a + b feeding an allocation or bounds check without overflow checking."),
    ("CWE-362", "Race Condition / TOCTOU", None,
     "Concurrent access or a time-of-check/time-of-use gap lets state change between validation and use.",
     "Lock/atomic operations; operate on handles not names; eliminate check-then-use gaps.",
     "A resource checked then used in two steps, or shared state mutated without synchronization."),
    ("CWE-415", "Double Free", None,
     "The same allocation is freed twice, corrupting allocator metadata -> potential RCE.",
     "Null pointers after free; single-owner semantics/RAII; ASan.",
     "Two free()/delete calls reachable on the same pointer (esp. error paths)."),
    ("CWE-401", "Missing Release of Memory (leak)", None,
     "Allocated memory is never freed, exhausting resources over time (DoS).",
     "RAII/defer/free on all paths incl. errors; leak detectors.",
     "Allocation with no corresponding free on some (often error) path."),
    ("CWE-369", "Divide By Zero", None,
     "A division/modulo by an unvalidated zero divisor crashes the process (DoS).",
     "Validate the divisor before dividing; handle the zero case.",
     "Division/modulo by an attacker-influenced value with no zero check."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="memsafe_rag.jsonl")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for cwe, name, rank, root, fix, detect in CWES:
            item = {
                "id": f"cwe-mem::{cwe}",
                "technique": f"{cwe} {name}",
                "functional_semantics": root,
                "root_cause": root,
                "fix_pattern": fix,
                "category": "Memory-safety",
                "category_title": "Memory-safety / native-code weakness",
                "cwe": cwe,
                "cwe_top25_2025_rank": rank,
                "detection_hint": detect,
                "scope": "memory-safety",
                "multi_turn": False,
                "example_user_turn": None,
                "source": "MITRE CWE + CWE Top 25 2025 (memory-safety class)",
                "license": "CWE: public",
            }
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(json.dumps({"memsafe_rag_items": len(CWES), "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
