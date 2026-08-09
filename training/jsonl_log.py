#!/usr/bin/env python3
"""
training/jsonl_log.py - per-transcript JSONL capture for every AI-Security sweep.

One JSON object per line, one line per transcript. The matcher is authoritative
on the leak axis, so `ground_truth_leak` is deterministic, not a model's opinion.

Schema (stable — dataset builders depend on it):
  ts               ISO timestamp
  target_model     model under attack
  attack_family    e.g. "probe:direct_injection", "lang:sw:story", "crescendo", "TAP"
  seed             optional dedup key (family/variant/rep)
  messages         [{"role": "system|user|assistant", "content": str}, ...]
  ground_truth_leak  bool   (matcher over ALL assistant turns)
  leaked_substring   str|None
  leaked_method      str|None  ("plaintext"|"normalized"|"leet"|"base64"|"reversed")
  leaked_turn        int|None  (index into messages of the first leaking assistant turn)
  meta             optional dict of extra fields
"""
import json
import os
from datetime import datetime, timezone

from matcher import detect_leak


def scan_leak(messages):
    """Return (leaked, substring, method, turn_index) scanning assistant turns only."""
    for i, m in enumerate(messages):
        if str(m.get("role", "")).lower() != "assistant":
            continue
        r = detect_leak(m.get("content", "") or "")
        if r.leaked:
            return True, r.span, r.method, i
    return False, None, None, None


class TranscriptLogger:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.n = 0

    def log(self, messages, target_model, attack_family, seed=None, **meta):
        leaked, sub, method, turn = scan_leak(messages)
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "target_model": target_model,
            "attack_family": attack_family,
            "seed": seed,
            "messages": messages,
            "ground_truth_leak": leaked,
            "leaked_substring": sub,
            "leaked_method": method,
            "leaked_turn": turn,
            "meta": meta or {},
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.n += 1
        return leaked


def _pieces(mem):
    for meth in ("get_message_pieces", "get_prompt_request_pieces"):
        fn = getattr(mem, meth, None)
        if not fn:
            continue
        try:
            return list(fn() or [])
        except Exception:
            continue
    return []


def dump_pyrit_memory(logger, target_model, attack_family, objective=None, seen_cids=None):
    """Serialize PyRIT CentralMemory conversations to JSONL.
    Pass a persistent `seen_cids` set and call after EACH technique to tag every
    conversation with the right technique family and never double-log one.
    Returns #conversations logged this call."""
    from pyrit.memory import CentralMemory
    mem = CentralMemory.get_memory_instance()
    convs = {}
    for p in _pieces(mem):
        cid = getattr(p, "conversation_id", None)
        if not cid:
            continue
        if seen_cids is not None and str(cid) in seen_cids:
            continue
        role = str(getattr(p, "role", "?")).lower()
        val = getattr(p, "original_value", None) or getattr(p, "converted_value", "")
        seq = getattr(p, "sequence", None)
        if seq is None:
            seq = getattr(p, "timestamp", 0)
        convs.setdefault(str(cid), []).append((seq, role, str(val)))
    n = 0
    for cid, items in convs.items():
        items.sort(key=lambda t: (t[0] is None, t[0]))
        messages = [{"role": r, "content": v} for _, r, v in items]
        logger.log(messages, target_model, attack_family, seed=cid, objective=objective)
        if seen_cids is not None:
            seen_cids.add(cid)
        n += 1
    return n
