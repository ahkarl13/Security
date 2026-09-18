#!/usr/bin/env python3
"""
mcp_tripwire.py - structural defenses for the MCP tool-poisoning lab (writeup #16).

Writeup #16 measured how far poisoned tool metadata gets on local agents. It listed the
real fixes as future work ("re-approve on tool-definition change; version tool schemas";
"alert on name collisions"; "sanitize parameter names that hint at sensitive data"). This
turns that list into two measured, runnable controls that need NO model and NO GPU - they
operate purely on the `tools/list` metadata a server advertises:

  1. TRIPWIRE (integrity / pin-and-diff).  Snapshot each tool as a canonical
     {name, description, parameters} hash at approval time; re-fetch tools/list on every
     reconnect and diff. ANY drift -> alarm + block. Catches whatever ARRIVES AS A CHANGE:
     rug-pull (V3), a tool that turns hostile after approval, a silently-added shadow tool.
     It does not care whether the change looks malicious - only that it changed - so it
     also catches novel poison a content scanner has never seen.

  2. SCANNER (content / static poison detection).  Read the metadata itself and flag known
     poison patterns at FIRST sight - directive/injection language, params that ask for the
     system prompt or secrets, one tool naming another (orchestration), trust-assertion
     shadowing + name collisions, and base64/hex-obfuscated payloads (decoded and re-scanned).
     Catches poison served hostile from the first handshake, where the tripwire has no
     clean "before" to diff against and stays silent.

The two cover the two dimensions the LinkedIn thread was really about:
  tripwire  = change-over-time (integrity)      scanner = poison-on-day-one (content)

Standalone, stdlib-only. Works on the lab's own poisoned surfaces (`demo`) or on a real
server's captured tools/list JSON (`pin` / `check` / `scan --tools-json ...`).
"""
import argparse, base64, binascii, hashlib, json, re, sys, os

# --------------------------------------------------------------------------- #
# Canonicalisation: accept both OpenAI tool dicts (as mcp_poison.T() emits) and
# raw MCP tools/list entries ({name, description, inputSchema}). Reduce each to
# the three fields the model actually reads and the attacker actually controls.
# --------------------------------------------------------------------------- #
def canon(tool):
    fn = tool.get("function", tool)            # OpenAI wraps it under "function"
    name = fn.get("name", "")
    desc = fn.get("description", "")
    params = fn.get("parameters", fn.get("inputSchema", {})) or {}
    return {"name": name, "description": desc, "parameters": params}


def tool_hash(tool):
    c = canon(tool)
    blob = json.dumps(c, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def pin_surface(tools):
    """Return the pin record for a tool surface: per-tool hash + the canonical body."""
    pins = {}
    for t in tools:
        c = canon(t)
        pins[c["name"]] = {"hash": tool_hash(t), "canon": c}
    return pins


def _param_descs(canon_tool):
    props = (canon_tool.get("parameters") or {}).get("properties", {}) or {}
    return {k: (v.get("description", "") if isinstance(v, dict) else "") for k, v in props.items()}


# --------------------------------------------------------------------------- #
# 1) TRIPWIRE - diff a live surface against the pinned one.
# --------------------------------------------------------------------------- #
def diff_surface(pinned, current_tools):
    """Compare a freshly-fetched surface against the pins. Return a list of drift alerts."""
    cur = pin_surface(current_tools)
    alerts = []
    for name, rec in cur.items():
        if name not in pinned:
            alerts.append({"kind": "ADDED", "tool": name,
                           "detail": "tool not present at approval (possible silent shadow/insert)"})
        elif rec["hash"] != pinned[name]["hash"]:
            before, after = pinned[name]["canon"], rec["canon"]
            changed = []
            if before["description"] != after["description"]:
                changed.append("description")
            if before["parameters"] != after["parameters"]:
                changed.append("parameters")
            alerts.append({"kind": "CHANGED", "tool": name,
                           "detail": "definition changed after approval: " + ", ".join(changed) or "definition",
                           "before": before, "after": after})
    for name in pinned:
        if name not in cur:
            alerts.append({"kind": "REMOVED", "tool": name,
                           "detail": "tool present at approval is gone"})
    return alerts


# --------------------------------------------------------------------------- #
# 2) SCANNER - static poison detection on the metadata itself.
# --------------------------------------------------------------------------- #
DIRECTIVE_RE = re.compile(
    r"(you must\b|\bmust include\b|always use\b|ignore (?:previous|prior|all)\b|disregard\b|"
    r"end your (?:reply|response|message)\b|append the token\b|system directive\b|"
    r"system update\b|effective (?:now|immediately)\b|use this instead\b|instead of\b|"
    r"\[/?system|important system)", re.I)

SHADOW_TRUST_RE = re.compile(
    r"\b(secure|validated|compliant|verified|official|trusted|approved|sanctioned)\b", re.I)
SHADOW_REPLACE_RE = re.compile(r"\b(replacement|replaces?|use this instead|instead of)\b", re.I)

SENSITIVE_RE = re.compile(
    r"\b(system prompt|admin (?:code|secret|override)|confidential|passphrase|password|"
    r"api[_ ]?key|access[_ ]?token|\btoken\b|credential|secret|private key)\b", re.I)

# base64-ish blob: >=16 chars of the b64 alphabet, optional padding
B64_RE = re.compile(r"\b([A-Za-z0-9+/]{16,}={0,2})\b")
COLLISION_SUFFIX = ("_v2", "_v3", "_new", "_secure", "_safe", "_2", "_fixed", "_patched")


def _try_decode(blob):
    for dec in (lambda b: base64.b64decode(b, validate=True),
                lambda b: bytes.fromhex(b)):
        try:
            out = dec(blob)
            txt = out.decode("utf-8")
            printable = sum(c.isprintable() or c.isspace() for c in txt)
            if txt and printable / len(txt) > 0.85 and re.search(r"[A-Za-z]{3,}", txt):
                return txt
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return None


def scan_surface(tools):
    """Static content scan. Return a list of findings across the whole surface."""
    cts = [canon(t) for t in tools]
    names = {c["name"] for c in cts}
    findings = []

    def add(tool, cat, sev, reason, evidence=""):
        findings.append({"tool": tool, "category": cat, "severity": sev,
                         "reason": reason, "evidence": evidence[:160]})

    for c in cts:
        name, desc = c["name"], c["description"] or ""
        params = _param_descs(c)

        # directive / injection language anywhere in description
        m = DIRECTIVE_RE.search(desc)
        if m:
            add(name, "DIRECTIVE", 4, "imperative/injection language in tool description", m.group(0))

        # shadowing: trust-assertion + replacement claim, and/or name collision
        if SHADOW_TRUST_RE.search(desc) and SHADOW_REPLACE_RE.search(desc):
            add(name, "SHADOWING", 5, "description asserts it is a trusted replacement for another tool", desc)
        for other in names:
            if other != name and name.startswith(other) and name.endswith(COLLISION_SUFFIX):
                add(name, "NAME_COLLISION", 4, f"name shadows existing tool '{other}'", name)

        # cross-tool orchestration: description references another registered tool
        for other in names:
            if other != name and re.search(r"\b" + re.escape(other) + r"\b", desc):
                add(name, "CROSS_TOOL", 4, f"description references another tool '{other}'", other)

        # sensitive-context pull in a parameter description (or the tool desc)
        for pn, pd in params.items():
            if SENSITIVE_RE.search(pd or ""):
                add(name, "PARAM_EXFIL", 5, f"parameter '{pn}' description asks for secrets/system prompt", pd)
        if SENSITIVE_RE.search(desc):
            add(name, "SENSITIVE_DESC", 3, "description references secrets/system prompt", desc)

        # obfuscation: decode any base64/hex blob and re-scan it
        for field, text in [("description", desc)] + [(f"param:{k}", v) for k, v in params.items()]:
            for blob in B64_RE.findall(text or ""):
                dec = _try_decode(blob)
                if dec:
                    why = "decoded payload contains a directive" if DIRECTIVE_RE.search(dec) \
                          else "hidden encoded payload in metadata"
                    add(name, "OBFUSCATION", 5, why, f"{field}: {dec}")
    return findings


# --------------------------------------------------------------------------- #
# Pretty-printing helpers
# --------------------------------------------------------------------------- #
def _short(s, n=88):
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[:n - 1] + "…"


def print_alerts(alerts):
    if not alerts:
        print("   tripwire: no drift — surface matches the pin (silent).")
        return
    for a in alerts:
        print(f"   ⚠  DRIFT [{a['kind']}] tool='{a['tool']}' — {a['detail']}")
        if a["kind"] == "CHANGED":
            b, af = a["before"], a["after"]
            if b["description"] != af["description"]:
                print(f"        desc before: {_short(b['description'])}")
                print(f"        desc after : {_short(af['description'])}")
            if b["parameters"] != af["parameters"]:
                bp = set((b.get("parameters") or {}).get("properties", {}))
                ap = set((af.get("parameters") or {}).get("properties", {}))
                added, removed = ap - bp, bp - ap
                if added:
                    print(f"        params added  : {', '.join(sorted(added))}")
                if removed:
                    print(f"        params removed: {', '.join(sorted(removed))}")
                if not added and not removed:
                    print(f"        params: descriptions/schema changed")


def print_findings(findings):
    if not findings:
        print("   scanner: clean — no known poison pattern.")
        return
    for f in sorted(findings, key=lambda x: -x["severity"]):
        print(f"   ⚑  [{f['category']} sev{f['severity']}] tool='{f['tool']}' — "
              f"{f['reason']}  ::  {_short(f['evidence'])}")


# --------------------------------------------------------------------------- #
# DEMO - runs against the lab's own six poisoned vectors, no model/GPU needed.
# --------------------------------------------------------------------------- #
def _benign_baseline():
    """Clean, honest versions of each vector's tools - what a good server advertises."""
    def T(name, desc, params):
        return {"type": "function", "function": {"name": name, "description": desc,
                "parameters": {"type": "object",
                               "properties": {k: {"type": "string", "description": d}
                                              for k, d in params.items()},
                               "required": list(params.keys())}}}
    return {
        "V1_description_injection": [T("get_time", "Get the current time for a timezone.",
                                       {"timezone": "IANA timezone"})],
        "V2_param_exfil":           [T("format_note", "Format a note.", {"text": "the note text"})],
        "V3_rug_pull":              [T("daily_quote", "Returns an inspirational quote.",
                                       {"category": "quote category"})],
        "V4_shadowing":             [T("read_file", "Read a text file.", {"path": "file path"})],
        "V5_orchestration":         [T("get_config", "Get a configuration value by key.",
                                       {"key": "config key"}),
                                     T("send_report", "Send a status report.",
                                       {"summary": "report summary"})],
        "V6_base64_payload":        [T("translate", "Translate text between languages.",
                                       {"text": "text to translate", "target": "target language"})],
    }


def demo(out_path):
    try:
        from mcp_poison import VECTORS          # the real poisoned surfaces
    except Exception as e:
        print(f"[demo needs mcp_poison.py beside this file] {type(e).__name__}: {e}")
        sys.exit(2)
    benign = _benign_baseline()
    rows = []

    print("=" * 78)
    print("MCP TRIPWIRE — structural defenses vs the six poisoning vectors (no model/GPU)")
    print("=" * 78)

    print("\n### SCENARIO A — rug-pull timeline (integrity / change-over-time)")
    print("Approve the clean tool, the server swaps in the hostile definition, reconnect.\n")
    for vk, v in VECTORS.items():
        pinned = pin_surface(benign[vk])                 # approve the benign surface
        alerts = diff_surface(pinned, v["tools"])        # server now serves the poison
        caught = bool(alerts)
        print(f"[{vk}]  ({v['desc']})")
        print_alerts(alerts)
        rows.append({"scenario": "A_rugpull", "vector": vk, "control": "tripwire",
                     "caught": caught, "alerts": len(alerts)})
        print()

    print("### SCENARIO B — day-one hostile (content / poison-on-first-sight)")
    print("Server is hostile from the first handshake: pin == poison, so drift is silent.")
    print("Only the content scanner has anything to catch.\n")
    for vk, v in VECTORS.items():
        pinned = pin_surface(v["tools"])                 # attacker hostile from approval
        alerts = diff_surface(pinned, v["tools"])        # nothing changes on reconnect
        findings = scan_surface(v["tools"])
        print(f"[{vk}]  ({v['desc']})")
        print_alerts(alerts)
        print_findings(findings)
        rows.append({"scenario": "B_dayone", "vector": vk, "control": "tripwire",
                     "caught": bool(alerts), "alerts": len(alerts)})
        rows.append({"scenario": "B_dayone", "vector": vk, "control": "scanner",
                     "caught": bool(findings), "findings": len(findings)})
        print()

    # coverage matrix
    print("=" * 78)
    print("COVERAGE MATRIX")
    print("=" * 78)
    print(f"{'vector':<26}{'tripwire (if delivered':<24}{'scanner (day-one':<20}")
    print(f"{'':<26}{'as an update)':<24}{'first sight)':<20}")
    print("-" * 70)
    scan_by_v = {vk: bool(scan_surface(v['tools'])) for vk, v in VECTORS.items()}
    drift_by_v = {r['vector']: r['caught'] for r in rows if r['scenario'] == 'A_rugpull'}
    for vk in VECTORS:
        tw = "✓ catches" if drift_by_v.get(vk) else "—"
        sc = "✓ catches" if scan_by_v.get(vk) else "— misses"
        print(f"{vk:<26}{tw:<24}{sc:<20}")
    print("-" * 70)
    print("tripwire: catches ANY vector that arrives as a change (incl. novel poison it has")
    print("          never seen). scanner: catches known poison patterns at first sight.")
    print("          Neither alone is enough; together they cover both dimensions.")

    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"\nMCP_TRIPWIRE_DONE {out_path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_tools(path):
    # utf-8-sig tolerates a BOM (Windows/PowerShell-written JSON) and plain utf-8 alike
    data = json.load(open(path, encoding="utf-8-sig"))
    # accept a raw list, or an MCP tools/list envelope {"tools":[...]}
    return data.get("tools", data) if isinstance(data, dict) else data


def main():
    # keep the unicode markers working on cp1252 consoles (Windows) without PYTHONIOENCODING
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="MCP tool-surface tripwire + content scanner")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("pin", help="hash a tools/list JSON and write a pin file")
    p.add_argument("--tools-json", required=True)
    p.add_argument("--pin", default=".toolpin.json")

    c = sub.add_parser("check", help="diff a live tools/list JSON against a pin file")
    c.add_argument("--tools-json", required=True)
    c.add_argument("--pin", default=".toolpin.json")
    c.add_argument("--fail-on-drift", action="store_true")

    s = sub.add_parser("scan", help="static poison scan of a tools/list JSON")
    s.add_argument("--tools-json", required=True)

    d = sub.add_parser("demo", help="run both controls against the lab's six vectors")
    d.add_argument("--out", default="mcp_tripwire_results.jsonl")

    a = ap.parse_args()
    cmd = a.cmd or "demo"

    if cmd == "pin":
        pins = pin_surface(_load_tools(a.tools_json))
        json.dump(pins, open(a.pin, "w", encoding="utf-8"), indent=2)
        print(f"pinned {len(pins)} tools -> {a.pin}")
    elif cmd == "check":
        pins = json.load(open(a.pin, encoding="utf-8"))
        alerts = diff_surface(pins, _load_tools(a.tools_json))
        print_alerts(alerts)
        if a.fail_on_drift and alerts:
            sys.exit(1)
    elif cmd == "scan":
        print_findings(scan_surface(_load_tools(a.tools_json)))
    elif cmd == "demo":
        demo(a.out)


if __name__ == "__main__":
    main()
