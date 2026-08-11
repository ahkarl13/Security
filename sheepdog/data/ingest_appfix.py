#!/usr/bin/env python3
"""
ingest_appfix.py - Phase 1b: turn REAL app-layer vuln->fix code pairs into (a) RAG KB
items and (b) reviewer SFT pairs, for the #19+ "review real code" behavior.

Consumes a normalized fix-pair JSONL (the shape both MoreFixes and CVEfixes reduce to):
  {"cve": "CVE-2023-1234", "cwe": "CWE-89", "language": "php",
   "description": "SQL injection in ...", "vuln_code": "<pre-fix hunk>",
   "fixed_code": "<post-fix hunk>", "repo": "org/repo", "url": "<commit url>"}

Filters to APP-LAYER CWEs + WEB LANGUAGES (not C/C++ memory-safety - that's ingest_memsafe).
Emits:
  * appfix_rag.jsonl   - KB items (same schema as rag/items.jsonl) for retrieval
  * appfix_sft.jsonl   - reviewer SFT pairs (vulnerable code -> grounded CWE review + fix)

Getting the input JSONL (the heavy, documented step):
  - MoreFixes (CC-BY-4.0): restore the Zenodo Postgres dump, then export
    fixes JOIN cwe_classification WHERE cwe IN (app-layer set) AND language IN (web) to this shape.
  - CVEfixes: run its collector, then query method_change / file_change for the same filter.
  - CrossVul: map its per-CWE files to this shape.
See DATA_FOUNDRY.md for the exact queries. This script is the transform, not the download.

  python ingest_appfix.py fixpairs.jsonl --out-rag appfix_rag.jsonl --out-sft appfix_sft.jsonl
"""
from __future__ import annotations
import argparse
import json
import re

# App-layer CWEs (2025 CWE Top 25 + common web classes). Memory-safety CWEs are excluded
# on purpose (handled by ingest_memsafe.py).
APP_CWES = {
    "CWE-79": ("A03", "Cross-site Scripting (XSS)"),
    "CWE-89": ("A03", "SQL Injection"),
    "CWE-77": ("A03", "Command Injection"),
    "CWE-78": ("A03", "OS Command Injection"),
    "CWE-94": ("A03", "Code Injection"),
    "CWE-90": ("A03", "LDAP Injection"),
    "CWE-91": ("A03", "XML Injection"),
    "CWE-22": ("A01", "Path Traversal"),
    "CWE-434": ("A04", "Unrestricted File Upload"),
    "CWE-352": ("A01", "Cross-Site Request Forgery (CSRF)"),
    "CWE-639": ("A01", "Authorization Bypass / IDOR"),
    "CWE-862": ("A01", "Missing Authorization"),
    "CWE-863": ("A01", "Incorrect Authorization"),
    "CWE-284": ("A01", "Improper Access Control"),
    "CWE-918": ("A10", "Server-Side Request Forgery (SSRF)"),
    "CWE-611": ("A05", "XML External Entity (XXE)"),
    "CWE-502": ("A08", "Deserialization of Untrusted Data"),
    "CWE-798": ("A07", "Use of Hard-coded Credentials"),
    "CWE-287": ("A07", "Improper Authentication"),
    "CWE-306": ("A07", "Missing Authentication"),
    "CWE-269": ("A01", "Improper Privilege Management"),
    "CWE-601": ("A01", "Open Redirect"),
    "CWE-1236": ("A03", "CSV/Formula Injection"),
}
WEB_LANGS = {"php", "java", "javascript", "js", "typescript", "ts", "python", "py",
             "ruby", "rb", "go", "csharp", "c#", "kotlin", "scala"}

REVIEW_SYS = (
    "You are Sheepdog, a defensive security code reviewer. Given a code hunk, identify the "
    "vulnerability class with its CWE and OWASP mapping, explain the root cause in one sentence, "
    "and give the concrete fix. Ground your review in the actual fix; do not invent issues. You "
    "harden code, never weaponize it."
)


def norm_lang(l: str) -> str:
    return (l or "").strip().lower()


def norm_cwe(c: str) -> str:
    m = re.search(r"CWE[-_ ]?(\d+)", str(c), re.I)
    return f"CWE-{m.group(1)}" if m else ""


def kb_item(rec, cwe, owasp, title):
    return {
        "id": f"appfix::{cwe}::{rec.get('cve','na')}",
        "technique": f"{title} ({cwe})",
        "functional_semantics": rec.get("description", title)[:400],
        "root_cause": rec.get("description", "")[:400] or f"{title} - unsanitized/untrusted input reaches a sensitive sink.",
        "fix_pattern": f"See the applied fix for {rec.get('cve','')}: " + (rec.get("fixed_code", "")[:300]),
        "cwe": cwe,
        "category": owasp,
        "category_title": title,
        "owasp_2026": None,
        "detection_hint": f"{title}: look for the {cwe} pattern in {rec.get('language','')} code (untrusted input into the sink).",
        "multi_turn": False,
        "example_user_turn": None,
        "source": f"appfix:{rec.get('repo','')}:{rec.get('cve','')}",
        "license": "CC-BY-4.0 (MoreFixes) / per-source",
    }


def sft_pair(rec, cwe, owasp, title):
    vuln = rec.get("vuln_code", "")[:2400]
    fix = rec.get("fixed_code", "")[:1200]
    user = (f"Review this {rec.get('language','')} code for security issues:\n```\n{vuln}\n```")
    assistant = (
        f"Finding: {title} ({cwe} / OWASP {owasp}).\n"
        f"Root cause: {rec.get('description','untrusted input reaches a sensitive sink without validation.')[:300]}\n"
        f"Fix: apply input validation / encoding / parameterization appropriate to {title}. "
        f"The upstream patch resolved it as:\n```\n{fix}\n```"
    )
    return {
        "messages": [
            {"role": "system", "content": REVIEW_SYS},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "attack_family": f"appfix:{cwe.lower()}",
        "technique": title,
        "category": owasp,
        "cwe": cwe,
        "source": "appfix",
        "license": "CC-BY-4.0/per-source",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("infile", help="normalized fix-pair JSONL")
    ap.add_argument("--out-rag", default="appfix_rag.jsonl")
    ap.add_argument("--out-sft", default="appfix_sft.jsonl")
    a = ap.parse_args()
    kept, skipped = 0, 0
    frag, fsft = open(a.out_rag, "w", encoding="utf-8"), open(a.out_sft, "w", encoding="utf-8")
    for line in open(a.infile, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        cwe = norm_cwe(rec.get("cwe", ""))
        lang = norm_lang(rec.get("language", ""))
        if cwe not in APP_CWES or lang not in WEB_LANGS or not rec.get("vuln_code"):
            skipped += 1
            continue
        owasp, title = APP_CWES[cwe]
        frag.write(json.dumps(kb_item(rec, cwe, owasp, title), ensure_ascii=False) + "\n")
        fsft.write(json.dumps(sft_pair(rec, cwe, owasp, title), ensure_ascii=False) + "\n")
        kept += 1
    frag.close(); fsft.close()
    print(f"[ingest_appfix] kept {kept}, skipped {skipped} (non-app-layer CWE / non-web lang / no code)")
    print(f"  -> {a.out_rag}  +  {a.out_sft}")


if __name__ == "__main__":
    main()
