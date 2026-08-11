#!/usr/bin/env python3
"""
sheepdog/data/ingest_appsec.py - APPLICATION-LAYER (web) security knowledge -> RAG items.

Closes the gap AK flagged: an LLM-security-only scope covers ~15-20% of the real
application-layer surface. The mass of real-world vulns is classic server-side web
security - broken access control, SQLi, XSS, SSRF, deserialization, IDOR, auth. This
module emits RAG knowledge items for:
  * OWASP Top 10:2025 (web) - the current released edition (verified genai/owasp.org),
    A01..A10.
  * The APPLICATION-LAYER entries of the MITRE 2025 CWE Top 25 (released Dec 2025) -
    XSS/SQLi/CSRF/Missing-Auth lead the list; ~17 of 25 are app-layer.

Feeds the #19+ application-layer lane and, via the shared RAG index, gives ALL Sheepdog
hats app-layer coverage now. Same Vul-RAG schema as ingest_owasp_llm.py.

Source: OWASP Top 10:2025 (owasp.org/Top10/2025) + MITRE CWE Top 25 2025 (cwe.mitre.org).
Risk/mitigation text is a factual condensation. License: OWASP CC-BY-SA-4.0; CWE public.

Usage:
  python ingest_appsec.py --out D:\\AISecurity\\Security\\sheepdog\\data\\appsec_rag.jsonl
"""
import argparse
import json
import os

# OWASP Top 10:2025 web (current released edition).
OWASP_WEB = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# (id, risk, mitigation) per OWASP Web 2025 category.
OWASP_ITEMS = {
    "A01": ("Users act outside their intended permissions - IDOR, missing function-level "
            "authorization, privilege escalation, force-browsing to unauthorized resources.",
            "Deny by default; enforce authorization server-side on EVERY request; check "
            "record ownership; centralize access-control logic; never rely on client-side "
            "enforcement or hidden fields."),
    "A02": ("Insecure defaults, unnecessary features, verbose errors, open cloud storage, "
            "unpatched or default-credential components.",
            "Harden a repeatable baseline; disable unused features/defaults; suppress verbose "
            "errors in prod; review cloud/IAM configs; scan configuration automatically."),
    "A03": ("Vulnerable, outdated, or compromised components and a compromised build/CI "
            "pipeline (expanded from 2021's Vulnerable & Outdated Components).",
            "Maintain an SBOM; pin and verify dependencies; sign build artifacts; monitor "
            "advisories (OSV/GHSA); secure the CI/CD pipeline and its secrets."),
    "A04": ("Weak or missing cryptography exposes data in transit or at rest; plaintext "
            "secrets; weak hashes.",
            "TLS everywhere; strong, current algorithms; proper key management/rotation; hash "
            "passwords with argon2/bcrypt/scrypt; never hardcode secrets."),
    "A05": ("Untrusted input is interpreted as code or query - SQL injection (CWE-89), XSS "
            "(CWE-79), OS/command/code injection, and (2025) SSRF folded in.",
            "Use parameterized queries / prepared statements; context-aware output encoding; "
            "allow-list input validation; safe APIs/ORM; avoid shells and eval."),
    "A06": ("Missing or ineffective security controls by design - business-logic flaws that "
            "no amount of clean implementation fixes.",
            "Threat-model early; apply secure design patterns; write security requirements and "
            "abuse cases; design for least privilege and secure defaults."),
    "A07": ("Weak authentication, credential stuffing, brittle session management, default "
            "credentials.",
            "Require MFA; rate-limit and lock out brute force; strong session management "
            "(rotation, secure/HttpOnly/SameSite cookies); secure credential storage."),
    "A08": ("Unsigned or untrusted updates, insecure deserialization (CWE-502), and CI/CD "
            "integrity failures.",
            "Verify signatures/integrity of code and data; avoid native deserialization of "
            "untrusted data; use trusted repositories and integrity checks."),
    "A09": ("Insufficient logging, monitoring, and alerting to detect and respond to attacks "
            "in time.",
            "Log security-relevant events with context; centralize and monitor; alert on "
            "anomalies; protect log integrity; define an incident-response path."),
    "A10": ("Improper handling of errors/exceptions leaks information or fails open (NEW in "
            "2025).",
            "Fail securely (closed); return generic error messages; handle all exceptional "
            "paths; never leak stack traces or sensitive data in errors."),
}

# Application-layer entries of the MITRE 2025 CWE Top 25 (memory-safety CWEs excluded -
# those belong to the native/systems slice, not the app-layer scope).
# dict(cwe, name, owasp, root_cause, fix, detect)
APP_CWES = [
    dict(cwe="CWE-79", name="Cross-site Scripting (XSS)", owasp="A05", rank=1,
         root_cause="User input is rendered into HTML/JS without neutralization, so it "
                    "executes in a victim's browser.",
         fix="Context-aware output encoding at every sink; a strict Content-Security-Policy; "
             "framework auto-escaping; sanitize rich text with a vetted library.",
         detect="User-controlled data reflected or stored into HTML/attribute/JS/URL contexts "
                "without encoding."),
    dict(cwe="CWE-89", name="SQL Injection", owasp="A05", rank=2,
         root_cause="Untrusted input is concatenated into a SQL statement and interpreted as "
                    "query structure.",
         fix="Parameterized queries / prepared statements everywhere; ORM with bound params; "
             "least-privilege DB accounts; allow-list any dynamic identifiers.",
         detect="SQL built by string concatenation/format with request data."),
    dict(cwe="CWE-352", name="Cross-Site Request Forgery (CSRF)", owasp="A01", rank=3,
         root_cause="A state-changing request is accepted without proof it was intentionally "
                    "issued by the authenticated user.",
         fix="Synchronizer (anti-CSRF) tokens on state-changing requests; SameSite cookies; "
             "re-auth for sensitive actions.",
         detect="State-changing POST/PUT/DELETE endpoints lacking a CSRF token or SameSite "
                "protection."),
    dict(cwe="CWE-862", name="Missing Authorization", owasp="A01", rank=4,
         root_cause="A function or resource performs no authorization check, so any "
                    "authenticated (or anonymous) actor can reach it.",
         fix="Enforce authorization server-side on every request; deny by default; centralize "
             "the check so no handler can forget it.",
         detect="Endpoints/handlers/resources with no permission check before the action."),
    dict(cwe="CWE-22", name="Path Traversal", owasp="A01", rank=6,
         root_cause="User input is used to build a filesystem path, letting '../' escape the "
                    "intended directory.",
         fix="Canonicalize then confine to a base directory; allow-list filenames; reject "
             "traversal sequences; use safe file APIs.",
         detect="File open/read/write using a user-controlled path component."),
    dict(cwe="CWE-78", name="OS Command Injection", owasp="A05", rank=9,
         root_cause="Untrusted input is passed into an OS shell command.",
         fix="Avoid the shell; use exec with an argument array and no shell interpretation; "
             "allow-list arguments; never interpolate input into a command string.",
         detect="system()/exec()/popen/backticks built with request data."),
    dict(cwe="CWE-94", name="Code Injection", owasp="A05", rank=10,
         root_cause="Untrusted input is evaluated as program code.",
         fix="Never eval untrusted input; remove dynamic code execution; if unavoidable, "
             "sandbox with a strict allow-list.",
         detect="eval/exec/Function()/template code paths fed user data."),
    dict(cwe="CWE-434", name="Unrestricted Upload of Dangerous File Type", owasp="A05", rank=12,
         root_cause="Uploaded files are not validated, allowing executable or malicious "
                    "content into a served/executed location.",
         fix="Validate type/size/content (not just extension); store outside the web root; "
             "serve with no-execute; randomize names; scan content.",
         detect="Upload handlers without type/content validation or storing under the web root."),
    dict(cwe="CWE-502", name="Deserialization of Untrusted Data", owasp="A08", rank=15,
         root_cause="Attacker-controlled serialized data is deserialized into objects, "
                    "enabling gadget-chain code execution.",
         fix="Do not natively deserialize untrusted data; use data-only formats (JSON) with "
             "schema validation; sign/verify integrity if serialization is required.",
         detect="pickle.loads / ObjectInputStream / unserialize / yaml.load on request data."),
    dict(cwe="CWE-863", name="Incorrect Authorization", owasp="A01", rank=17,
         root_cause="An authorization check exists but its logic is flawed, granting access it "
                    "should deny.",
         fix="Centralize and unit-test authorization; deny by default; verify against a policy, "
             "not ad-hoc conditionals.",
         detect="Authorization conditionals with logic errors (wrong role/ownership comparison)."),
    dict(cwe="CWE-284", name="Improper Access Control", owasp="A01", rank=19,
         root_cause="Access control is missing or improperly enforced for a resource or action.",
         fix="Enforce least privilege server-side; deny by default; consistent access-control "
             "layer across all entry points.",
         detect="Resources/actions reachable without an enforced access-control decision."),
    dict(cwe="CWE-200", name="Exposure of Sensitive Information", owasp="A01", rank=20,
         root_cause="Sensitive data is disclosed to actors not authorized to see it.",
         fix="Minimize collected/returned data; authorize before returning; redact in "
             "logs/errors; encrypt at rest and in transit.",
         detect="Sensitive fields in responses, error messages, or logs without authorization."),
    dict(cwe="CWE-306", name="Missing Authentication for Critical Function", owasp="A07", rank=21,
         root_cause="A critical function is reachable without any authentication.",
         fix="Require authentication on all sensitive operations; no unauthenticated admin/"
             "management endpoints.",
         detect="Critical/admin endpoints with no authentication requirement."),
    dict(cwe="CWE-918", name="Server-Side Request Forgery (SSRF)", owasp="A05", rank=22,
         root_cause="The server fetches an attacker-controlled URL, reaching internal services "
                    "or metadata endpoints.",
         fix="Allow-list outbound destinations; block internal/link-local ranges and cloud "
             "metadata IPs; resolve+validate the host; no raw user-URL fetches.",
         detect="Server-side HTTP/file fetch of a user-supplied URL/host."),
    dict(cwe="CWE-77", name="Command Injection", owasp="A05", rank=23,
         root_cause="Untrusted input is incorporated into a command that a component executes.",
         fix="Use parameterized/allow-listed command APIs; avoid shells; separate command from "
             "data.",
         detect="Command strings assembled with request data."),
    dict(cwe="CWE-639", name="Authorization Bypass Through User-Controlled Key (IDOR)",
         owasp="A01", rank=24,
         root_cause="Object references (ids) are honored without checking the caller owns/"
                    "may access that object.",
         fix="Enforce per-object ownership/authorization on every reference; use unguessable or "
             "indirect references; never trust a client-supplied id alone.",
         detect="Resource access by a user-supplied id with no ownership check."),
    dict(cwe="CWE-20", name="Improper Input Validation", owasp="A05", rank=18,
         root_cause="Input is used without adequate validation of type, length, format, or "
                    "range, enabling downstream injection/logic abuse.",
         fix="Allow-list validation at trust boundaries; canonicalize before validating; reject "
             "rather than sanitize where possible.",
         detect="Request data used in a sink without prior validation."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="appsec_rag.jsonl")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    n = 0
    with open(a.out, "w", encoding="utf-8") as f:
        # OWASP Web 2025 category items
        for cid, (risk, mitig) in OWASP_ITEMS.items():
            item = {
                "id": f"owasp-web::{cid}",
                "technique": f"{cid} {OWASP_WEB[cid]}",
                "functional_semantics": risk,
                "root_cause": risk,
                "fix_pattern": mitig,
                "category": cid,
                "category_title": OWASP_WEB[cid],
                "cwe": None,
                "detection_hint": f"Application-layer weakness in the class {OWASP_WEB[cid]}.",
                "scope": "application-layer",
                "multi_turn": False,
                "example_user_turn": None,
                "source": "OWASP Top 10:2025 (owasp.org/Top10/2025)",
                "license": "CC-BY-SA-4.0",
            }
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            n += 1
        # CWE Top 25 2025 app-layer class items
        for c in APP_CWES:
            item = {
                "id": f"cwe::{c['cwe']}",
                "technique": f"{c['cwe']} {c['name']}",
                "functional_semantics": c["root_cause"],
                "root_cause": c["root_cause"],
                "fix_pattern": c["fix"],
                "category": c["owasp"],
                "category_title": OWASP_WEB[c["owasp"]],
                "cwe": c["cwe"],
                "cwe_top25_2025_rank": c["rank"],
                "detection_hint": c["detect"],
                "scope": "application-layer",
                "multi_turn": False,
                "example_user_turn": None,
                "source": "MITRE CWE Top 25 2025 + OWASP Top 10:2025",
                "license": "CWE: public; OWASP: CC-BY-SA-4.0",
            }
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            n += 1
    print(json.dumps({"appsec_rag_items": n, "owasp_web": len(OWASP_ITEMS),
                      "app_cwes": len(APP_CWES), "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
