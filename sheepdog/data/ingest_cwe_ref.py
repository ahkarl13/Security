#!/usr/bin/env python3
"""
sheepdog/data/ingest_cwe_ref.py - a FULLER CWE reference -> RAG items.

Writeup #18's broadening test showed RAG's lift on real CVEs tracks KB coverage. The
Top-25 (app-layer in appsec_rag + memory-safety in memsafe_rag) covers the headline
classes; this adds the NEXT tier of common CWEs that show up across real CVEs (crypto,
auth/session, credentials, config/permissions, injection variants, info exposure,
resource, deserialization-adjacent) so retrieval is relevant across a wider CVE spread.

Curated (authored) reference at a knowledge level. Source: MITRE CWE (public).

Usage:
  python ingest_cwe_ref.py --out D:\\AISecurity\\Security\\sheepdog\\data\\cwe_ref_rag.jsonl
"""
import argparse
import json
import os

# (cwe, name, desc, fix) - common CWEs beyond the Top-25 app-layer/memory-safety already in KB
CWES = [
    ("CWE-798", "Use of Hard-coded Credentials", "Credentials embedded in source/config/firmware that attackers can extract.", "Externalize secrets (vault/KMS/env); no default or embedded credentials; rotate."),
    ("CWE-259", "Use of Hard-coded Password", "A password is written directly into code.", "Store hashed/managed secrets outside code; require configured credentials."),
    ("CWE-522", "Insufficiently Protected Credentials", "Credentials stored/transmitted without adequate protection.", "Hash+salt at rest, TLS in transit, least exposure, secret managers."),
    ("CWE-311", "Missing Encryption of Sensitive Data", "Sensitive data stored/sent in the clear.", "Encrypt at rest and in transit with strong, current algorithms."),
    ("CWE-319", "Cleartext Transmission of Sensitive Info", "Sensitive data sent over an unencrypted channel.", "Enforce TLS everywhere; HSTS; disable plaintext protocols."),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "Weak/obsolete crypto (MD5, DES, RC4).", "Use vetted current algorithms (AES-GCM, SHA-256+, argon2); crypto-agility."),
    ("CWE-328", "Use of Weak Hash", "Fast/weak hashing for passwords or integrity.", "Use argon2/bcrypt/scrypt for passwords; SHA-256+ for integrity."),
    ("CWE-330", "Use of Insufficiently Random Values", "Predictable randomness for tokens/keys/IDs.", "Use a CSPRNG for anything security-relevant."),
    ("CWE-295", "Improper Certificate Validation", "TLS cert/hostname not validated -> MITM.", "Validate chain + hostname + expiry; pin where appropriate; no verify-disable."),
    ("CWE-384", "Session Fixation", "A pre-auth session ID is honored after login.", "Regenerate the session ID on authentication; bind sessions."),
    ("CWE-613", "Insufficient Session Expiration", "Sessions/tokens stay valid too long.", "Short-lived tokens, idle+absolute timeouts, revocation."),
    ("CWE-620", "Unverified Password Change", "Password can be changed without proving identity.", "Require current password / re-auth for credential changes."),
    ("CWE-640", "Weak Password Recovery Mechanism", "Reset flow is guessable/abusable.", "Random single-use time-limited tokens over a verified channel; rate-limit."),
    ("CWE-732", "Incorrect Permission Assignment for Critical Resource", "Files/objects world-readable/writable.", "Least-privilege permissions; deny by default; review ACLs."),
    ("CWE-276", "Incorrect Default Permissions", "Insecure permissions set at install/creation.", "Ship secure defaults; restrict on creation."),
    ("CWE-269", "Improper Privilege Management", "Privileges granted/dropped incorrectly.", "Least privilege; drop privileges promptly; validate role transitions."),
    ("CWE-250", "Execution with Unnecessary Privileges", "Component runs as root/admin needlessly.", "Run with minimal privileges; separate duties."),
    ("CWE-668", "Exposure of Resource to Wrong Sphere", "A resource is reachable by an unintended actor.", "Scope resources correctly; access control at the boundary."),
    ("CWE-538", "Insertion of Sensitive Info into Externally-Accessible File/Dir", "Secrets/logs exposed via reachable files.", "Keep sensitive files out of served paths; restrict access; redact logs."),
    ("CWE-532", "Insertion of Sensitive Information into Log File", "Secrets/PII written to logs.", "Redact secrets/PII before logging; protect log access."),
    ("CWE-209", "Generation of Error Message Containing Sensitive Info", "Verbose errors leak internals.", "Generic error messages in prod; log details server-side only."),
    ("CWE-611", "Improper Restriction of XML External Entity (XXE)", "XML parser resolves external entities -> file read/SSRF.", "Disable DTD/external entities in the parser; use safe parsers."),
    ("CWE-776", "XML Entity Expansion (Billion Laughs)", "Recursive entity expansion exhausts memory.", "Disable entity expansion; limit parser resources."),
    ("CWE-113", "HTTP Response Splitting", "CRLF injection into headers.", "Strip/encode CR/LF in header values; use safe header APIs."),
    ("CWE-601", "Open Redirect (URL Redirection to Untrusted Site)", "User-controlled redirect target enables phishing.", "Allow-list redirect targets; use relative/mapped destinations."),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "Server fetches an attacker URL reaching internal services.", "Allow-list destinations; block internal/link-local + metadata; validate host."),
    ("CWE-116", "Improper Encoding or Escaping of Output", "Output not neutralized for its sink.", "Context-aware encoding at every sink (HTML/JS/SQL/shell/URL)."),
    ("CWE-93", "CRLF Injection", "Injected CR/LF alters logs/headers/protocols.", "Strip/encode control chars; validate input."),
    ("CWE-88", "Argument Injection", "Untrusted input injected as command arguments/flags.", "Allow-list args; separate command from data; avoid shell."),
    ("CWE-134", "Use of Externally-Controlled Format String", "User input used as a printf-style format.", "Use constant format strings; pass input as arguments only."),
    ("CWE-90", "LDAP Injection", "Untrusted input into an LDAP filter.", "Escape/parameterize LDAP filters; validate input."),
    ("CWE-91", "XML Injection", "Untrusted input alters XML structure.", "Encode/validate; use safe builders; schema-validate."),
    ("CWE-643", "XPath Injection", "Untrusted input into an XPath query.", "Parameterize XPath; validate/encode input."),
    ("CWE-1236", "Formula Injection (CSV Injection)", "Exported cells start with =,+,-,@ -> spreadsheet code execution.", "Prefix/neutralize leading formula chars on export; validate."),
    ("CWE-843", "Type Confusion", "An object accessed as an incompatible type -> memory corruption.", "Validate types; safe casts; memory-safe patterns."),
    ("CWE-706", "Use of Incorrectly-Resolved Name or Reference", "Name/path resolves to an unintended resource.", "Canonicalize + validate; avoid TOCTOU; allow-list."),
    ("CWE-59", "Improper Link Resolution (Link Following)", "Symlink/junction abuse redirects file operations.", "Resolve+validate real paths; O_NOFOLLOW; confine to a base dir."),
    ("CWE-400", "Uncontrolled Resource Consumption", "No limits on memory/CPU/connections -> DoS.", "Quotas, rate limits, timeouts, backpressure."),
    ("CWE-770", "Allocation of Resources Without Limits or Throttling", "Unbounded allocation from input.", "Cap sizes/counts; validate before allocating."),
    ("CWE-834", "Excessive Iteration / Algorithmic Complexity DoS", "Worst-case input triggers pathological work (ReDoS).", "Bound iterations; safe regex; complexity limits."),
    ("CWE-1333", "Inefficient Regular Expression Complexity (ReDoS)", "Catastrophic backtracking on crafted input.", "Use linear-time regex engines; simplify patterns; input caps."),
    ("CWE-347", "Improper Verification of Cryptographic Signature", "Signatures not (properly) checked.", "Verify signatures with correct keys before trusting data."),
    ("CWE-345", "Insufficient Verification of Data Authenticity", "Data trusted without integrity/authenticity checks.", "MAC/sign + verify; validate provenance."),
    ("CWE-565", "Reliance on Cookies Without Validation/Integrity", "Trusting client cookies for security decisions.", "Sign/verify or server-side session state; don't trust client values."),
    ("CWE-863", "Incorrect Authorization", "Authorization logic is present but flawed.", "Centralize + test authz; deny by default."),
    ("CWE-1021", "Improper Restriction of Rendered UI Layers (Clickjacking)", "Framing tricks users into unintended clicks.", "X-Frame-Options / CSP frame-ancestors; frame-busting."),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)", "State-changing request without intent proof.", "Anti-CSRF tokens; SameSite cookies; re-auth sensitive actions."),
    ("CWE-1188", "Insecure Default Initialization of Resource", "Insecure out-of-the-box configuration.", "Secure-by-default; force configuration of security-critical settings."),
    ("CWE-16", "Configuration", "Security weaknesses arising from misconfiguration.", "Hardened baselines; config review; least functionality."),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="cwe_ref_rag.jsonl")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for cwe, name, desc, fix in CWES:
            item = {
                "id": f"cwe-ref::{cwe}",
                "technique": f"{cwe} {name}",
                "functional_semantics": desc,
                "root_cause": desc,
                "fix_pattern": fix,
                "category": "CWE reference",
                "category_title": "CWE reference",
                "cwe": cwe,
                "detection_hint": f"Indicators of {name}.",
                "scope": "cwe-reference",
                "multi_turn": False,
                "example_user_turn": None,
                "source": "MITRE CWE (public reference)",
                "license": "CWE: public",
            }
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(json.dumps({"cwe_ref_rag_items": len(CWES), "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
