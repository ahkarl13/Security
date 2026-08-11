#!/usr/bin/env python3
"""
sheepdog/data/ingest_owasp_llm.py - OWASP LLM Top 10 category knowledge -> RAG items.

Emits one RAG knowledge item per OWASP-LLM category (2025 edition, the stable/official
list) in the same Vul-RAG shape as build_llmsec.py's items, with a provisional 2026
rename note where one applies. Category-level context that complements the
technique-level items (llmsec_rag.jsonl).

Source: OWASP Top 10 for LLM Applications 2025 (genai.owasp.org). Risk/mitigation text
is a factual condensation, not verbatim. License: OWASP content is CC-BY-SA-4.0.

Usage:
  python ingest_owasp_llm.py --out D:\\AISecurity\\Security\\sheepdog\\data\\llmsec\\owasp_rag.jsonl
"""
import argparse
import json
import os

import taxonomy as tax

# (2025 id, risk, mitigation). Titles come from taxonomy.OWASP.
CATEGORIES = {
    "LLM01": (
        "Untrusted input (direct or indirect, incl. via retrieved content or tool output) "
        "manipulates the model into ignoring its instructions or taking attacker-chosen actions.",
        "Constrain and validate inputs; enforce an instruction hierarchy and delimit untrusted "
        "content; segregate external/retrieved data from instructions; filter model output; "
        "require human approval for sensitive actions."),
    "LLM02": (
        "The model discloses sensitive data - PII, secrets, or proprietary content - via training-"
        "data memorization, RAG chunk leakage, or including it in responses.",
        "Sanitize training/RAG data; enforce least-privilege data access and authorize before "
        "retrieval; redact/filter output; never place secrets in the prompt."),
    "LLM03": (
        "Vulnerabilities enter through third-party models, datasets, plugins, adapters, or MCP "
        "tool servers.",
        "Vet and pin third-party sources; verify model provenance/signatures; scan serialized "
        "model files; maintain an SBOM for AI components."),
    "LLM04": (
        "Poisoned pre-training or fine-tuning data embeds backdoors or biases that activate on a "
        "trigger.",
        "Vet data provenance; detect anomalies/outliers; control and audit fine-tuning data; test "
        "for backdoor triggers before deployment."),
    "LLM05": (
        "Model output is treated as trusted and passed into downstream sinks (SQL, HTML, shell, "
        "code, terminal), enabling XSS/SQLi/RCE - the 'XSS of AI'.",
        "Treat every model output as untrusted; context-encode and validate before any sink; use "
        "parameterized queries; sandbox code/command execution."),
    "LLM06": (
        "An agent is granted excessive permissions or autonomy and eventually takes a consequential "
        "action without adequate oversight.",
        "Enforce least agency; scope tools narrowly; require human-in-the-loop for sensitive, "
        "non-reversible operations; log and rate-limit agent actions."),
    "LLM07": (
        "The system prompt holds business logic, credentials, or policy that attackers extract "
        "through crafted questioning.",
        "Never store secrets or authorization logic in the system prompt; enforce controls OUTSIDE "
        "the model; apply output-side redaction; assume the system prompt can be revealed."),
    "LLM08": (
        "RAG-specific: poisoned embeddings, cross-tenant leakage, and embedding inversion in shared "
        "vector databases.",
        "Access-control and tenant-isolate the vector store; authorize before retrieval; validate "
        "and provenance-track embedded content; monitor for retrieval anomalies."),
    "LLM09": (
        "Confident, fluent, plausible-but-wrong outputs drive flawed automated actions or human "
        "decisions.",
        "Ground responses (RAG) and cite sources; require human review for high-risk decisions; add "
        "confidence scoring and fact-checking; constrain automated execution."),
    "LLM10": (
        "Token floods, recursive context expansion, and reasoning-model resource drain cause cost "
        "spikes and denial of service.",
        "Enforce rate limits, quotas, and timeouts; cap context/output length; monitor token cost "
        "and alert; isolate workloads by sensitivity."),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="llmsec/owasp_rag.jsonl")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    n = 0
    with open(a.out, "w", encoding="utf-8") as f:
        for cid, (risk, mitig) in CATEGORIES.items():
            item = {
                "id": f"owasp::{cid}",
                "technique": f"{cid} {tax.OWASP[cid]}",
                "functional_semantics": risk,
                "root_cause": risk,
                "fix_pattern": mitig,
                "category": cid,
                "category_title": tax.OWASP[cid],
                "owasp_2026": tax.OWASP_2026_RENAME.get(cid),
                "detection_hint": f"Interactions exhibiting {tax.OWASP[cid]} "
                                  f"({'2026: ' + tax.OWASP_2026_RENAME[cid] if cid in tax.OWASP_2026_RENAME else 'stable title'}).",
                "multi_turn": False,
                "example_user_turn": None,
                "source": "OWASP Top 10 for LLM Applications 2025 (genai.owasp.org)",
                "license": "CC-BY-SA-4.0",
            }
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            n += 1
    print(json.dumps({"owasp_rag_items": n, "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
