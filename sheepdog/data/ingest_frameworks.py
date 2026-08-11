#!/usr/bin/env python3
"""
sheepdog/data/ingest_frameworks.py - MITRE (ATT&CK, ATLAS) + NIST (AI RMF, CSF 2.0,
SSDF) framework knowledge -> RAG items, with crosswalks.

Adds the adversary-TTP + compliance/attestation layer AK asked for. Tactic-level for
ATT&CK/ATLAS (stable IDs; full technique-level STIX ingest is a later fatten step) plus
the key AI techniques and the crosswalks (CWE<->CAPEC<->ATT&CK, OWASP-LLM<->ATLAS) that
turn an isolated finding into adversary + compliance context.

Versions verified Aug 2026: ATT&CK Enterprise v19; ATLAS v2026.05; NIST AI RMF 1.0 +
GenAI Profile (AI 600-1, Jul 2024); CSF 2.0 (Feb 2024); SSDF SP 800-218 + 218A.

Usage:
  python ingest_frameworks.py --out D:\\AISecurity\\Security\\sheepdog\\data\\frameworks_rag.jsonl
"""
import argparse
import json
import os

ITEMS = []


def add(id, framework, name, what, use_or_fix, detect, source, license="see source", scope="framework"):
    ITEMS.append(dict(id=id, technique=name, functional_semantics=what,
                      root_cause=what, fix_pattern=use_or_fix, category=framework,
                      category_title=framework, detection_hint=detect, scope=scope,
                      multi_turn=False, example_user_turn=None, source=source, license=license))


# --- MITRE ATT&CK Enterprise tactics (v19) ---
ATTACK_SRC = "MITRE ATT&CK Enterprise v19 (attack.mitre.org; ATT&CK Terms of Use)"
ATTACK_TACTICS = [
    ("TA0043", "Reconnaissance", "Gathering info to plan future operations (targets, infra, people)."),
    ("TA0042", "Resource Development", "Establishing resources (infrastructure, accounts, tooling) to support operations."),
    ("TA0001", "Initial Access", "Getting into the network (phishing, exploit public-facing app, valid accounts)."),
    ("TA0002", "Execution", "Running adversary-controlled code on a local or remote system."),
    ("TA0003", "Persistence", "Maintaining a foothold across restarts/credential changes."),
    ("TA0004", "Privilege Escalation", "Gaining higher-level permissions."),
    ("TA0005", "Defense Evasion", "Avoiding detection (obfuscation, disabling tools, living-off-the-land)."),
    ("TA0006", "Credential Access", "Stealing credentials (dumping, brute force, keylogging)."),
    ("TA0007", "Discovery", "Learning the environment (hosts, accounts, services, trusts)."),
    ("TA0008", "Lateral Movement", "Moving through the environment (pivoting, remote services)."),
    ("TA0009", "Collection", "Gathering data of interest toward the objective."),
    ("TA0011", "Command and Control", "Communicating with compromised systems to control them."),
    ("TA0010", "Exfiltration", "Stealing data out of the network."),
    ("TA0040", "Impact", "Manipulating, interrupting, or destroying systems/data."),
]
for tid, name, what in ATTACK_TACTICS:
    add(f"attack::{tid}", "MITRE ATT&CK", f"{tid} {name}", what,
        "Map observed/adversary behavior to this tactic; pair with ATT&CK mitigations + "
        "detections (data sources) for the blue-team response.",
        f"Behaviors in the {name} phase of an intrusion; ATT&CK techniques enumerate the how.",
        ATTACK_SRC)

# --- MITRE ATLAS (adversarial ML) tactics + key AI techniques ---
ATLAS_SRC = "MITRE ATLAS v2026.05 (atlas.mitre.org; MITRE Distribution Unlimited)"
add("atlas::TA-overview", "MITRE ATLAS", "ATLAS - Adversarial Threat Landscape for AI Systems",
    "An ATT&CK-style matrix of tactics/techniques against ML/AI systems: recon, ML model "
    "access, ML attack staging, initial access, execution, persistence, evasion, discovery, "
    "collection, exfiltration, impact - plus real-world case studies.",
    "Use ATLAS to threat-model and red-team AI systems; it is the adversary-TTP counterpart "
    "to the OWASP LLM Top 10 (which is the secure-design/weakness lens).",
    "AI-specific adversary behavior: prompt injection, poisoning, evasion, model theft, agentic/MCP abuse.",
    ATLAS_SRC)
ATLAS_TECH = [
    ("AML.T0051", "Prompt Injection", "Crafting input that overrides model instructions.",
     "OWASP LLM01 Prompt Injection", "Instruction-override / untrusted-content-as-instruction patterns."),
    ("AML.T0020", "Poison Training Data", "Tampering with training/fine-tuning data to embed behavior.",
     "OWASP LLM04 Data & Model Poisoning", "Anomalous/backdoored training samples; trigger phrases."),
    ("AML.T0043", "Craft Adversarial Data (Evasion)", "Perturbed inputs that cause misclassification.",
     "-", "Inputs engineered to flip a model decision."),
    ("AML.T0044", "Model Extraction / Theft", "Querying to reconstruct or steal a model.",
     "-", "High-volume systematic querying to clone model behavior."),
    ("AML.T0024", "Exfiltration via ML Inference / Membership Inference", "Leaking training data or membership via outputs.",
     "OWASP LLM02 Sensitive Information Disclosure", "Probing to recover training data or confirm membership."),
]
for tid, name, what, xwalk, detect in ATLAS_TECH:
    add(f"atlas::{tid}", "MITRE ATLAS", f"{tid} {name}", what,
        f"Defensive countermeasure per ATLAS mitigations; crosswalk: {xwalk}.",
        detect, ATLAS_SRC)

# --- NIST AI RMF 1.0 + GenAI Profile ---
AIRMF_SRC = "NIST AI RMF 1.0 (AI 100-1) + Generative AI Profile (AI 600-1, Jul 2024) - US Gov public domain"
for fid, name, what in [
    ("GOVERN", "Govern", "Cultivate a risk-management culture: policies, accountability, roles, oversight (cross-cutting)."),
    ("MAP", "Map", "Frame context and identify AI risks for the system and its use."),
    ("MEASURE", "Measure", "Analyze, benchmark, and track identified AI risks (incl. red-team results)."),
    ("MANAGE", "Manage", "Prioritize, respond to, and monitor AI risks over the lifecycle."),
]:
    add(f"nist-airmf::{fid}", "NIST AI RMF", f"AI RMF: {name}", what,
        "Use as the attestation checklist spine (Sentinel): map controls/evidence to this "
        "function; the GenAI Profile (AI 600-1) enumerates GenAI-specific risks + actions.",
        f"Governance/assurance activity under the {name} function.", AIRMF_SRC, scope="compliance")

# --- NIST CSF 2.0 ---
CSF_SRC = "NIST CSF 2.0 (CSWP 29, Feb 2024) - US Gov public domain"
for fid, name, what in [
    ("GV", "Govern", "Establish and monitor the cybersecurity risk-management strategy (new in 2.0)."),
    ("ID", "Identify", "Understand assets, risks, and context."),
    ("PR", "Protect", "Safeguards to manage risk (access control, data security, training)."),
    ("DE", "Detect", "Find and analyze possible attacks/compromises."),
    ("RS", "Respond", "Act on a detected incident."),
    ("RC", "Recover", "Restore assets/operations after an incident."),
]:
    add(f"nist-csf::{fid}", "NIST CSF 2.0", f"CSF 2.0: {name}", what,
        "Governance/mapping hub: tie technical findings to CSF subcategories; OLIR provides "
        "machine-readable crosswalks to 800-53/ISO/ATT&CK.",
        f"Program-level {name} capability.", CSF_SRC, scope="compliance")

# --- NIST SSDF (800-218 / 218A) ---
SSDF_SRC = "NIST SSDF SP 800-218 v1.1 + 800-218A (GenAI, Jul 2024) - US Gov public domain"
for fid, name, what in [
    ("PO", "Prepare the Organization", "People, process, tech ready to develop secure software."),
    ("PS", "Protect the Software", "Protect all software components from tampering/unauthorized access."),
    ("PW", "Produce Well-Secured Software", "Design/build software with minimal vulnerabilities (maps to CWE-class reduction)."),
    ("RV", "Respond to Vulnerabilities", "Identify residual vulns and respond appropriately (disclosure, fix, root-cause)."),
]:
    add(f"nist-ssdf::{fid}", "NIST SSDF", f"SSDF: {name}", what,
        "Secure-SDLC framing for remediation advice; 218A adds AI-supply-chain tasks. "
        "Informative references map to OWASP (SAMM/ASVS/proactive controls) + CWE.",
        f"Secure-development practice group {fid}.", SSDF_SRC, scope="compliance")

# --- Crosswalk items (the real payoff) ---
add("xwalk::cwe-capec-attack", "Crosswalk",
    "CWE -> CAPEC -> ATT&CK",
    "A weakness (CWE) is exploited by an attack pattern (CAPEC) that maps to an adversary "
    "technique (ATT&CK). Turns a code weakness into operational adversary context.",
    "Given a CWE finding, pivot: CWE -> CAPEC attack pattern -> ATT&CK technique -> detections/mitigations.",
    "Use to enrich a vuln finding with how it is exploited and detected in operations.",
    "MITRE CWE/CAPEC/ATT&CK mappings (attack/capec.mitre.org)")
add("xwalk::owaspllm-atlas", "Crosswalk",
    "OWASP LLM Top 10 <-> MITRE ATLAS",
    "The OWASP LLM Top 10 (weakness/design lens) maps many-to-many to ATLAS techniques "
    "(adversary lens): e.g., Prompt Injection <-> AML.T0051; Sensitive Info Disclosure <-> "
    "membership/inference exfiltration; Data & Model Poisoning <-> AML.T0020.",
    "Given an OWASP-LLM category, cite the corresponding ATLAS technique(s) for red-team + "
    "detection context; the 2026 OWASP LLM edition ships official ATLAS/NIST/CWE mappings.",
    "Use to connect an LLM weakness to the AI adversary technique that exploits it.",
    "OWASP GenAI crosswalks + MITRE ATLAS")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="frameworks_rag.jsonl")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for it in ITEMS:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    from collections import Counter
    by = Counter(it["category"] for it in ITEMS)
    print(json.dumps({"frameworks_rag_items": len(ITEMS), "by_framework": dict(by),
                      "out": a.out}, indent=2))


if __name__ == "__main__":
    main()
