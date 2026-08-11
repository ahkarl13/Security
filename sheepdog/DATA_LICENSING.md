# Sheepdog — Data provenance & licensing ledger

Every source used for training or RAG gets a row here BEFORE it enters `data/`.
Because Sheepdog is "combination" framing (portfolio + possible Sentinel component), keep
rights clean. If a source can't be placed in a row with a compatible license + attribution,
it does not go in.

Legend — **Use**: RAG (knowledge items) / SFT (train pairs) / EVAL-ONLY (never train on it).

## Tier 1 — licensed public (the core)

| Source | Content | License | Use | Caveat |
|---|---|---|---|---|
| NVD / CVE (nvd.nist.gov) | CVE records, CVSS, CWE map, refs | US-gov **public domain** | RAG + labels | NVD enrichment backlog since 2024 — cross-fill w/ OSV/GHSA |
| GitHub Security Advisories (`github/advisory-database`) | Curated advisories + fix commits + CWE | **CC-BY-4.0** | RAG + SFT | Attribution required |
| OSV.dev (bulk `all.zip`) | 18+ ecosystems aggregated | mostly **CC-BY-4.0** (per-source) | RAG | Check per-source license |
| CWE (MITRE) | ~940 weakness taxonomy + examples | Free w/ attribution | RAG + "what to look for" SFT | — |
| CERT Secure Coding (SEI/CMU) | rule → noncompliant → compliant → risk | © CMU, reuse-restricted | RAG + SFT seeds | Respect CMU reuse terms; don't redistribute raw |
| OWASP Top 10 + **LLM Top 10** + Cheat Sheets | risk categories + remediation prose | **CC-BY-SA-4.0** | RAG + SFT | ShareAlike = copyleft on derived text |
| CleanVul (`yikun-li/CleanVul`) | ~8.3k @97% / 11.6k @91% function-level vuln/fix | open (verify repo) | SFT (primary) | Java-heavy; verify license before any release |
| CVEfixes / MoreFixes | fix-diff corpus (regenerable) | **CC-BY-4.0** (+MIT code) | SFT (after cleaning) | ~48% commit-label noise — MUST clean |
| SVEN | ~1.6k hand-verified pairs, 9 CWEs | MIT | SFT (gold) | narrow |

## Tier 1 — EVAL ONLY (never train on these)

| Source | Content | License | Note |
|---|---|---|---|
| PrimeVul | ~7k vuln/229k, dedup, chrono split | MIT | honest floor; VD-Score + pairwise |
| VulnPatchPairs | 26.2k C paired (vuln vs its own patch) | research | diagnostic — did we learn or cheat |
| SecVulEval / SeCodePLT | context-rich detection + patch bench | open | eval |
| CTIBench | CTI MCQA + CVE→CWE (RCM) + ATT&CK (ATE) | open | the 8B sweet spot |

## Tier 2 — our own (clean provenance, the moat)

| Source | Content | Use | Note |
|---|---|---|---|
| Our red-team logs (`..\training\data\*.jsonl`) | singleturn/multiturn/judge/attacker transcripts | SFT (LLM-security hat) | fully ours; the OWASP-LLM-Top-10 material nobody else has |
| Our writeups #1–#17 | vuln→PoC→fix narratives w/ before/after | RAG + SFT | already defensively framed |

## Tier 3 — bounty-derived via CVE trail (NOT scraping)

| Path | Content | Use | Rule |
|---|---|---|---|
| huntr / other disclosures → assigned CVE + fix PR | AI/ML supply-chain vulns | RAG + SFT | ingest the **licensed** CVE/PR artifacts only; never scrape the platform |

## Tier 4 — grounded synthetic

| Path | Content | Use | Rule |
|---|---|---|---|
| strong model *explains* a real diff | vuln/fix explanation pairs | SFT volume | anchor to a REAL diff, never invent; rejection-sample vs ground-truth patch; mind teacher-model distillation ToS |

## DO-NOT-USE (the traps)
- **BigVul (25% correct), Devign/CodeXGLUE (24%)** — radioactive label noise.
- **HackerOne/huntr/Bugcrowd report text** — ToS prohibits training; disclosure-confidential.
- **Snyk DB / CodeQL queries** — proprietary / restricted derivative use (don't bake into a shippable model).
- **MegaVul** — GPL-3.0 copyleft; only if we accept that on any derived artifact.

## Cleaning gate (every Tier 1/3/4 row passes this before `data/`)
1. Dedup the WHOLE corpus first (MinHash + identifier-normalized), THEN split.
2. Drop tangled / test-only / format-only hunks (where ~40–75% of mislabels live).
3. LLM-aided label audit on survivors; keep an FP/FN audit bucket (mirror `..\training` judge_to_audit).
4. Record source + license + attribution here.
