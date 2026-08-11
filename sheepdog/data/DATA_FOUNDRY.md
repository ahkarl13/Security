# Sheepdog Phase 1 — Data foundry

Turns raw "bug reports and fixes" into two clean artifacts, reusing the training/ conventions
(matcher-as-leak-authority, split-by-family, argparse JSONL CLIs).

## Scope split
- **1a — LLM-security (for writeup #18). PRIMARY now.** Sources: our own red-team logs
  (`..\..\training\data\*.jsonl` + `judge/` + `attacker/`), writeups #1–#17, OWASP **LLM** Top 10
  (**2025** primary/official — the 2026 edition's renumbering is reported inconsistently across
  sources and the official OWASP site still serves 2025, so 2026 is carried as a provisional
  rename note, see `taxonomy.py`), AI/ML CVEs via the huntr→CVE trail, grounded-synthetic. Moat.
- **1b — software-vuln (#19+). Later.** CleanVul / SVEN / CVEfixes / GHSA.

## Two output artifacts (both split by family/project — reuse `family_split`)
1. **SFT analyst pairs** — chat format.
   - input = an attack transcript (1a) or vulnerable code + report (1b)
   - target = the **analysis**: `{category (OWASP-LLM / CWE), technique, succeeded + why, fix,
     what-to-look-for}` — **defensively framed** (the analyst explains/defends; never an attacker
     producing harm — this is the emergent-misalignment antidote).
2. **RAG knowledge items** — Vul-RAG shape:
   `{functional_semantics, root_cause, fix_pattern, category, detection_hint, source, license}`.

## Pipeline stages (shared 1a/1b)
1. **ingest** — load each raw source to a common record.
2. **dedup** — MinHash + identifier-normalized, WHOLE corpus first, THEN split.
3. **de-tangle / label-audit** — drop tangled/test-only/format-only hunks (1b); for 1a the
   `ground_truth_leak` field + `matcher.py` already give a clean success label.
4. **map / enrich** — `taxonomy.py` maps `attack_family` → category+root-cause+fix (grounded in
   writeups #1–#17); optional grounded-synthetic explanations (rejection-sampled vs the real record).
5. **format** — emit SFT (chat) + RAG (knowledge item) JSONL, split by family/project.
6. **provenance** — every record carries `source` + `license` (feeds `DATA_LICENSING.md`).

## Modules (to build, training/-style CLIs)
- `taxonomy.py` — `attack_family` → `{owasp_llm, technique, root_cause, fix, detection_hint}`,
  grounded in writeups #1–#17 (injection→LLM01, md-image exfil→LLM02/05, tool-result→LLM01/07,
  quant/temperature/transfer findings, MCP tool-poisoning, etc.).
- `build_llmsec.py` — own logs → SFT analyst pairs + RAG items. Reuse `matcher` (success label),
  `family_split` (splits), dedup by `(target_model, attack_family, seed)`.
- `ingest_owasp_llm.py` — OWASP LLM Top 10 (2025 primary; 2026 rename noted) → RAG knowledge items.
- `enrich_synth.py` — grounded-synthetic analyst explanations over real records (Phase 1a v2).
- `build_softwarevuln.py` — CleanVul/CVEfixes → pairs (Phase 1b / #19+).

## Reuse map
- `..\..\training\matcher.py` — leak/success authority.
- `..\..\training\build_attacker_dataset.py::family_split` — 70/15/15 by-family split.
- `..\..\training\jsonl_log.py` — record schema conventions.
- Pop shell for GPU steps: `..\..\training\popsh.py / poprun.py / popput.py`.
