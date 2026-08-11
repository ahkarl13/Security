# Writeup #19 — An application-layer security-review agent: grounding a code reviewer in a curated vulnerability KB

**TL;DR.** Most vulnerabilities that matter originate at the *application layer* — the code, not the network. So the second Sheepdog deliverable is a **defensive code-review agent**: a reasoning model plus retrieval over a curated **206-item knowledge base** (OWASP Top 10:2025, the 2025 CWE Top 25, memory-safety CWEs, a 49-class CWE reference, and MITRE/NIST framework + penetration-testing methodology). Given source code, it retrieves the relevant vulnerability knowledge and produces a **grounded** review — every finding located, classed by CWE/OWASP, severity-rated, explained in a sentence, and given a concrete fix.

- On a planted-vulnerability sample, the **27B + RAG** configuration caught **all six** issues with the correct CWE ids (SQLi CWE-89, command injection CWE-78, path traversal CWE-22, XSS CWE-79, weak-hash CWE-328/916, hard-coded secret CWE-798) — and the fixes were real.
- On an external benchmark (**CTIBench `cti-rcm`**, real CVE → CWE), the security-pretrained base already maps 62.5% correctly, and **relevant** retrieval lifts it — while **irrelevant** retrieval hurts. That relevance-is-everything result is carried over from writeup #18 and is the whole reason the KB is curated, not scraped.

This is the application-layer companion to writeup #18 (which measured *fine-tune vs RAG*). Here the question is narrower and more practical: **can a commodity model + a good knowledge base review real code and ground what it finds?**

## Why the application layer

Network and infra hardening gets the attention, but the recurring finding across the industry is that the large majority of exploitable weaknesses live in the application: injection, broken access control, unsafe deserialization, secrets in code, weak crypto, memory-safety bugs in native code. That's also where a knowledge-grounded assistant has the most leverage — the failure modes are well-catalogued (CWE, OWASP), so a reviewer that can *retrieve the right catalog entry* and apply it to the code in front of it can be both accurate and auditable.

So the design goal wasn't "a model that has memorized every CVE." It was "a model that, for the code in front of it, pulls the right vulnerability class from a curated reference and grounds each finding in it." Knowledge lives in the KB; the model supplies reasoning and code understanding.

## The knowledge base (206 items, curated not scraped)

| Layer | Items | Source |
|---|---|---|
| LLM-security | 28 | my own red-team logs (writeups #1–17), mapped to OWASP LLM Top 10 |
| Application-layer | 27 | OWASP Top 10:2025 web + 17 of the 2025 CWE Top 25 classes |
| CWE reference | 49 | common CWEs (crypto, auth, session, creds, config, injection variants, info-exposure, resource, XXE, SSRF, ReDoS) |
| Memory-safety | 12 | native/memory-safety CWEs (CWE-787/416/125/120/476/121/122/190/362/415/401/369) |
| Frameworks | 36 | MITRE ATT&CK/ATLAS, NIST AI RMF / CSF 2.0 / SSDF, plus CWE↔CAPEC↔ATT&CK and OWASP-LLM↔ATLAS crosswalks |
| Pentest methodology | 44 | box + depth levels, the 11-phase lifecycle, 10 standards (PTES/WSTG/NIST 800-115), 14 surfaces |

Each item is a small structured record (technique, functional semantics / root cause, fix pattern, CWE/OWASP/ATT&CK tags, detection hint), embedded with `qwen3-embedding:8b`; retrieval is cosine over a local index, top-k injected as context. Nothing here is scraped from bounty platforms or dumped from a CVE feed — it's a curated reference so retrieval stays *relevant*, which writeup #18 showed is the entire ballgame for RAG value.

One honest note the KB earns its keep on: the base model's OWASP knowledge is **2021-edition** (it will happily write "A05:2021"), while the current web standard is **OWASP Top 10:2025** and the current weakness list is the **2025 CWE Top 25**. Carrying the current taxonomy in the KB — rather than trusting the model's frozen training — is exactly what retrieval is for.

## The agent

`sheepdog/agent/review.py`. The pipeline is deliberately boring:

1. **Ingest** the source file (or a code string).
2. **Optional static pass** — if Semgrep is installed, run it and fold its findings in as hints; if not, skip and rely on the model + KB.
3. **Retrieve** the top-k relevant KB items for the code (plus any Semgrep hints).
4. **Ground** — hand the model the code, the static hints, and the retrieved knowledge, with a system prompt that forces a fixed finding shape and a hard "do not invent line numbers or issues that aren't present" instruction. It is a *defender*: it hardens code, it does not weaponize it.

Output per finding: location, vulnerability class with CWE and/or OWASP id, severity (Critical/High/Medium/Low), a one-sentence explanation, and the concrete fix — ending in a prioritized remediation summary. Per writeup #18, knowledge matters most for review, so the default is a capable reasoner + RAG (`qwen3.6:27b` via Ollama); the fine-tuned Sheepdog behavior model can be swapped in once served.

## What it catches

Against a deliberately vulnerable sample (SQL injection, OS-command injection, path traversal, reflected XSS, MD5 password hashing, a hard-coded API key), the **27B + RAG** review found **all six**, each correctly classed and fixed:

- **SQL injection** — `get_user`, string-concatenated query → **CWE-89**, Critical, parameterized-query fix.
- **OS command injection** — `ping` with `shell=True` → **CWE-78**, Critical, argument-list + `shell=False` fix.
- **Path traversal** — `read_report` concatenating user input into a path → **CWE-22**, High, `basename` + realpath-containment fix.
- **Reflected XSS** — `render` interpolating input into HTML → **CWE-79**, High, `html.escape` / auto-escaping-template fix.
- **Weak password hash** — MD5 → **CWE-328/916**, Medium, bcrypt/scrypt/argon2 fix.
- **Hard-coded secret** — module-level API key → **CWE-798**, Medium, env-var / secrets-manager fix.

A smaller model (`llama3.1:8b`) run on the same sample caught the obvious injections but **missed** the path-traversal and the MD5 issue and mislabeled the XSS — a concrete illustration of the size/knowledge tradeoff from #18: the capable reasoner over the same KB is meaningfully sharper on the subtle findings.

## Does it generalize? (real CVEs)

Catching planted bugs is table stakes; the harder question is real, unseen vulnerabilities. On **CTIBench `cti-rcm`** (a held-out benchmark of real CVE → CWE mappings) the security-pretrained base (`Foundation-Sec-8B`) already scores **62.5%**, and retrieval helps **where the KB covers the weakness class**. When I first ran it, the KB was application-layer-only and CTIBench is dominated by *memory-safety* CWEs — so retrieval surfaced irrelevant items and barely moved the number. Adding memory-safety CWEs and the 49-class CWE reference (145 → 206 items) flipped that: relevant retrieval then *helped*, and the effect was cleanest on the larger model, where the same retrieval that **hurt** it off-topic began to **help** it once the KB covered the topic. The lesson is the KB-coverage lesson from #18, restated at the application layer: **retrieval is only as good as its relevance, so invest in curated coverage.**

## The two hats

The reviewer above is the **defensive** hat — public, portfolio, and the seed of a larger review pipeline. There is a **private, scope-gated offensive counterpart** for *authorized* validation (prove a candidate weakness is real so it gets fixed). It refuses to operate on anything outside an explicit, validated authorization scope — the gate is enforced in code, before any model call — and its tooling and any weights are **never published**. Authorized, scoped testing only; that lane stays local by design, so this writeup describes it but ships none of it.

## Honest caveats

- The planted-vuln walkthrough is a demonstration, not a benchmark; the real-CVE numbers (n≈40) are directional.
- Scoring on CTIBench is exact CWE-id match, not human-graded reasoning quality.
- The agent reviews what it's given — it is a grounded reviewer, not a whole-repo taint-analysis engine; pair it with real static analysis (Semgrep) for coverage.
- Retrieval quality is the ceiling: a weakness class the KB doesn't cover won't be grounded, only guessed.

## Reproduce

`sheepdog/agent/review.py` (the reviewer), `sheepdog/rag/` (index + query/answer), and `sheepdog/data/` (the ingest scripts that build the 206-item KB: `ingest_appsec.py`, `ingest_cwe_ref.py`, `ingest_memsafe.py`, `ingest_frameworks.py`, `ingest_pentest.py`, plus the OWASP-LLM taxonomy). Real-CVE harness and the fine-tune/RAG evals that motivate the design are in `training/` and documented in writeup #18.
