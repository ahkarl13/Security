# OpenAI Safety Bug Bounty — Launch Plan

**Lane:** AI Security (bug-bounty bolt-on income stream)
**Program chosen:** OpenAI Safety Bug Bounty — **Agentic Tools including MCP** + **Codex**
**Prepared:** 2026-08-13 · updated with the live BugCrowd engagement brief (all categories)
**Status:** pre-registration — plan + first-report drafts ready; AK executes the account + authorized testing steps

---

## 0. One-paragraph orientation

OpenAI's *Safety* Bug Bounty pays for **agentic** failures — an attacker hijacking someone's ChatGPT agent via untrusted content, exfiltrating data through an agent's Connector/MCP tools, driving high-impact actions without confirmation, or (Codex) making a coding agent execute beyond its sandbox/approval guardrails. It does **not** pay for plain jailbreaks or system-prompt / model-context leakage. Two categories fit your moat directly: **Agentic Tools including MCP** (highest per-find) and **Codex** (fastest to a first filing — you test it on your own machine). Both are indirect-injection-driven and need **zero harmful content**.

## 0b. The full engagement board — where you fit

| Category | P1 reward | Fit to your moat | Note |
|---|---|---|---|
| **Agentic Tools incl. MCP** | **$5.5k-7.5k** | **HIGH — lead** | Indirect injection -> Connector/MCP data exfil / unauthorized action, in your own victim account |
| **Codex** (CLI/App/IDE/Web + sandbox) | $500-1.5k | **HIGH — fastest first** | Attacker-controlled repo/file/prompt -> execution beyond guardrails; test on your own machine |
| Proprietary Information | $5.5k-7.5k | LOW | Only **full unsummarized CoT** in scope; system prompts explicitly **out** |
| Account & Platform Integrity | $5.5k-7.5k | LOW | Rate-limit bypass (>=1,000 completions on Sol, <=5 accts/day) or mass account creation |
| OpenAI Research Org (`openai.org`) | $1.25k-3.5k | MED (appsec) | Classic web/API testing — future Sheepdog appsec lane |
| Other OpenAI Targets (`openai.com`, docs, playground) | $1.25k-2.5k | MED (appsec) | Classic web/infra testing |
| Third-Party Corporate Targets | $5k flat / P1 | LOW | **OSINT only** — find leaked OpenAI *corporate* docs on SaaS vendors; no active testing of those vendors; single docs usually P4/P5 (unpaid) |
| OpenAI API Keys | $250-2.5k | LOW-MED | Report leaked `sk-`/`sess-` keys via the **special form, NOT BugCrowd**; monthly ranked bonus only |

Your two lanes below are **Agentic Tools incl. MCP** (sections 2-6) and **Codex** (section 6b).

---

## 1. Program facts (from the live engagement brief, 2026-08-13)

| Item | Detail |
|---|---|
| Program | OpenAI Safety Bug Bounty — launched 2026-03-25, on **BugCrowd** |
| Entry | `openai.com/index/safety-bug-bounty/` -> **Apply** -> BugCrowd engagement |
| **Reward (real, tiered)** | **P1 $5,500-7,500 - P2 $2,500-3,500 - P3 $750-1,500 - P4 $250-500** |
| Headline "$100k" | Press ceiling for *exceptional/differentiated* cases — the **tiered chart above governs** ordinary findings |
| Repro bar | Injection findings need realism + feasibility; **no reliance on the victim running malicious/dangerous commands** |

### Category we're targeting: **Agentic Tools including MCP**
"Abuse risks in agentic products" = any product that **acts on behalf of the user** or **accesses data as the user**. Named in-scope surfaces: **Atlas Browser, Codex, Operator, Connectors, and other agentic ChatGPT tools.**

**In scope (the four sub-cases):**
1. **Indirect / third-party prompt injection or untrusted-content** that makes an agent **misuse a Connector/MCP tool** to access, exfiltrate, or transform sensitive data from a **bughunter-owned "victim" account**, or take a harmful action under it. *Extracting PII from chat history counts as sensitive data.*
2. **Authorization / permission bypass** — agent accesses Connector/MCP data or performs actions beyond user/workspace/app permissions (incl. **cross-workspace / cross-tenant**).
3. **Missing or materially misleading confirmation** — tool actions taken without appropriate user understanding, especially high-impact ones (sharing/exporting data, changing settings, posting/sending messages).
4. **Disallowed action at scale** — misusing an agentic tool to create **>=10 OpenAI accounts without human interaction**.

**Out of scope (read carefully — these bite your old framing):**
- Issues **solely in a third-party service** with no OpenAI-side remediation (e.g. a poorly-annotated *third-party* MCP server). The flaw must be in **OpenAI** systems / config / permissioning / confirmation-UX / integration logic.
- **System prompts** and **any info in the model context window at inference time except CoT** — so a system-prompt / passphrase leak is **NOT** a valid finding here.
- Plain jailbreaks / content-policy bypasses without demonstrable harm.
- Testing accounts / data you don't own.

---

## 2. Scope-map — your portfolio -> this category

| Your writeup | Technique proven | Maps to sub-case | Submittable as-is? | Gap to close |
|---|---|---|---|---|
| **#16 MCP tool-poisoning** — tool shadowing 100%, suggestive-param exfil 17-33% | Hostile tool metadata steers selection + argument-filling | 1 (Connector/MCP misuse) | **No** (local; flaw must be OpenAI-side, not a bad 3rd-party server) | Reproduce on a **real OpenAI Connector/MCP** where OpenAI-side logic lets the misuse happen; exfil **planted PII**, not a system prompt |
| **#2 Markdown-image zero-click exfil** (CamoLeak/EchoLeak class) | Agent renders attacker URL -> silent exfil | 1 (exfil) | **Partial** — strongest lead | Reproduce on Atlas Browser / a Connector surface that fetches external resources; payload = planted chat-history PII -> your collector |
| **#14 AgentDojo agentic injection** — native 0% vs prompted 16% | Untrusted instruction hijacks a tool-using agent task | 1 (harmful action) or 3 (missing confirm) | **No** (local) | Reproduce on Operator/Atlas doing a real task; show an unauthorized send/share **without proper confirmation** |
| **#1 Indirect injection** -> exfil chain | Foundational untrusted-content -> tool-misuse chain | 1 | **No** (local) | Basis for the chain; retarget to a named surface |
| **#15 Agentic defense bake-off** | Which mitigations move ASR | — | **N/A** | Feeds the **Remediation** section |

**Lead pick: sub-case 1 — indirect-injection data exfil of planted PII** (Atlas Browser or a Connector). Clearest harm story, PII-from-chat-history is *named* as sensitive, and #2 + #16 already prove the primitive. **Second lead: sub-case 3** — a high-impact send/share action under a materially misleading (or absent) confirmation, driven by untrusted content.

---

## 3. The gap that matters: local PoC -> OpenAI-target finding

Three things must all be true for a payable report, and your local results satisfy none yet:
1. **Named OpenAI surface** — Atlas Browser, Operator, Codex, or a Connector/MCP integration (not Ollama).
2. **OpenAI-side flaw** — the abuse must trace to OpenAI's permissioning / confirmation-UX / integration logic, *not* to a deliberately-bad third-party server (the out-of-scope trap your #16 shadowing setup could fall into — a hostile third-party MCP server alone isn't OpenAI's bug; you need OpenAI-side logic that lets untrusted content drive a *legitimate* connector into misuse).
3. **Realistic trigger + real harm** — untrusted content arriving the way it really would (a web page the agent browses, an email/record a Connector reads), **not** the victim pasting a malicious command; harm = planted PII leaving your victim account, or an unauthorized high-impact action.

Your harnesses are the engine: `md-exfil-lab/` + collector (the exfil channel), `training/mcp_poison.py` (tool-selection/param manipulation — reframed to a legit connector), `training/adj_run.py` (the agent-task/confirmation driver).

**"Reproduce" concretely:** in your **own** bughunter victim account, plant benign PII (a fake "SSN"/email/note you control), stage the untrusted content, and show the PII reaching *your* collector — or the unauthorized action firing — with clean, realistic steps. Capture full transcripts + network evidence; note the confirmation UX you bypassed.

---

## 4. Registration / apply — step by step

1. **BugCrowd account** — create/verify at `bugcrowd.com`.
2. **Apply** from `openai.com/index/safety-bug-bounty/` -> the Safety engagement. Don't test until accepted.
3. **Read the full engagement brief** on the live page (targets/ROE/safe-harbor). It's binding and supersedes this doc.
4. **Two test accounts you own** — an "attacker" and a "victim," per ROE; plant benign PII in the victim. Never touch a real user's agent.
5. **Confirm safe-harbor + disclosure** before probing.

---

## 5. Evidence checklist (per finding)

- [ ] Realistic untrusted-content trigger (no victim-run malicious command).
- [ ] Named OpenAI surface + version string recorded.
- [ ] Flaw is OpenAI-side (state exactly which permission/confirmation/integration-logic gap).
- [ ] Run repeatedly; report success rate; attach per-trial transcripts + **network proof** of PII hitting your collector (or the action firing).
- [ ] Benign planted PII only — never real user data or real secrets.
- [ ] Note the confirmation UX bypassed / mitigations defeated (strengtheners).
- [ ] Remediation from #15's measured defenses.

---

## 6. Ranked submission queue (Agentic-MCP)

1. **Indirect-injection PII exfil via a Connector/Atlas** (sub-case 1) — untrusted content -> agent misuses a legit connector -> planted chat-history PII -> your collector.
2. **Unauthorized high-impact action w/ missing/misleading confirmation** (sub-case 3) — untrusted content drives Operator/Atlas to send/share/export under your victim account.
3. **Permission / cross-workspace bypass** (sub-case 2) — if you can show an agent reaching connector data beyond its granted scope.

File one at a time, strongest first; roll variants in as strengtheners.

---

## 6b. Second lead lane — Codex (the fastest path to a first filing)

**Why this may go first:** you test Codex entirely **on your own machine, with your own data** (the brief says so), so there's no victim-account setup, no connector plumbing, and no third-party-server out-of-scope trap. The in-scope vuln class is your specialty rephrased for a coding agent.

**Surfaces:** Codex CLI, App, IDE, and Web — plus its sandbox (macOS Seatbelt / Linux Landlock or Bubblewrap / Windows elevated).

**In scope (what to hunt):**
- **Attacker-controlled input -> execution beyond guardrails.** A poisoned **repository** — a crafted README / source comment / config / test file — that, when Codex reads or works the repo, causes an action beyond intended guardrails (indirect prompt injection landing on a coding agent — your #1/#14/#16 skill).
- **Sandbox / boundary bypass** under default/intended config:
  - *Filesystem:* writing/modifying files **outside** the allowed workspace/write roots, or changing protected config to broaden capability. (**Reading files on disk is explicitly NOT a bypass** — don't submit reads.)
  - *Network:* making outbound requests when networking should be denied/restricted.
  - *Process/OS:* launching processes or reaching OS resources (keychain/credential stores, privileged APIs) that policy should block.
- **Approval/confirmation bypass** — actions occurring without the required user acknowledgment.

**Explicitly out (don't waste a report):**
- Anything requiring a `--dangerously-bypass` / "YOLO" / no-sandbox / no-approval mode.
- Social-engineering the user into running commands **outside** Codex; user-installed malware; root/admin-only assumptions.
- Reading files (not a bypass); pure perf / "bad advice" / non-security bugs; DoS needing sustained traffic; unreleased/experimental-not-default features. (Minor Codex-web UI findings = P5 informational, unpaid.)

**Concrete first PoC (on your machine):** a benign test repo whose content carries an indirect instruction; open it with Codex under **default** sandbox/approval; demonstrate one guardrail crossing — e.g. Codex **makes an outbound request to your own collector** when networking should be denied, or **writes a file outside the workspace root**, triggered by the repo content and **without** the approval the policy requires. Benign payload only; prove the crossing, capture the transcript + the sandbox policy in effect, stop.

**Reward reality:** Codex P1 $500-1.5k (lower per-find than the MCP lane's $5.5-7.5k), but the shortest path to your first *accepted* report and a clean portfolio proof point. Run Codex for the fast first win; run the MCP-exfil lane for the bigger payouts.

---

## 7. Legal / scope guardrails (your standing rules, applied)

- Only your **own** attacker + victim test accounts (Codex: your own environment/data); never a real user's agent.
- **Benign planted PII/canary only**; no real data, no real secrets; no CBRN/harmful content (out of scope anyway).
- Flaw must be **OpenAI-side**; don't dress up a third-party-server bug.
- Realism bar: no "victim runs a dangerous command" PoCs; Codex: no unsafe/YOLO mode.
- Stay in safe-harbor; **stop at proof**; no escalation/persistence/scale.

---

## 8. Do-next checklist

- [ ] **AK:** BugCrowd account -> apply -> read the full brief
- [ ] **Fast path (Codex, 6b):** install Codex CLI/IDE locally, build the benign poisoned-repo PoC, capture one guardrail crossing under default sandbox -> file with the Codex draft
- [ ] **Payout path (MCP, 2-6):** stand up attacker + victim accounts; plant benign PII; pick Atlas Browser or a Connector; retarget the exfil harness; capture realistic repro + network evidence -> file with the agentic draft
- [ ] Fill each draft's `[...]` from the live brief before filing
- [ ] Log submissions to vault (`AI Security.md`) + repo

---

*Sources: the live OpenAI Safety BB BugCrowd engagement brief (pasted 2026-08-13) — binding; OpenAI Safety Bug Bounty announcement (openai.com/index/safety-bug-bounty/).*
