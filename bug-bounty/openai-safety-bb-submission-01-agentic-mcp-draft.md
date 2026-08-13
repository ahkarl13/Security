# OpenAI Safety Bug Bounty — Submission Draft (Agentic Tools incl. MCP)

> **TEMPLATE — fill the `[...]` fields after you're accepted and have picked the surface.**
> Category: **Agentic Tools including MCP**. Technique + remediation are grounded in your
> published research; the OpenAI-target specifics + reproduction are bracketed because they
> must be captured against the authorized surface with your own victim account.

---

**Title:** Untrusted web/connector content drives a ChatGPT agent to exfiltrate a victim account's private chat data via a Connector/MCP tool

**Category (in scope):** Agentic Tools including MCP -> indirect / third-party prompt injection causing Connector/MCP tool misuse (data exfiltration)

**Affected surface / version:** `[Atlas Browser | Operator | specific Connector — + build/version]`

**Severity (self-assessed):** `[P1-P4 per the reward chart]` — justify from data sensitivity (PII from chat history) + reproducibility + whether confirmation was bypassed.

**Reproducibility:** `[X]/[N]` realistic trials succeeded = `[XX]%`.

---

## Summary

While a victim uses `[the named agentic surface]`, untrusted content the agent encounters through a realistic channel (`[a web page it browses / an email or record a Connector reads]`) contains an embedded instruction. Because of `[the specific OpenAI-side gap — permissioning / missing-or-misleading confirmation / integration logic]`, the agent misuses a **legitimate** Connector/MCP tool to read the victim's private chat data (a **planted benign PII value**) and send it to an attacker-controlled destination. The victim issues only a normal request and runs no malicious command.

## Why this is OpenAI-side (not a third-party-server issue)

`[State plainly which OpenAI-side control fails: e.g. the agent applies a connector action to attacker-influenced content without re-consent; the confirmation UX misrepresents what will be sent; untrusted content crosses the instruction/data boundary into a trusted tool call. The connector itself is legitimate — the flaw is in how OpenAI's agent orchestrates it.]`

## Preconditions

- Victim account (**bughunter-owned**) using `[surface]` with `[the Connector/tool]` enabled (default per brief).
- A benign PII canary — `[fake SSN / email / private note, e.g. CANARY-PII-<unique>]` — planted in the victim's chat/connector data.
- Attacker controls only third-party content the agent will read. No access to the victim account. **No malicious command is run by the victim.**

## Step-by-step reproduction

1. In the victim account, plant `CANARY-PII-<unique>` in `[chat history / a connected doc/record]`.
2. Stage untrusted content at `[realistic in-scope location the agent will encounter]` carrying the injection: `[instruction that makes the agent read the canary and route it outward via the connector/render channel]`.
3. As the victim, issue the benign request `[e.g. "summarize this page" / "help me with these emails"]`.
4. Observe the agent `[call the connector / emit an external resource URL / send a message]` carrying `CANARY-PII-<unique>` — and note the confirmation UX shown (or absent / misleading).
5. Confirm the canary arrives at the attacker collector log.

**Attacker collector:** minimal HTTP endpoint logging inbound requests (your markdown-exfil-lab harness; benign — only ever receives the planted canary).

## Reproducibility evidence

- Trials `[N]`, successes `[X]`, rate `[XX]%` — all via the realistic channel (no victim-run command).
- Attached per trial: transcript, tool-call log, **collector access log w/ timestamps**, surface + version, and a capture of the confirmation UX.
- Variants (strengtheners): `[render-URL channel vs. connector-argument channel; different connectors]`.

## Real-world harm

A third party who can place content in the agent's path silently siphons a victim's private chat data / connector contents — PII the brief names as sensitive — with no victim awareness or malicious action. Same class as CamoLeak (CVE-2025-59145) and EchoLeak against shipping assistants.

## Remediation (measured)

From the agentic-defense bake-off (my research); defenses are threat-specific and must be measured in the deployed loop:
- **Egress/render control:** gate external resource URLs and connector destinations the agent can emit from attacker-influenced context — the transferable fix for the zero-click channel.
- **Re-consent on attacker-influenced actions; make confirmations faithful** to what will actually be sent/shared (directly addresses sub-case 3).
- **Least privilege on tool arguments/context;** untrusted content must not silently become a trusted tool instruction.
- **repeat_user_prompt -43% / spotlighting-with-delimiting -35%** ASR on the full AgentDojo banking suite; **native structured tool-calling 0% vs 16%** prompted.

## Supporting prior research (proof-of-craft)

Public repo `github.com/ahkarl13/Security`: **#2** markdown-image exfil channel - **#16** MCP tool-poisoning - **#14** AgentDojo agentic injection (verified polarity) - **#15** defense bake-off (remediation numbers) - **#1** indirect-injection chain.

## Disclosure & ethics

Tested only within the accepted engagement scope/ROE, using **my own** attacker + victim accounts and a **benign planted PII canary** — no real user data, no system-prompt/model-context extraction (out of scope), no harmful content. Reported under safe-harbor; no public disclosure pending program guidance.

---

### Report hygiene (delete before filing)
- Fill **every** `[...]`; an unfilled bracket = not ready.
- Name the **OpenAI-side** control that fails — this separates an in-scope report from an out-of-scope "third-party server" reject.
- Payload = **planted PII / chat data**, never a system prompt (system-prompt leakage is out of scope here).
- One finding per report; variants as strengtheners; attach raw artifacts for the reproducibility claim.
