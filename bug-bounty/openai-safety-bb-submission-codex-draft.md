# OpenAI Safety Bug Bounty — Codex Submission Draft

> **TEMPLATE — fill `[...]` from your own local reproduction.**
> Category: **Codex**. Test only in your **own** environment/data. Benign payloads only
> (a canary write / a request to your own collector). Prove the boundary crossing, stop.

---

**Title:** Attacker-controlled repository content drives Codex to `[make a denied outbound network request / write outside the workspace root / act without required approval]` under default sandbox

**Category (in scope):** Codex -> attacker-controlled input causes execution beyond intended guardrails (`[sandbox bypass | network boundary bypass | approval bypass]`)

**Surface / config:** `[Codex CLI | IDE | App | Web]`, version `[x]`, sandbox `[macOS Seatbelt | Linux Landlock (default) | Linux Bubblewrap | Windows elevated]`, **default/intended settings — no unsafe/YOLO mode**.

**Severity (self-assessed):** `[P1-P4]` per the Codex chart — justify from which boundary is crossed and the impact.

---

## Summary

A benign-looking repository contains attacker-controlled content (`[a crafted README / source comment / config / test fixture]`). When a user opens the repo with Codex and issues an ordinary request (`[e.g. "explain this project" / "run the tests" / "fix the build"]`), the embedded content causes Codex to `[perform the guardrail-crossing action]` — an action the default sandbox/approval policy should block. The user runs no unsafe flag and takes no action beyond a normal Codex request.

## Boundary crossed (be specific — this is the whole report)

`[Pick one and detail it:]`
- **Network:** Codex issued an outbound request to `[your collector URL]` while networking was `[denied/restricted]` under the active policy. *(Reading files is NOT a bypass — this must be an action, not a read.)*
- **Filesystem:** Codex wrote/modified `[path outside the allowed workspace/write root]`, outside the permitted roots.
- **Process/OS:** Codex launched `[process]` / accessed `[keychain / credential store / privileged API]` that policy should block.
- **Approval:** Codex performed `[high-impact action]` without the required user acknowledgment / with a materially misleading confirmation.

## Preconditions

- Codex `[surface]` on `[OS]`, **default** sandbox + approval settings (state them exactly).
- A **trusted/normal project** context — not an unsafe mode. `[If "trusted projects" is relevant, note how the attacker content still lands.]`
- Attacker controls only repository content the user opens. No host compromise, no root, no social-engineered command.

## Step-by-step reproduction

1. Create repo with `[the crafted file + the injected instruction]`. (Payload benign: `[a write of CANARY-<unique> / a GET to your collector]`.)
2. Open it in `[Codex surface]` under default config.
3. Issue the ordinary request `[...]`.
4. Observe Codex `[perform the boundary-crossing action]` — capture the exact policy that should have blocked it.
5. Confirm the effect: `[canary file at the out-of-root path / the request in your collector log / the action taken with no approval prompt]`.

## Reproducibility evidence

- Trials `[N]`, successes `[X]`, rate `[XX]%`, all under default config.
- Attached: full Codex transcript/session log, the repo, the active sandbox policy, and proof of the crossing (`[collector log / filesystem listing / process trace]`), version string.

## Real-world harm

Developers routinely open untrusted repos in Codex. An attacker who controls repo content can `[exfiltrate via the denied network path / plant/modify files outside the workspace / trigger an unapproved action]` on the developer's machine — execution beyond the sandbox is the harm, no user misstep required.

## Remediation

- Treat repository content as **untrusted data**, never as instructions that can widen sandbox/network/approval scope (instruction/data boundary — the through-line of my research).
- Enforce the intended boundary regardless of in-repo content; require genuine, faithful approval for the crossed action.
- `[If Linux Landlock allowed the write: note the Bubblewrap experimental fix — codex -c features.use_linux_sandbox_bwrap=true — and whether it closes it.]`

## Supporting prior research (proof-of-craft)

`github.com/ahkarl13/Security`: **#16** MCP tool-poisoning - **#14** AgentDojo agentic injection - **#1** indirect-injection -> action chain - **#15** agentic defenses.

## Disclosure & ethics

Tested only in my own environment/data, default config, benign canary payloads — no host compromise, no unsafe mode, no social engineering, no reading-only "bypass." Reported under safe-harbor.

---

### Report hygiene (delete before filing)
- The report **is** the boundary crossing — name the exact policy that should have blocked the action.
- Never submit a file **read** as a bypass, or anything needing an unsafe/YOLO flag — both are explicit out-of-scope.
- Benign payloads only; prove and stop.
