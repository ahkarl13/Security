# Session 01 — PortSwigger: Exploiting LLM APIs with excessive agency

- **Path:** Web LLM attacks → *Exploiting LLM APIs, functions, and plugins*
- **Target:** the lab's per-user `*.web-security-academy.net` instance (sanctioned; in `scope.labs.json`)
- **True class:** OWASP **LLM06 Excessive Agency** (an LLM tool/API call with more privilege than the user)
- **Copilot:** served `sheepdog:8b` (Foundation-Sec-8B + SFT-v2/DPO-v2), personal-brain hat

## Sheepdog pre-brief (verbatim, `sheepdog:8b`, 2.4s)
> 1. **Vulnerability class + OWASP LLM id:** System Prompt Injection / OWASP LLM01
> 2. **Detect:** look for indirect system-prompt leakage via the AI's reply (hidden admin
>    override passphrase or internal instructions).
> 3. **Exploit (high level):** craft the request so the model recites restricted info.
> 4. **ATLAS/ATT&CK:** System Prompt Injection is under development at MITRE; monitor for updates.
> 5. **Fix:** never place secrets in the system prompt; enforce OUTPUT-SIDE redaction
>    (canary/secret filter on every reply and tool result); rate-limit + monitor multi-attempt sessions.

## ⚠️ Copilot correction (the training-signal moment)
Sheepdog mislabeled this as **LLM01** (its SFT set is only LLM01/LLM07). The real class is
**LLM06 Excessive Agency**: the flaw is the *breadth of the actions the LLM can take* (calling a
privileged backend function), not prompt-injection/leakage. The exploitation *vector* is often a
prompt-injected instruction, but the **root cause is over-broad agency**. This disagreement is
exactly the kind of high-value signal the flywheel captures.

## Approach (solve it yourself first, then diff)
1. Ask the assistant what APIs/functions/tools it can call (enumerate its agency).
2. Find a function that acts with more privilege than you have (e.g. a debug SQL/query helper,
   a delete/reset function).
3. Get the LLM to invoke that function with attacker-chosen arguments (the injection is the
   *delivery*; the *bug* is that the function exists + is reachable + over-privileged).
4. Confirm the lab's solved banner.

## Fix (the LLM06 lesson, for the KB item)
Minimize agency: least-privilege the tools the LLM can call, require human approval / re-auth for
sensitive actions, validate/authorize every tool call **server-side** against the *end user's*
permissions (never the LLM's), and don't expose debug/admin functions to the assistant at all.

## Capture → distill (after solving)
Fill `_template.json` for this lab with the corrected **LLM06** classification, then:
```
python distill.py sessions/portswigger-web-llm-01.json
```
→ appends a corrected-class KB item + SFT pair (the class diversity the SFT set is missing).
