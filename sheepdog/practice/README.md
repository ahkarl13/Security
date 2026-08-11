# 🎯 Sheepdog Practice Range

Sharpen AK's offensive/defensive skills on **platform-sanctioned** targets, and turn every
authorized session into training signal for Sheepdog. Vault plan: `Sheepdog Practice Range.md`.

> **Hard rule (from the Sheepdog red lines):** only ever point the offensive hat at
> platform-sanctioned targets — PortSwigger's own lab instances (`*.web-security-academy.net`),
> self-hosted labs on the homelab, or HTB/THM hosts you're connected to over their VPN. The
> `hunt.py` scope gate enforces this in code; `scope.labs.json` is the honest scope file for it.

## Starting lane: PortSwigger "Web LLM attacks" path
Closest to our own writeup lab work, free, ground-truth solutions. Section sequence:
detecting LLM vulns → exploiting LLM APIs/functions/plugins → indirect prompt injection →
insecure output handling → training-data poisoning/leakage → defenses. Each maps onto a KB
layer Sheepdog already carries, so practice **validates** the KB and **expands** it where thin.

## The flywheel
1. **Capture** each session as `sessions/<id>.json` (steps + Sheepdog's analysis + ground-truth solve).
2. **Distill** with `distill.py` → a Vul-RAG KB item + a defensively-framed SFT analyst pair,
   in the exact shapes of `../rag/items.jsonl` and `../data/llmsec/llmsec_sft_train.jsonl`.
3. **Fold in** → append KB items to `../rag/items.jsonl`, rebuild the index; add SFT pairs to the set.
4. Sheepdog covers more of the taxonomy each cycle; writeups #19+ fall out of the same notes.

This directly attacks the biggest data gap: the SFT set is only **2 classes** (LLM01 ×911 /
LLM07 ×240). Working the *other* OWASP-LLM categories produces the class diversity the analyst
(and a non-skewed DPO set) needs.

## Copilot workflow (with the served `sheepdog:8b`)
- **Personal-brain hat:** ask Sheepdog to brief a lab / map a finding to OWASP/ATT&CK/ATLAS
  before you work it. See `sessions/portswigger-web-llm-01.md` for a real briefing.
- **Defensive `review.py`:** run it on the *source* of Juice Shop / WebGoat / DVWA; diff its
  findings against the official solutions (a free accuracy check).
- **Offensive `hunt.py` (scope-gated):** add the sanctioned target to `scope.labs.json` and
  have it produce the engagement plan. You execute; it plans and grounds.
- **Compare, don't outsource:** solve it yourself first, then diff against Sheepdog — the
  disagreements are the highest-value training signal.

## ⚠️ Known copilot limitation (surfaced 2026-08-11)
`sheepdog:8b` is SFT'd on only LLM01/LLM07, so it **mislabels other OWASP-LLM categories**
(it called an *Excessive Agency* / LLM06 lab "LLM01"). Detection/exploitation/fix guidance is
still sound; treat its OWASP **id** for LLM02–LLM10 as unverified until the flywheel adds those
classes. This is the #1 thing the practice range exists to fix.

## Files
```
practice/
  scope.labs.json       honest scope for hunt.py (sanctioned targets only)
  distill.py            session capture -> KB item + SFT pair
  sessions/
    _template.json      capture schema
    portswigger-web-llm-01.md   lab 1 briefing (sheepdog:8b copilot) + solve/capture notes
```
