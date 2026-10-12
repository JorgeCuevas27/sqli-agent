# SALSA — a local, adaptive, grammar-driven SQL-injection agent

*(SALSA = Small-model Adaptive Local SQLi Agent — working name, change freely.)*

This is the research spec for the project. It states the gap in the literature, our
contribution, the architecture, and the evaluation plan. It doubles as scaffolding for the paper.

## 1. Problem & gap

Automated SQL-injection with LLMs is active but clusters into a few shapes, all with a gap:

| Work | What it is | Limitation we exploit |
|---|---|---|
| SqliGPT (2024) | LLM black-box **detector** | detection only, cloud LLM |
| Babaey & Ravindran | GPT-4o generates 514 payloads, 89% evade ModSecurity | bulk generation, cloud, not an online adaptive agent |
| RADAGAS / RefleXQLi (2026) | RAG + reflective CoT vs 10 WAFs, 240k payloads | cloud GPT-4o; **rule-based WAFs (ModSecurity/CRS) resist: 0–5.7% bypass** |
| AdvSQLi | LLM + RL (PPO/A2C) + reward model | needs training; WAF-as-a-service target |
| BWAFSQLi (2026) | 58-rule grammar + mutation | **no LLM** (no reasoning/generality) |
| "LLM Agents can Autonomously Hack Websites" (2024) | GPT-4 agents, blind schema extraction | cloud, general, not WAF-focused |

**The pattern:** cloud models (GPT-4o), or RL training, or detection/generation only.
No one reports a **fully local, small-model, training-free agent** that adapts to a WAF online.

## 2. Contribution (novelty)

A fully **local / offline** multi-agent SQLi **exploitation** system that:

1. **Runs on a small local model (7B–14B via Ollama)** — privacy-preserving, zero API cost,
   reproducible, usable in isolated engagements. Most prior LLM SQLi work depends on cloud GPT-4o.
2. **"The LLM plans, the grammar mutates."** Surface obfuscation is produced by a *deterministic,
   token-aware transformation grammar* (code), not hand-written by the model. The LLM is reserved
   for reasoning (which methodology step, interpret the response). This fixes the failure mode of
   small models — they corrupt identifiers (`p/**/a/**/ss/**/word`) and loop on the same payload.
3. **Online, training-free WAF fingerprinting.** Within a single run the agent records which named
   transforms pass vs are blocked by *this* WAF, locks a working surface form, and prunes the rest —
   no RL, no reward model, no pre-training (contrast AdvSQLi).
4. **Schema discovery**, so the agent does not assume the target schema (no hardcoded `users` /
   `user,password`). Generalises beyond DVWA.
5. **A reproducible tiered-WAF benchmark** with *time-to-exploit* as the primary metric.

Honest framing: even cloud GPT-4o bypasses rule-based WAFs only 0–5.7% (RADAGAS). So a local agent
failing CRS is *consistent with SOTA*; succeeding on naive/rule WAFs shows the mechanism works, and
the interesting question is **how close a local small model gets to cloud results, per WAF tier.**

## 3. Architecture

```
            Orchestrator  (control loop, time-to-exploit clock)
                 │
   ┌─────────────┼───────────────────────────────┐
   │             │                                │
 Planner      Executor  ── EvasionEngine ──►  Target (interface)
 (LLM: pick   (LLM: pick     (deterministic      │  DVWATarget
  method step  base payload)  grammar + WAF       │  SqliLabsTarget
  + technique)               profile, mutates)    │  GenericHTTPTarget
   ▲             │                                │
   └── Analyst ──┴── classifies Response into a signal taxonomy, updates
       (LLM)         discovery state + WAF profile
```

Key split: **base payload** (SQL *content*, chosen by methodology/LLM) is independent of the
**surface pipeline** (chosen by the deterministic EvasionEngine). On a WAF block → keep base,
escalate surface. On WAF pass but wrong SQL → keep the locked surface, vary base.

### Response signal taxonomy
Every request is classified into exactly one: `BLOCKED` (WAF), `DB_ERROR`, `DATA` (rows dumped),
`BOOL_TRUE` / `BOOL_FALSE` (boolean-blind differential), `DELAYED` (time-based), `BENIGN` (nothing).
This taxonomy is the only thing the loop reacts to, which keeps it model-agnostic.

## 4. Methodology (discovery FSM — removes DVWA overfit)

States, each with an objective and how to read the taxonomy:
1. `CONFIRM` — is it injectable? (error / boolean / time).
2. `COLUMNS` — column count (`ORDER BY n` ramp, or `UNION SELECT 1..n`).
3. `REFLECT` — which columns are echoed back.
4. `ENUMERATE` — DBs / tables / columns via `information_schema` (skipped when target is known).
5. `DUMP` — extract the sensitive columns.

The Planner picks the next state + technique; it never assumes table/column names.

## 5. Evasion grammar + online WAF profiling  *(implemented: `src/evasion.py`)*

A set of named, **semantics-preserving, token-aware** transforms composed into pipelines:
`case`, `inline_comment`, `whitespace_tab/newline`, `versioned_comment`, `union_all`,
`term_hash/term_dash`, and the conditional `double_keyword` (for strip-once filters).
The `EvasionEngine` walks an escalation ladder, **never resends the same bytes** (fixes looping),
records per-pipeline outcomes in a `WafProfile`, and **locks** the first pipeline the WAF lets
through so later payloads reuse it. The profile (which transform first bypassed each WAF) is a
paper artifact.

## 6. Evaluation

- **Targets:** DVWA (baseline), SQLi-Labs (graded benchmark), a generic HTTP param.
- **WAF tiers:** none / naive-rule (our documented regex proxy) / ModSecurity + OWASP CRS.
- **DVWA levels:** low / medium / high.
- **Metrics:** success rate, **time-to-exploit** (vs ~10 min human baseline), steps, and the
  bypassing transform per (WAF, success).
- **Runner:** `src/experiments.py` sweeps the matrix × N runs → CSV for the paper tables.
- **Hardware:** local Ollama on an RTX 5070 (qwen2.5:7b, optionally 14b).

## 7. Status / build order

- [x] WAF harness (ModSecurity + CRS in front of DVWA) — confirmed CRS blocks naive SQLi (403).
- [x] Evasion grammar + WAF profile (`src/evasion.py`) + unit tests.
- [x] EvasionEngine wired into the orchestrator (content/surface decoupling) + flow tests.
- [x] Naive-rule WAF proxy (middle tier, `waf/`) + bypass tests.
- [ ] `Target` interface + refactor DVWA into `DVWATarget`.
- [ ] Discovery FSM wired into Planner/Analyst (remove remaining DVWA overfit).
- [ ] Experiment runner + CSV.
- [ ] SQLi-Labs + generic HTTP targets.
