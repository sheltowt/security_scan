# security-scan

A coding-agent skill that turns your agent into a security auditor. It is a derivative of Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill) and keeps its source-first method: isolated hunters work from a deterministic coverage ledger, every candidate goes to a verifier that tries to disprove it, output is schema-validated with `confirmed` / `needs_validation` / `rejected` verdicts, and severity comes only from demonstrated impact. On top of that it adds the strongest practices from the other open-source AI security harnesses.

## What's new compared with upstream

| Addition | What it does | Inspired by |
|---|---|---|
| **Phase 0 prefilter** (`tools/prefilter.cjs`, 90+ signatures) | Deterministic regex triage before any agent runs. Ranks hotspots, seeds hunters with `file:line` leads, and never copies source text (lines can contain secrets). Costs no agent invocations. | deepsec, ai-deep-sast |
| **SAST import** (`tools/import-sarif.cjs`) | Pulls Semgrep/OpenGrep/CodeQL/Bandit/gosec SARIF in as corroborating signals, with path confinement and CWE→attack-class mapping. | raptor, Trail of Bits, ai-deep-sast |
| **Threat model** | Attacker profiles, ranked goals, and crown-jewel abuse paths in `architecture.md` decide the hunting order. | VVAH |
| **Diff mode** (`tools/diff-scope.cjs`, `DIFF-MODE.md`) | PR and change-set reviews that seed units from changed surfaces *and* the controls they depend on, plus a CI example. | deepsec, claude-code-security-review |
| **Signal feedback loop** | Hunters mark each lead `lead` / `false_positive` / `not_reached`. The report shows the lead rate per rule so signatures can be tuned. | deepsec (revalidation) |
| **Evidence ladder** | Every confirmed record states E2 `local_check`, E3 `sanitizer_or_crash`, or E4 `end_to_end_fixture`. Memory-safety claims need a sanitizer or deterministic crash. | defending-code, raptor |
| **Real sandbox + promotion code** (`tools/sandbox-run.sh`, `tools/promote.py`) | Upstream *requires* an OS sandbox and race-safe promotion but ships neither. This repo includes both, with an honest `--check` that reports controls it cannot enforce. | defending-code (gVisor sandbox), raptor |
| **Cross-model verification** (`deep`) | Phase 3 and Phase 5 verifiers run on different model families, and a third fresh verifier settles any disagreement. | raptor (multi-model consensus) |
| **Model routing** | A triage tier for critics and formatting, a frontier tier for anything that sets a verdict. | ai-deep-sast (fast/deep) |
| **Exploit chains** (Phase 3b, `chain-schema.json`, `validate-chains.cjs`) | Composes validated records across units. A chain is confirmed only when every link is confirmed and one end-to-end fixture reproduces it. | VVAH |
| **SARIF 2.1.0** (`tools/to-sarif.cjs`) | GitHub code-scanning output with `security-severity`, code flows, and CWE tags. `needs_validation` exports as `kind: review`. | Trail of Bits, VVAH |
| **Verified remediation** (Phase 7, `REMEDIATION.md`) | A patch plus regression test, written in a disposable copy. The original PoC and the existing suite are re-run before and after, and a fresh verifier tries a variant. Target source is never modified. | vulnhunter, VVAH, defending-code |
| **Cost ledger** (`tools/cost-summary.cjs`) | Invocations and tokens by phase, role, and tier against the budget. Prices are optional and user-supplied. | deepsec |
| **Resumable runs** | `phase_status` checkpoints. An interrupted run restarts at the first phase that isn't done. | deepsec |
| **Crypto & smart-contract companions** | `CRYPTOGRAPHY.md` and `SMART-CONTRACTS.md` attack-class playbooks, in upstream's format. | Trail of Bits |

The evidence bar is unchanged: none of these additions can turn a signal, a SAST hit, or a source-only trace into a `confirmed` finding.

## Workflow

```
0  prefilter + SAST import  → signals.json (+ diff-scope.json)          deterministic, no agents
1  recon + threat model     → architecture.md, coverage-ledger.json      ranked by threat, then signals
2  coverage-led hunting     → candidates, signal dispositions            leads per unit, critic waves
3  adversarial validation   → verdict + evidence level per candidate     climbs E2 → E4
3b chain synthesis          → chains.json                                end-to-end reproduction
4  structured output        → findings.json                              3 validators
5  record verification      → fresh (cross-model in deep) verifiers
6  reports                  → REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, results.sarif, COST.md
7  remediation (on request) → patches/*.diff, REMEDIATION.md, fix_verification
```

## Install

```bash
npx skills add https://github.com/sheltowt/security_scan --skill security-scan          # project
npx skills add https://github.com/sheltowt/security_scan --skill security-scan --global # user
```

Or copy `skills/security-scan/` into your agent's skills directory (for Claude Code: `~/.claude/skills/security-scan/` or `<project>/.claude/skills/security-scan/`).

## Use

```
security audit this codebase
security review this PR against main
do a deep security audit of ./services/billing and propose verified fixes for high and critical findings
find vulnerabilities in ./contracts, output to ~/audits/vault
```

Questions and focused reviews use guidance mode and write no files. Full and diff audits write to `~/security-scan/<repo>/run-<N>/` unless you name a directory. The skill never writes inside the target unless you explicitly choose an ignored directory there.

## Requirements

- A coding agent with tool use and parallel sub-agents
- Node.js ≥ 20 (validators and tools are zero-dependency)
- Python 3 for `tools/promote.py`
- For target execution (evidence levels E2–E4): Docker, Podman, or Linux bubblewrap with `prlimit`, plus a size-limited scratch filesystem. Without a sandbox the skill still runs, but every lead stays `needs_validation`. See [`SANDBOX.md`](skills/security-scan/SANDBOX.md).
- Optional: locally installed Semgrep/OpenGrep/CodeQL/Bandit/gosec for SAST import

## Repository layout

```
skills/security-scan/
  SKILL.md                     entry point: modes, safety, setup, routing, phases
  PREFILTER.md DIFF-MODE.md    Phase 0 and change-set scoping
  RECONNAISSANCE.md HUNTING.md VALIDATION-AND-REPORTING.md CHAINING.md REMEDIATION.md SANDBOX.md
  ATTACK-CLASSES.md + 12 domain companions (incl. CRYPTOGRAPHY.md, SMART-CONTRACTS.md)
  report-schema.json chain-schema.json
  validate-findings.cjs validate-coverage-ledger.cjs validate-chains.cjs  (+ tests)
  tools/  prefilter.cjs signatures.json import-sarif.cjs diff-scope.cjs to-sarif.cjs
          cost-summary.cjs sandbox-run.sh promote.py lib/ tools.test.cjs
examples/github-actions/security-scan-pr.yml   diff-mode PR scan + SARIF upload
```

## Test

```bash
cd skills/security-scan && node --test
```

The suite covers the upstream validator tests plus the new tools. That includes hostile-input timing for every signature, symlink escapes, a target-configured `fsmonitor` that must not run, SARIF path confinement, chain link rules, and promotion refusals (symlinks, hard links, FIFOs, planted destination symlinks, size limits).

## License

MIT. See [`LICENSE`](LICENSE). Derived from cloudflare/security-audit-skill (MIT, © Cloudflare, Inc.); see [`NOTICE.md`](NOTICE.md).
