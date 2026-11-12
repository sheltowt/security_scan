---
name: security-scan
description: Security guidance and vulnerability review for codebases, APIs, services, CLI tools, libraries, daemons, and smart contracts. Use for security questions, focused reviews, vulnerability research, security audits, pen tests, and pull-request security reviews. Run the complete workflow only for explicit codebase audit or pen-test requests, full/comprehensive/end-to-end reviews, PR/diff security reviews, or requested report artifacts.
---

# Security Scan

Find vulnerabilities that violate a real trust boundary, then give owners the source evidence, safe reproduction, priority, and smallest effective fix — verified, when requested, by re-running the reproduction against a patched copy. This is a defensive, source-first workflow. A candidate without a concrete affected principal, resource, or security outcome is not a confirmed finding.

This skill extends Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill) six-phase method with a deterministic prefilter (Phase 0), SAST ingestion, a threat model, diff mode, an evidence ladder, cross-model verification, exploit chaining (Phase 3b), SARIF output, cost tracking, and verified remediation (Phase 7). Every upstream evidence rule still applies; the additions change what gets looked at first and what the owner receives, never the bar for `confirmed`.

## Operating modes

This skill is guidance by default. Loading it does not authorize the complete audit workflow or file creation.

- **Guidance mode**: For security questions, focused reviews, methodology, triage, or investigation of specific findings, use only the relevant parts of this skill. Do not automatically run the phases, create an output directory, or write audit artifacts. You may launch focused agents when useful; they return results to the current task.
- **Full audit mode**: Use the complete workflow when the user explicitly asks to audit or pen-test a codebase, asks for a full, comprehensive, or end-to-end security review, or requests report artifacts. Run Phases 0–6 and write the files defined below. Run Phase 7 only when the user asks for fixes or patches.
- **Diff mode**: A full-audit-mode scoped run over a change set — a pull request, a branch, or `<base>..<head>` — defined in [DIFF-MODE.md](DIFF-MODE.md). Use it when the user asks to security-review a PR, a diff, or "what changed". It is partial coverage by definition and says so.

If the request could mean more than one mode, ask one focused question before creating files or starting a workflow.

## Platform terminology

This skill is agent-neutral:

- **Parent** is the agent that coordinates the run and owns shared state.
- **Task tool** is the platform's delegation or sub-agent mechanism.
- **`research` agent** is a delegated agent for focused source exploration and factual verification.
- **`general` agent** is a delegated agent for broad investigation and bounded local execution.
- **`subagent_type:`** in a heading names which of these two delegated agent roles runs that work.

Use equivalent platform capabilities while preserving role, write-isolation, prompt, and independence boundaries.

## Universal execution safety

These rules apply in both operating modes. Source inspection is read-only. Run target-controlled builds, tests, processes, browsers, emulators, fuzzers, and fixture processing only inside an OS-enforced sandbox that provides all of these controls:

- no external network; use only an isolated loopback namespace when the check needs local client/server traffic;
- an empty environment populated from an explicit allowlist with safe values, with scratch-local `HOME`, temporary directories, and caches;
- a read-only target and toolchain, with the target-controlled process able to write only inside its assigned `scratch/` directory; and
- explicit low CPU, memory, process, file-size, disk, and wall-clock limits.

The agent, outside the target-controlled process, may make a disposable source copy in an assigned `scratch/` directory when a build must write beside source. In guidance mode, do not retain target-controlled files. In full audit mode, only trusted parent-side code may promote the minimum non-secret result to retained `artifacts/` using the procedure under Write isolation. Never expose a retained output directory (other than the agent's own assigned `scratch/`), another agent's directory, the host home directory, credentials, sockets, or shared services to target code. Do not install dependencies or let builds fetch them. Use only tools and dependencies already available locally. If every control cannot be enforced, do not execute target code: report the missing sandbox capability as a needs-validation blocker and give a safe validation plan.

Use dummy principals, fixtures, and secrets. Do not probe deployed endpoints, external services, shared infrastructure, production identities, other users' data, or live control planes. Do not test availability against a live or shared process, publish artifacts, alter releases, spend paid API quota, or continue beyond the minimum local effect needed to establish a defect. If the decisive fact is outside source or the sandboxed fixture, report it as needing validation.

## Full audit setup

In full audit mode, resolve these values before reconnaissance:

- **Skill directory**: the absolute directory containing this `SKILL.md`.
- **Target**: the absolute repository root under review.
- **Repo name**: a stable repository identifier from the directory or local Git remote.
- **Output directory**: a new writable directory outside the target, defaulting to `~/security-scan/<repo-name>/run-<N>`, where `<N>` is the next unused integer. Use a directory inside the target only when the user explicitly selects it and the parent verifies that version control ignores the whole directory. Otherwise stop and request an external path.
- **Source ref**: the reviewed commit and whether the worktree is dirty. Do not treat unreviewed generated or modified files as another revision.
- **Mode and scope**: `full` or `diff` (with base and head refs from [DIFF-MODE.md](DIFF-MODE.md)), plus any user-named paths.
- **Sandbox capability**: run `bash <skill-dir>/tools/sandbox-run.sh --check` and record the result. See [SANDBOX.md](SANDBOX.md). A missing backend or missing control does not stop the audit; it blocks target execution and caps evidence at source level, so affected leads stay `needs_validation`.

### Write isolation

The parent creates and is the only writer of shared run files:

- `run-metadata.json`
- `signals.json` and, in diff mode, `diff-scope.json`
- `architecture.md`
- `coverage-ledger.json`
- `findings.json`
- `chains.json`
- `cost-ledger.jsonl` and `COST.md`
- `REPORT.md`
- `FINDINGS-DETAIL.md`
- `NEEDS-VALIDATION.md`
- `results.sarif`
- `REMEDIATION.md` and `patches/` (Phase 7 only)

Each hunter or verifier receives a unique root under `<output-dir>/agents/<agent-id>/`, with separate `scratch/` and `artifacts/` directories. Canonical agent IDs match `^[a-z0-9][a-z0-9_-]{0,63}$` and must not equal a Windows device name such as `con`, `prn`, `aux`, `nul`, `com1` through `com9`, or `lpt1` through `lpt9`. Lowercase IDs prevent case-fold collisions. The agent and every target-controlled process may write only to `scratch/`; retained `artifacts/` is parent-owned, is never exposed to the sandbox, and is writable only by trusted parent-side promotion code. Agents may not change shared files, target source, retained artifacts, or another agent's directory. Do not use `/tmp` or the host home directory as a writable fallback.

Before execution, the parent opens and retains trusted, non-inheritable directory descriptors for the agent's `scratch/` and `artifacts/` roots, and records an allowlist of expected scratch-relative artifact files plus explicit per-file and cumulative byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox and all its processes terminate, trusted parent-side code promotes each allowlisted file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity, type, link count, or size.
7. For the destination, walk every parent component from the retained artifacts-root descriptor with no-follow directory-relative operations; require each existing component to be a real directory, and create any missing directory exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened destination is a regular file with link count exactly one, and copy from the verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or open or promote a symlink, FIFO, socket, device, directory, hard-linked file, changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch entry; if it is decisive evidence, retain `needs_validation` with the exact promotion blocker.

[HUNTING.md](HUNTING.md) and [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) carry this procedure as one identical fenced block for hunter and verifier prompts; it states the same rules in the same order as this list.

`tools/promote.py` implements this procedure with directory-descriptor-relative, no-follow POSIX calls: `python3 -I <skill-dir>/tools/promote.py --scratch <agents/<id>/scratch> --artifacts <agents/<id>/artifacts> --allow <relative-path>... --max-file-bytes N --max-total-bytes N`. It prints one JSON result per file and exits nonzero if any declared file was refused. Use it, or an equivalent that meets every step, as the trusted parent-side promotion code. On platforms where it reports that a required primitive is unavailable, promotion is blocked.

For a reproduced check, record the command, exact test input, sandbox limits, and only the allowlisted environment variable names plus safe non-secret values needed to reproduce it. Never capture or copy the ambient environment, inherited variables, credential values, authentication state, or unrelated host paths. Launch from an empty environment rather than trying to redact one after execution.

Before delegation, the parent writes `run-metadata.json` with at least `run_id`, `repo`, `target`, `source_ref`, `mode` (`full` or `diff`, with `diff_base` and `diff_head`), `profile`, `scope_paths`, `budget` (null if unset), `execution_policy: "sandboxed-source-and-local-only"`, the `sandbox` check result, `model_routing`, selected companion files, prior-run paths, shared-file owners, `phase_status`, and `run_status: "in_progress"`. Update metadata only when those facts change; candidate state belongs in the coverage ledger and `findings.json`.

### Resumable runs

`phase_status` maps each phase (`"0"`, `"1"`, `"2"`, `"3"`, `"3b"`, `"4"`, `"5"`, `"6"`, `"7"`) to `pending`, `in_progress`, `done`, or `skipped` with a reason. The parent sets a phase `done` only after its outputs are written and its validators pass. If a run is interrupted, a new session pointed at the same output directory resumes. It re-runs the validators on existing files, then restarts the first phase that is not `done`. Ledger units left `in_progress` without a returned result go back to `planned` with a fresh owner, and their archived attempts stay untouched. Never resume over a changed source ref. If `source_ref` differs, start a new run and treat the old one as a prior run.

### Model routing

Record which model or tier serves each role in `model_routing`. Two tiers are enough:

- **triage** (a fast, inexpensive model): Phase 0 signal grouping, coverage critics, final record-verifier formatting checks, report drafting from final records, and the Phase 6 SARIF/cost steps.
- **frontier** (the most capable available model): reconnaissance agents 1b and 1c, threat modeling, hunters, Phase 3 candidate verifiers, chain verifiers, Phase 5 verifiers of `confirmed` records, and Phase 7 remediators and fix verifiers.

Never route a role that can set or raise a verdict, severity, or evidence level to the triage tier. In the `deep` profile, the Phase 5 verifier of each `confirmed` record runs on a different model family from its Phase 3 verifier when one is available. Record both model identifiers in the ledger check. Model disagreement is resolved by a third fresh verifier, never by averaging.

### Cost tracking

After every agent invocation, the parent appends one line to `cost-ledger.jsonl` with `agent_id`, `phase`, `role`, `model`, `model_tier`, and the platform-reported `input_tokens`, `output_tokens`, `cache_read_tokens`, and `wall_seconds` (null when unavailable). Before Phase 6, run `node <skill-dir>/tools/cost-summary.cjs --ledger cost-ledger.jsonl --metadata run-metadata.json --out COST.md`, adding `--prices <file>` only when the user supplies prices. The invocation count is the same unit as `budget`.

## Full audit planning

The coverage, prior-run, profile, and budget requirements in this section apply only in full audit mode.

### Coverage and prior runs

No one pass is complete. Build a deterministic coverage plan before hunting and update it after every agent result. [RECONNAISSANCE.md](RECONNAISSANCE.md) defines the stable coverage units and [HUNTING.md](HUNTING.md) defines coverage-critic waves. The parent alone updates the ledger.

If prior runs exist, read every compatible `coverage-ledger.json` and `findings.json` before planning the current run:

1. Compare the relevant current source with each prior record and unit. A prior source ref alone is not evidence that a path is unchanged.
2. Carry a prior `confirmed` record into the current candidate set only when its relevant source and conditions are unchanged and its evidence still meets the current contract. Link it to a current ledger unit seeded `planned`, preserve its fingerprint, exclude only that carried root cause from hunters, and send the carried record through the current final verification path; the Phase 3 verifier that re-checks it becomes that unit's assignment owner and moves it to `candidate`.
3. When relevant source for a prior `confirmed` record changed, create a current planned revalidation unit. Do not put that record on the hunter exclusion list. It remains confirmed only if current independent validation establishes the current path and result.
4. Make prior `needs_validation`, `deferred`, `blocked`, `out_of_scope`, and any changed-source unit current work. A still-external `needs_validation` record may be carried only after the current source trace is checked and linked by fingerprint to a current `planned` unit whose verifier re-check supplies its owner and evidence; the record keeps the unresolved blocker. These prior states never suppress a current unit.
5. A prior same-source covered unit may inform priority, but it remains visible in the current ledger. A prior `rejected` record suppresses only the unchanged failed claim, not coverage of its unit; changed evidence creates current work.
6. Read the prior profile and scope. A prior `quick` or scoped ledger contributes only its recorded evidence and gaps, never an implied "rest is fine."

If no prior ledger exists, say so in the final coverage statement. Never imply that one run exhausts the target.

### Run profiles and scope

During full audit setup, pick a profile from the user's request or propose one from the target's size and stakes. Record it in `run-metadata.json` (`profile`, `scope_paths`) and state it in the report. The default is `standard`.

- **`quick`** — a bounded pass for small targets, re-runs, or a fast first look. Coarsen ledger units to surface × boundary × attack class (subsystem uses the fixed canonical `profile/quick/all-in-scope-subsystems` identifier), run exactly one hunter wave followed by exactly one final coverage-critic pass, and use one fresh verifier per candidate for both candidate validation and final record verification. Do not launch a follow-up hunter wave: record the critic's accepted discoveries and reassignments as `deferred`.
- **`standard`** — the workflow as written.
- **`deep`** — for high-stakes or large targets. Split ledger units per subsystem and lifecycle mode, run critic waves to a clean pass, keep candidate validation and final record verification as separate fresh agents (on different model families when available), run Phase 3b chain synthesis, and give `prior_covered_same_source` units an independent second pass.

A **scoped run** audits a subset: named paths, one subsystem, one companion domain, or the diff between two source refs. Seed ledger units only for in-scope surfaces and record everything else as `out_of_scope` — never as `covered`. A scoped or `quick` run must present itself as partial coverage. Diff mode is a scoped run with the seeding rules in [DIFF-MODE.md](DIFF-MODE.md).

Profiles change breadth and redundancy, never the evidence bar. Do not scale away the candidate gate, the source/local execution boundary, `needs_validation` discipline, schema validation, or independent verification of `confirmed` records.

#### Cost budget

The ledger makes spend countable: one unit is roughly one hunter assignment, and one surviving candidate is one or two verifier assignments depending on profile. Phase 0 is deterministic and costs no agent invocations. A Phase 3b chain costs one synthesizer per run plus one verifier per proposed chain. A Phase 7 fix costs one remediator plus one fix verifier per finding. When the user sets a budget — or the parent proposes one for a large target — record `budget` in `run-metadata.json` as a maximum number of agent invocations across all phases. Phases 3b and 7 are funded only from what remains after Phases 1–5 reserve their minimums. They never take from the critic or validation reserves.

Apply the strict budget gate before launching any reconnaissance agent. Reserve the four baseline reconnaissance calls, one final post-wave critic for `quick` or one post-wave plus one distinct final-clean critic for `standard`/`deep`, and at least one verifier call. Add focused reconnaissance only after repeating this gate for each extra call. If the requested budget cannot fund that minimum, launch no agent: ask for a larger budget, narrower scope, or different profile. If the request remains unchanged, set `run_status: "incomplete"` with `incomplete_reason: "budget_cannot_fund_reconnaissance_and_reserves"` and report that no audit pass ran.

Spend it in this order:

1. Count reconnaissance, every post-wave critic, and the separate final-clean critic as agent invocations.
2. **Reserve critics and validation before hunting.** For `quick`, reserve its one post-wave final critic. Before every `standard` or `deep` hunter wave, reserve one immediate post-wave critic plus one distinct final-clean critic. Also reserve verifier cost from the profile (about 1 or 2 agents per expected candidate; when in doubt reserve 30% of the balance after critic reservation). Never assign hunters into either reserve.
3. Assign hunters to units in priority order until the hunting allowance is spent. Spend the reserved post-wave critic immediately after that wave; keep the final-clean and validation reserves intact.
4. Before a later wave, reserve its new post-wave critic again. If the remaining budget cannot cover the required critic calls and validation reserve, launch no hunters from that wave, mark its planned units `deferred` with reason `budget_cannot_reserve_critics_and_validation`, and use the retained final-clean critic to record the resulting gap.

Before wave 1, update the pre-recon estimate with seeded units, implied hunter count, mandatory critic calls, validation reserve, and whether the remaining budget covers the plan. If it clearly cannot, say so and propose either a tighter scope or a coarser profile instead of silently thinning evidence. If later facts consume the required final-critic reserve, launch no hunters, mark all planned work deferred, set the run incomplete with reason `critic_budget_exhausted`, and make no complete-coverage claim.

A strict total-agent budget can still be exceeded by an unexpectedly large candidate set or by a material Phase 5 replacement that needs another independent verifier. If the remaining budget cannot validate every candidate, stop hunting, validate candidates in fingerprint order while the budget permits, and set `run_status: "incomplete"` plus `incomplete_reason: "validation_budget_exhausted"`. Keep each unvalidated fingerprint linked to a `candidate` ledger unit with that unresolved reason. Do not put an unvalidated candidate in `findings.json`, relabel it `needs_validation`, or report the run as complete. Phase 6 may produce a partial report only if its first section states that candidate validation is incomplete and lists the affected fingerprints and units. Never exceed a user-set strict budget silently.

## Core principles

### Require a boundary and result

For every candidate, name the lower-trust principal, accepted input or action, intended control, crossed boundary, affected principal or resource, and concrete observed or owner-observable result. Do not elevate a missing best practice, guessed deployment behavior, generic parser crash, or self-impact into a security finding.

### Use bounded local evidence

Static analysis establishes the source path. Sandboxed local tests resolve behavior when all execution controls are available: a minimal function harness, existing unit test, small parser fixture, dummy-tenant integration test, locally rendered configuration, or bounded isolated-loopback client. Stop at a wrong return value, unauthorized dummy record, sanitizer finding, policy difference, or other minimum effect. Do not extend the local check beyond the minimum boundary result or produce persistence, post-fault, or concealment material.

### Respect source visibility

Deployment controls, proxy behavior, provider settings, browser headers, identity policy, broker ACLs, packaging, and topology are real controls. If they are required and absent from the repository, do not assume either presence or absence. Use `needs_validation` with the exact missing fact and a safe owner-observed or local plan.

### Separate priority from certainty

Only `confirmed` records receive severity. Likelihood and impact must reflect the demonstrated conditions and result; overall severity cannot exceed demonstrated impact. `needs_validation` means a specific source-grounded boundary hypothesis is blocked, not a low-confidence confirmed vulnerability, and it has no severity.

Calibrate overall severity with these anchors:

- **critical** — an unauthenticated actor gains code execution, full data-store access, or takeover of arbitrary accounts.
- **high** — an actor fully defeats an explicit security control with real consequences: authentication bypass, cross-tenant read or write, stored script execution affecting other users, authenticated code execution, or an unauthenticated remote stop of a shared service.
- **medium** — a real boundary violation with limited blast radius, uncommon preconditions, or consequences confined to a narrow resource set.
- **low** — disclosure of non-secret internals, or an effect requiring sustained effort for minimal gain.
- **informational** — a confirmed but minimal-impact observation, useful mainly as a prerequisite inside a larger finding.

The high/medium discriminator: does the demonstrated result fully defeat an explicit control for an action with real consequences, or only weaken it? If you cannot state the concrete damage, the severity is lower than it feels.

### Recommend the smallest effective source fix

For each confirmed finding, identify the invariant the code must enforce and the narrowest source change that enforces it at the last trusted decision point. Prefer specific repository-relative changes and regression tests over generic hardening advice. The audit never modifies target source. Phase 7, when requested, writes and tests patches only in a disposable copy and hands owners a `.diff`.

## Full audit workflow

In full audit mode, follow the phases in order:

0. **Deterministic prefilter** — run the regex prefilter and import any locally available SAST results into `signals.json` with [PREFILTER.md](PREFILTER.md). This needs no agents and makes no claims. In diff mode, compute `diff-scope.json` first.
1. **Reconnaissance and threat model** — map the source, trust boundaries, attacker goals, local build paths, companion selections, prior evidence, and the initial deterministic coverage ledger ranked by threat and signal density, using [RECONNAISSANCE.md](RECONNAISSANCE.md).
2. **Coverage-led hunting waves** — assign isolated hunters from the ledger with their units' signals as leads, and collect structured candidate results, using [HUNTING.md](HUNTING.md), [ATTACK-CLASSES.md](ATTACK-CLASSES.md), and the selected domain companions.
3. **Candidate validation** — consolidate fingerprints and give every candidate to a fresh adversarial verifier that tries to disprove it and climbs the evidence ladder, as defined in [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md).
3b. **Chain synthesis** (`standard` when two or more validated records exist; always in `deep`) — compose validated records into exploit chains and verify each chain end to end, using [CHAINING.md](CHAINING.md).
4. **Structured output** — write all final `confirmed`, `needs_validation`, and `rejected` records to `findings.json` and chains to `chains.json`. Validate them with `validate-findings.cjs` and `validate-chains.cjs`, and validate the coverage claim with `validate-coverage-ledger.cjs`.
5. **Independent record verification** — use fresh agents to verify final source claims and reconcile corrections or state changes.
6. **Target-neutral report** — derive `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `results.sarif`, and `COST.md` from the final records, with no live-probe instructions.
7. **Verified remediation** (only on request) — for each requested confirmed finding, write the smallest patch in a disposable copy, add a regression test, re-run the PoC and the existing suite in the sandbox, and record `fix_verification`, using [REMEDIATION.md](REMEDIATION.md).

Do not end the run before one of exactly two terminal states: (a) all Phase 6 artifacts are written (plus Phase 7 artifacts when requested) and every validator passes, or (b) `run_status: "incomplete"` is recorded with its exact reason and the gap is disclosed in the report. Never stop mid-phase.

## Files

| File | Use |
|------|-----|
| [PREFILTER.md](PREFILTER.md) | Phase 0: regex prefilter, SAST import, hotspot ranking |
| [DIFF-MODE.md](DIFF-MODE.md) | Pull-request and change-set scoping, CI usage |
| [RECONNAISSANCE.md](RECONNAISSANCE.md) | Phase 1: reconnaissance, threat model, coverage ledger |
| [HUNTING.md](HUNTING.md) | Phase 2: hunter orchestration, prompts, critics |
| [ATTACK-CLASSES.md](ATTACK-CLASSES.md) and domain companions | Attack-class blocks copied into hunter prompts, including [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) and [SMART-CONTRACTS.md](SMART-CONTRACTS.md) |
| [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md) | Phases 3–6: validation, evidence ladder, output, verification, reports, SARIF |
| [CHAINING.md](CHAINING.md) | Phase 3b: exploit-chain synthesis and verification |
| [REMEDIATION.md](REMEDIATION.md) | Phase 7: patch, regression test, and fix verification |
| [SANDBOX.md](SANDBOX.md) | Sandbox backends, the `sandbox-run.sh` contract, size-limited scratch |
| `tools/` | `prefilter.cjs`, `import-sarif.cjs`, `diff-scope.cjs`, `to-sarif.cjs`, `cost-summary.cjs`, `sandbox-run.sh`, `promote.py` |

## Anti-patterns

1. Checklist deviations presented as vulnerabilities.
2. Defense-in-depth advice with no reachable boundary violation.
3. Live or shared-environment testing where bounded local evidence is insufficient.
4. Guessing provider, proxy, browser, identity, or deployment behavior not present in source.
5. Treating intended same-principal authority or self-impact as a cross-boundary result.
6. Reporting a parser or runtime effect stronger than the observed effect.
7. Emitting prose-only hunter results that cannot be deduplicated or verified.
8. Re-reporting carried same-source prior confirmed records or using them as exemplars that anchor the hunt.
9. Assigning severity to `needs_validation` records.
10. Writing the report before independent verification or letting prose and JSON disagree.
11. Treating a prefilter signal or imported SAST result as a finding, or closing a coverage unit because no signal fired there.
12. Letting signal density decide what is *not* reviewed. Signals reorder work; they never remove a unit from the ledger.
13. Routing a role that sets a verdict, severity, or evidence level to the triage model tier.
14. Reporting a chain whose links were not each independently validated, or whose combined result was inferred rather than reproduced.
15. Applying a patch to target source, or reporting a fix as verified without re-running the original reproduction against the patched copy.
