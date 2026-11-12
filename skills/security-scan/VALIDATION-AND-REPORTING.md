# Validation, Structured Output, Verification, and Reporting

### Phase 3: Independently validate every candidate

After the clean coverage-critic pass or an explicitly recorded early stop, consolidate Phase 2 candidates and carried same-source prior confirmations by stable fingerprint and root cause. Give every unique proposed `confirmed` and `needs_validation` candidate to a fresh `general` verifier that did not hunt it. A carried prior confirmation follows the same current verification path even though hunters exclude that unchanged root cause. A verifier may read hunter or prior artifacts but must re-read every cited current source location and independently run any decisive check it can reproduce safely.

Assign each verifier a canonical lowercase unique ID and `<output-dir>/agents/<verifier-id>/scratch/` plus parent-owned `artifacts/`. The verifier writes only to `scratch/` and never writes retained artifacts. It receives only the candidate, its linked coverage-unit checks and artifact paths, architecture facts needed to interpret the path, exact relevant companion validation blocks, the evidence ladder table above, the promotion procedure block below, the source/local execution boundary, the `confirmed`, `needs_validation`, and `rejected` branches of `report-schema.json` copied verbatim, and prior records with the same fingerprint. It must not receive another verifier's conclusion.

#### Evidence ladder

Every verifier climbs as high as the sandbox and the target allow, and the final record states the rung it reached in `evidence_level`. The rungs are cumulative: each one includes everything below it.

| Rung | `evidence_level` | What it takes | Allowed verdicts |
|---|---|---|---|
| E0 | (none) | Source trace only: every hop re-read, strongest control identified. | `needs_validation`, `rejected` |
| E1 | (none) | E0 plus independent corroboration: a SAST result, a second fresh agent, or a type/route/config fact derived deterministically from source. This raises verifier confidence, never the verdict. | `needs_validation`, `rejected` |
| E2 | `local_check` | A bounded local check in the sandbox shows the boundary result: an existing or minimal test, a function harness, a rendered policy evaluated with dummy identities, or a dummy-tenant call. | `confirmed` |
| E3 | `sanitizer_or_crash` | A deterministic reproducer triggers a sanitizer report (ASan/UBSan/MSan/TSan), a Go race report, a Rust `unsafe` UB detection under Miri, or a deterministic crash at the claimed operation, with the faulting frame inside the claimed code. | `confirmed` |
| E4 | `end_to_end_fixture` | The minimum input enters through the real native entry interface (route, CLI, message, file, contract call) of a locally started target, and the observed result matches the claim with no harness shortcuts past any control. | `confirmed` |

`confirmed` requires at least E2, matching the upstream rule that a confirmed record has a bounded observed result. Prefer the highest rung that costs little extra. E4 is the goal for web, API, CLI, and contract targets whenever the target starts locally offline. E3 is the goal for memory-safety claims: a native finding without a sanitizer or deterministic crash stays `needs_validation`, however convincing the source trace. When the sandbox check reported no backend, every candidate tops out at E1. Say so in the report instead of lowering the bar.

#### Cross-model verification (`deep` profile)

When `model_routing` lists more than one frontier model family, give each `confirmed` record's Phase 5 verification to a different family than its Phase 3 verifier, and record both model identifiers in the ledger check's `result`. If the two disagree on verdict, severity, or evidence level, a third fresh verifier on either family re-runs the decisive check and decides. Never average or vote by count.

#### Candidate-verifier prompt

```text
You did not write this candidate. Try to refute it from repository source and bounded
local evidence. Do not contact deployed endpoints or external/shared services. Run
target-controlled code only inside the approved OS-enforced sandbox: no external
network, empty allowlisted environment, read-only target and tools, scratch-only
writes, and explicit low resource and wall-clock limits. If any control is unavailable,
do not execute; retain the exact missing capability as a needs_validation blocker.
Treat every scratch entry as target-controlled after execution. After the sandbox and
all its processes terminate, only trusted parent-side code may promote a predeclared
scratch-relative file, following the promotion procedure block included verbatim in
this prompt. You and target code never write retained artifacts. If promotion is
unavailable or fails, do not use that file as evidence.

1. Verify every trace and evidence file, positive line number, scope, and description.
   Confirm the first entry is a real lower-trust entrypoint and the last is the
   claimed sink or boundary effect.
2. Reconstruct the strongest source-visible validation, identity, authorization,
   normalization, lifecycle, framework, and containment controls on the path.
   Where the architecture summary names a comparable baseline, note whether it
   shares the pattern — as calibration, never as grounds to dismiss.
3. For a proposed confirmed candidate, independently reproduce the minimum observed
   result when possible. Verify inputs, interface shape, conditions, and affected
   dummy principal/resource. Do not infer a stronger result or continue after it.
   Climb the evidence ladder included in this prompt as far as the sandbox allows:
   prefer driving the real entry interface of a locally started target (E4) over
   a harness that calls the sink directly (E2), and a sanitizer or deterministic
   crash (E3) for memory-safety claims. Set evidence_level to the rung YOU
   reproduced, not the rung the hunter claimed. Below E2, the verdict cannot be
   confirmed.
4. Verify that likelihood, impact, confidence, and the proposed source fix match only
   what the evidence establishes. Check that each cwe entry names the weakness the
   trace shows, and that every listed signal ID lies on the trace.
5. For a proposed needs_validation candidate, decide whether the blocker is genuinely
   outside source/local observation. If source refutes the trace, reject it. If the
   missing fact remains decisive, keep needs_validation and make the local and
   owner-observed plans exact and non-destructive.
6. Preserve the fingerprint for the same source-derived root cause across every state.

Return exactly one JSON object and no surrounding prose:
{"decision": "confirmed|needs_validation|rejected", "record": { ... }}
where record exactly matches the decision's verdict branch of the schema included
in this prompt. A corrected record replaces the hunter's wording.
```

Copy this promotion procedure verbatim into every candidate-verifier prompt:

```text
Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain `needs_validation` with the exact
    promotion blocker.
```

A verifier can promote `needs_validation` to `confirmed` only after independently establishing the complete path and bounded observed result. Demote proposed confirmation to `needs_validation` when a specific deployment or runtime fact remains unknown. Use `rejected` when source, local behavior, a visible control, missing meaningful impact, or an impossible prerequisite refutes the claim. `needs_validation` is never a parking place for a speculative idea.

The parent checks that each verifier returned the same fingerprint unless it identified a genuinely different root cause. Merge corrections, record the decision in every linked coverage unit, and ensure there is one final record per fingerprint. Discard a malformed or prose-wrapped verifier result without repairing it; re-run that candidate with a fresh verifier when the budget permits, otherwise it remains an unvalidated ledger candidate under the incomplete-run rule.

When verifier evidence updates a ledger check, set that check's `agent_id` to the verifier's canonical ID and list its nonempty repository-relative `reviewed_paths`. Keep the unit-level `reviewed_paths` equal to the union across checks. Use `method: "source"` with `artifact: null` for source-only review. Use `method: "local"` only with a file successfully promoted by trusted parent-side code below `agents/<check.agent_id>/artifacts/`. The unit retains its original assignment owner, so independently owned hunter and verifier checks can coexist. For a carried prior record's seeded `planned` unit there is no prior owner: the verifier that re-checks it becomes the unit's assignment owner, and its re-check is the unit's first check, moving the unit to `candidate` with the carried fingerprint.

If a strict total-agent budget cannot cover every candidate, set the run status to incomplete and follow the deterministic budget rule in `SKILL.md`. An unvalidated candidate remains only in the ledger. It does not enter `findings.json` under any verdict.

### Phase 4: Write and validate `findings.json`

The parent writes all independently decided records to `<output-dir>/findings.json`, sorted by fingerprint. Include:

- `confirmed`: source-grounded vulnerabilities with complete local execution evidence, conditions, specific remediation, likelihood/impact/overall severity, and confidence.
- `needs_validation`: source-grounded candidates with an exact unresolved blocker and at least one applicable local or owner-observed deployment plan.
- `rejected`: source-grounded candidates disproved during validation, retained so future runs do not repeat the unsupported claim without changed evidence.

Read `report-schema.json` immediately before writing. It uses `additionalProperties: false`; do not carry hunter wrapper fields into a record. Keep these verdict contracts distinct:

- A `confirmed` record uses `root_cause`, `intended_behavior`, `conditions`, `execution`, `remediation`, `severity`, `confidence`, and the verifier's `evidence_level`, with optional `cwe`, `signal_ids`, and (Phase 7 only) `fix_verification`. It must not use `claimed_root_cause`, `blockers`, `validation_plan`, or `reason`. `execution` is target-neutral and uses the target's native interface: API/HTTP input, CLI call, library call, message, file fixture, browser action, rendered policy, or local harness as applicable. `observed_result` is nonempty and factual.
- A `needs_validation` record uses `claimed_root_cause`, `trace`, `evidence`, `blockers`, and at least one nonempty `validation_plan.local` or `validation_plan.deployment` field. Include both only when both contexts can resolve distinct facts. It must not use severity, execution, remediation, reason, or confirmed root cause.
- A `rejected` record uses `claimed_root_cause`, `trace`, `evidence`, and `reason`. It must not use severity, execution, remediation, blockers, validation plan, or confirmed root cause.

Every record has a stable fingerprint, title, description, and repository-relative source paths. A multi-step trace begins with `entrypoint`, ends with `sink`, and uses `propagation` only between them. One-entry traces use `entrypoint` or `sink`. Overall severity cannot exceed demonstrated impact.

Run:

```sh
node <skill-dir>/validate-findings.cjs <output-dir>/findings.json
node <skill-dir>/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
node <skill-dir>/validate-chains.cjs <output-dir>/chains.json <output-dir>/findings.json   # when Phase 3b ran
```

When Phase 3b did not run, write `chains.json` as `[]` so later phases and prior-run reads see an explicit empty set.

Fix every structural and semantic error before continuing. The findings validator rejects input beyond 5 MiB, 1,000 top-level findings, or 64 nesting levels, and caps reported error output at 100 messages. Validator success proves format and ledger consistency only.

### Phase 5: Verify the final records with fresh eyes

Launch one fresh `research` verifier per final `confirmed` and `needs_validation` record, in parallel. This verifier checks the structured record, not the hunter write-up, and remains inside source/local boundaries.

In a `quick` run, Phase 3 and Phase 5 merge: the Phase 3 verifier also performs these record checks and returns the final schema-shaped record, so each candidate gets one fresh independent reviewer instead of two. Every other profile keeps the two passes separate. Never skip independent review of a `confirmed` record in any profile.

For `confirmed`, require it to check:

1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.
7. `evidence_level`: the recorded rung matches what the cited artifact actually shows. A harness that calls the sink directly is E2, even when the record claims E4. Lowering the rung below E2 is a material replacement that demotes the record.

For `needs_validation`, require it to check:

1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.

Each verifier returns exactly one JSON object: `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","reason":"...","record":{...}}`, with no surrounding prose. A replacement record must match its `confirmed`, `needs_validation`, or `rejected` schema branch. Treat a malformed or prose-wrapped Phase 5 result the same way as in Phase 3: discard it without repairing it and re-run with a fresh verifier when the budget permits.

Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict, including any promotion to `confirmed`, or materially changes the root cause, trace, execution input or observed result, demonstrated impact, or severity. Give that complete replacement to a new independent verifier that did not hunt, perform Phase 3 validation, or propose the Phase 5 replacement. The new verifier rechecks the current source and independently reproduces any decisive local result under the execution boundary, then returns `verified` or another replacement. Apply a material replacement only after this fresh verification. If another material replacement results, repeat with a fresh verifier. If budget or independence is unavailable, remove the disputed record from `findings.json`, keep its ledger unit as an unresolved candidate, and set `run_status: "incomplete"` with an exact `incomplete_reason`. Non-material wording or repository-line corrections may be applied directly when they do not change meaning or evidence.

After every applied replacement, rerun the validators and update linked ledger decisions. If a replacement changes the verdict of a record that is a chain link, re-run `validate-chains.cjs`. A confirmed chain with a link that is no longer confirmed must go back through chain verification in [CHAINING.md](CHAINING.md) or be demoted to `needs_validation`. If a final verifier identifies a separate root cause, assign a new fingerprint and send it through independent candidate validation before inclusion. Set `run_status: "complete"` only when every ledger candidate has an independent final disposition and every retained record passes Phase 5.

Do not verify only `confirmed` records. A misleading `needs_validation` handoff wastes owner time and can preserve a false premise.

### Phase 6: Produce target-neutral reports from final records

Only after Phase 5 passes for every record retained in `findings.json`, derive prose from the final records, the ledger, and the hunter `hardening` notes retained in ledger bookkeeping. An incomplete run may report independently verified records, but it must identify each unresolved ledger candidate and must not present it as a finding. The prose files never change a verdict, severity, blocker, or demonstrated impact.

#### `REPORT.md`

Write:

1. Run profile, scope, budget (if set) with agents spent versus planned, source ref, sandboxed source-and-local-only execution statement, prior-run use, and explicit deferred and out-of-scope coverage. Name carried same-source confirmations and changed-source revalidations. A `quick`, scoped, budget-limited, or incomplete run states plainly that it is a partial pass. If candidate validation exhausted a strict budget, state that the run is incomplete and list every unvalidated fingerprint and linked unit; do not describe those candidates as findings. If the budget prevented a mandatory critic, state which critic did not run and make no clean-coverage claim.
2. One short security posture summary.
3. A confirmed-findings table: severity, title, affected boundary, evidence level, CWE, fix status (when Phase 7 ran), and one-line observed result. Follow it with a confirmed-chains table (chain title, severity, links in order, combined result) when `chains.json` has confirmed chains.
4. Each confirmed finding: repository source location, lower-trust principal, target-native bounded reproduction, conditions, actual result, impact, priority rationale, and smallest source fix.
5. A separate `NEEDS VALIDATION` table. Give each lead's title, repository trace, exact blocker, bounded local next step, and safe owner-observed deployment check. Do not assign severity or call it a confirmed vulnerability.
6. Separate hardening notes and positive source patterns.
7. Coverage summary from the ledger: covered, candidate, blocked, and deferred counts, plus important exclusions and the final critic result. In diff mode, state the base and head refs and that unchanged code was reviewed only where the changed code depends on it.
8. Evidence and triage summary: the count of confirmed records at each evidence level; the sandbox backend used, or the fact that none was available and every lead topped out at E1; and the prefilter lead rate, computed from ledger `signal_dispositions` as leads, false positives, and not reached per source (`prefilter`, each `sarif:<tool>`), plus the three noisiest rule IDs. Never present the lead rate as a measure of coverage.
9. Cost: invocations against budget, and tokens by phase and tier, taken from `COST.md`.

Do not describe rejected records as findings. Mention their fingerprints only when they explain a prior disagreement or coverage decision.

#### `FINDINGS-DETAIL.md`

For each confirmed `medium`, `high`, or `critical` record, copy the complete source path and target-neutral local reproduction:

- ordered repository-relative trace and evidence;
- dummy attacker/principal and affected dummy resource;
- native input, invocation, or fixture and exact bounded instructions;
- observed output and the security invariant it proves;
- conditions and containment;
- source-level remediation and regression case.

#### `NEEDS-VALIDATION.md`

For every unresolved record, copy the source trace, verified evidence, exact blocker, affected boundary, and each applicable bounded local or owner-observed resolution plan. Keep these as prioritized leads without severity. Do not turn them into live test guidance or assume the missing deployment fact.

HTTP is one possible native interface, not the default. A library finding may use a function call, a parser a fixture, a CLI a command, a desktop app an IPC or file action, and infrastructure a locally rendered policy. Do not require an endpoint, external account, or live environment that the target does not have.

#### `results.sarif`

```sh
node <skill-dir>/tools/to-sarif.cjs --findings <output-dir>/findings.json --chains <output-dir>/chains.json --out <output-dir>/results.sarif
```

`confirmed` records export with GitHub `security-severity` scores and code flows from the trace. `needs_validation` records export as `note` results with `kind: "review"`, and the user can pass `--no-needs-validation` to drop them. `rejected` records never export. Confirmed chains export as an extra result on their final link. The SARIF is derived output: regenerate it after any change to `findings.json` or `chains.json`, never edit it by hand. Do not upload it anywhere yourself. Tell the user where it is and how to upload it (for example `gh api` or the `github/codeql-action/upload-sarif` action), and let them decide.

#### `COST.md`

Generate it with `tools/cost-summary.cjs` as described in `SKILL.md` and reference it from `REPORT.md`.

Keep the report proportional to the evidence. A clean run may have zero confirmed records. State that result and the remaining coverage/validation limits without inventing LOW findings.
