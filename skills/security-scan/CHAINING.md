# Exploit-Chain Synthesis

### Phase 3b: Compose validated records into chains

Individually limited findings often combine into a much larger one. An informational path disclosure plus a medium SSRF plus a low metadata-service exposure can add up to cloud credential theft. Upstream `ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries` asks hunters to look for chains inside one unit. This phase looks across units, after Phase 3 has given every record an independent verdict.

A chain never replaces its links. Each link stays in `findings.json` with its own verdict and severity. The chain is a separate record in `chains.json` with its own end-to-end evidence.

Run this phase in `deep`, and in `standard` when at least two `confirmed` or `needs_validation` records exist. Skip it in `quick` and record `phase_status["3b"]: "skipped"` with the reason. Budget: one synthesizer, then one verifier per proposed chain, funded only from what remains after reserving one Phase 5 verifier per retained record (see `SKILL.md`).

## Step 1: Capability graph (parent, no agent)

For every `confirmed` and `needs_validation` record, the parent writes one line: the fingerprint, the principal the record starts from, and the concrete capability the record's result grants (a read of X, a write of Y, a token for Z, code execution as W, an SSRF to the internal network). Take both directly from the record's `execution.attacker_perspective` and `observed_result`, or from `claimed_root_cause` for leads. `rejected` records never enter the graph.

## Step 2: Synthesizer (`research` agent, frontier tier)

The synthesizer receives `architecture.md` (including the threat model's crown jewels), the capability lines, and the full records. It reads source but does not execute anything.

```text
You are composing already-validated security findings into exploit chains.
You may not invent new findings. Every link must be one of the fingerprints given.

For each crown-jewel goal in the threat model, search the capability lines for a
sequence where each record's granted capability satisfies the next record's
starting precondition, beginning from a principal that the threat model admits.
Check each handoff in source: the exact value, token, file, or state the first
record produces must be the exact input the second record consumes, in the same
deployment mode, tenant, and lifecycle state. A handoff that only "might" work is
a blocker, not a link.

Return only chains whose combined result is strictly more severe than every link
alone. Prefer the shortest chain to each goal. Return exactly one JSON object:
{"chains": [{"chain_id": "...", "title": "...", "description": "...",
  "starting_principal": "...", "links": [{"fingerprint": "...", "requires": "...",
  "provides": "..."}], "claimed_result": "...", "handoff_evidence": [
  {"from": "<fingerprint>", "to": "<fingerprint>", "file": "repo/path",
   "line": 1, "description": "why the output of one is the input of the next"}],
  "open_questions": ["..."]}]}
Return {"chains": []} when no chain is strictly more severe than its links.
```

Chain IDs follow the fingerprint pattern, derive from the link fingerprints (for example `chain-<first>-to-<goal>`), and must not collide with a finding fingerprint.

## Step 3: Chain verifier (`general` agent, frontier tier, one per chain)

The verifier did not hunt, validate, or synthesize any link. It receives the proposed chain, the link records, their ledger checks and artifacts, the evidence ladder, the promotion procedure block, the sandbox boundary, and `chain-schema.json` copied verbatim.

```text
You did not propose this chain. Try to break it.

1. Re-read every handoff location. Confirm that the value produced by each link
   is consumed unchanged (or in a form the next link accepts) by the next link,
   in the same deployment mode, tenant, and state.
2. If every link is confirmed and the sandbox is available, reproduce the whole
   chain in ONE bounded local fixture: start from the starting principal's
   capability, drive each link through its native interface, and stop at the
   minimum combined result. Do not reuse a link's harness if it skips a control
   that the chained path must cross.
3. Decide:
   - confirmed: every link is confirmed AND the end-to-end fixture shows the
     combined result. Severity follows the severity anchors in SKILL.md for the
     combined result; it may exceed every link's severity but never the
     demonstrated combined impact.
   - needs_validation: the composition is source-grounded but a link is
     needs_validation, a handoff depends on an unobserved deployment fact, or the
     end-to-end run is blocked. Name every blocker and an exact local or
     owner-observed plan. No severity.
   - reject: a handoff fails in source, the combined result is not more severe
     than a link alone, or a link's conditions are mutually exclusive.
Return exactly one JSON object and no prose:
{"decision": "confirmed|needs_validation|rejected", "record": { ... } | null, "reason": "..."}
where record matches the chain-schema.json branch for the decision (null when rejected).
```

The parent keeps only `confirmed` and `needs_validation` chain records. It writes them to `chains.json` sorted by `chain_id` and runs:

```sh
node <skill-dir>/validate-chains.cjs <output-dir>/chains.json <output-dir>/findings.json
```

Rejected chains are recorded only in `run-metadata.json` under `rejected_chains` (ID plus one-line reason), so a later run does not re-propose the same composition without new evidence.

## Rules

1. A chain is only as strong as its weakest link. Any `needs_validation` link makes the chain `needs_validation`.
2. A confirmed chain needs one end-to-end local reproduction. Concatenating the links' separate reproductions is not end-to-end evidence.
3. Do not raise a link's own severity because it participates in a chain. The chain carries the combined severity.
4. Do not chain across tenants, deployments, or lifecycle states that the source shows cannot coexist.
5. Phase 5 replacements that change a link's verdict send the chain back through Step 3 (see VALIDATION-AND-REPORTING.md).
