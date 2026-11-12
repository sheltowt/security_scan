# Verified Remediation

### Phase 7: Patch, test, and prove the fix (only on request)

Run this phase only when the user asks for fixes, patches, or a remediation plan with code. Its output is a `.diff` per finding plus evidence that the diff closes the reproduction without breaking the existing tests. The target repository is never modified. The owner decides whether to apply the patch.

Scope: `confirmed` records at or above a user-chosen severity (default `medium`), in severity order, then fingerprint order. `needs_validation` records get no patch: there is nothing reproduced to verify a fix against. Their `validation_plan` is the remediation step.

Budget: one remediator plus one fix verifier per finding, from what remains after Phase 6. Phase 7 can run in a later session against a completed run directory, as long as the source ref is unchanged.

## Step 1: Disposable copy (parent)

For each finding, the parent creates `<output-dir>/agents/<remediator-id>/scratch/src/` as a copy of the target at the run's source ref. Use `git worktree add --detach` or `git archive <ref> | tar -x` with the same safe git flags as `tools/lib/git.cjs`, or a plain copy for non-git targets. Never use a checkout that shares a working tree with the target. The copy lives in scratch, so it is target-controlled from this point on.

## Step 2: Remediator (`general` agent, frontier tier)

The remediator receives the confirmed record, its ledger checks and promoted artifacts, the `architecture.md` facts for the path, the sandbox boundary, and the promotion procedure block.

```text
Write the smallest source change that enforces the violated invariant at the last
trusted decision point named in the record's remediation strategy. Edit only files
under your scratch copy. Do not refactor, reformat, rename, bump dependencies,
or touch unrelated code.

1. Add a regression test in the project's existing test framework and layout that
   encodes the record's reproduction: it fails on the unpatched copy and passes
   on the patched copy. Use dummy principals and fixtures only.
2. In the sandbox (tools/sandbox-run.sh, target mounted from your scratch copy):
   a. run the regression test on the UNPATCHED copy and confirm it fails for the
      claimed reason;
   b. apply the patch and run the regression test again: it must pass;
   c. re-run the record's original reproduction (execution.instructions and
      payloads): the boundary result must no longer occur;
   d. run the project's existing test suite (or the narrowest documented subset
      that covers the changed files) and record pass/fail counts.
3. Check sibling paths named in the record and in its ledger unit (batch, legacy,
   alternate routes). If the same root cause appears there, fix it in the same
   patch, or say why it is out of scope.
4. Write the patch as a unified diff relative to the repository root, at
   scratch/patches/<fingerprint>.diff, plus the regression test inside the diff.
Return exactly one JSON object and no prose:
{"fingerprint": "...", "patch_file": "patches/<fingerprint>.diff",
 "regression_test": "repo/relative/test/path", "unpatched_test_result": "...",
 "patched_test_result": "...", "poc_after": "...", "tests_after": "...",
 "siblings": "...", "status": "verified|failed", "notes": "..."}
```

If the sandbox is unavailable, the remediator may still write the patch and the regression test from source. In that case it returns `status: "not_attempted"` with the missing control in `notes`, and the record says the fix is unverified.

## Step 3: Fix verifier (`general` agent, frontier tier, fresh)

The parent promotes `patches/<fingerprint>.diff` with `tools/promote.py`, then gives a fresh verifier (one that did not hunt, validate, or remediate this finding) a new clean copy, the patch, and the record.

```text
You did not write this patch. Try to show it is wrong or incomplete.
1. Apply the patch to your clean copy. It must apply without fuzz.
2. Re-run the record's original reproduction and the regression test, unpatched
   and patched, in the sandbox. Confirm the patched run no longer shows the
   boundary result and the unpatched run still does.
3. Try one variant of the original input that targets the same invariant (a
   different encoding, the batch path, a sibling route) against the patched copy.
4. Run the existing test suite on the patched copy.
5. Read the diff: it must enforce the invariant at a trusted decision point, not
   move trust, disable a feature, or only special-case the PoC input.
Return {"decision": "verified|failed", "poc_after": "...", "tests_after": "...",
 "variant_result": "...", "notes": "..."} and no prose.
```

## Step 4: Record and report (parent)

- Copy the promoted diff to `<output-dir>/patches/<fingerprint>.diff`.
- Set the record's `fix_verification`: `verified` only when the fix verifier returned `verified`. Use `failed` with notes when either agent found the fix incomplete, and `not_attempted` with notes when the sandbox or budget blocked it. Re-run `validate-findings.cjs`, then regenerate `results.sarif`.
- Write `REMEDIATION.md`: one section per finding with severity, the invariant, the patch path, the regression test path, the before/after reproduction results, the test-suite results, the sibling-path note, and the variant result. List unverified and failed fixes first, so nobody mistakes them for done.

A patch is a proposal. Say plainly in `REMEDIATION.md` that it was verified only against the local reproduction, the variant, and the existing tests, and that it still needs owner review.
