# Diff Mode

Review a change set: a pull request, a branch against its merge base, or any `<base>..<head>`. Diff mode is a scoped full-audit run. It keeps every evidence rule and changes only which ledger units are seeded. It is partial coverage by definition, and the report says so.

## Choosing refs

- **Pull request**: `base` is the merge base with the target branch (`git merge-base origin/main HEAD`) and `head` is the PR head commit. Do not use the target branch tip as base: unrelated changes merged since the branch point would appear as part of the PR.
- **Local work**: `base` is the last reviewed commit, and `head` is omitted to compare against the worktree. Record `dirty: true` in `source_ref`.
- **Release delta**: `base` is the previous release tag, `head` the candidate tag.

Refs must already exist locally. Never fetch during the run. If the user names a remote PR that is not checked out, ask them to check it out (for example `! gh pr checkout <n>`) instead of fetching it yourself.

## Seeding

Run Phase 0 with `diff-scope.cjs` and then `prefilter.cjs --diff-scope`. In Phase 1, give reconnaissance the changed-file list. Then seed ledger units for:

1. **Changed surfaces**: every entry surface, boundary, or sink whose implementation includes a changed line.
2. **Changed controls**: every authentication, authorization, validation, encoding, or isolation control with a changed line. Seed a unit for each surface that relies on it, even if the surface itself did not change. A weakened check in shared middleware is the classic diff-mode miss.
3. **New dependencies, workflows, and configuration**: changed manifests, lockfiles, CI workflows, IaC, and container files. Use SUPPLY-CHAIN-AND-RELEASE.md and CLOUD-AND-DEPLOYMENT.md.
4. **Removed code**: deleted checks, tests, or validation. Diff `--name-status` reports `D`, and hunks show removed lines. A removal is reviewed for what it stopped enforcing.

Everything else is `out_of_scope` with reason `diff_mode_unchanged`. Hunters may still *read* unchanged code to trace a path. They just are not assigned it. Set `priority.in_diff` on seeded units and rank them first (HUNTING.md).

Give hunters the changed line ranges for their units (HUNTING.md part 3a) and add this sentence to their role preamble: "Focus on what this change introduces or weakens; a pre-existing issue on the same path is still in scope if the change makes it reachable or worse, and out of scope otherwise. Say which in the candidate description."

## Profiles and budget

Use `quick` for small PRs (under about 300 changed lines in one subsystem) and `standard` otherwise. Diff mode rarely needs `deep`. If the change touches a crown-jewel boundary from a prior full run's threat model, say so and offer `standard`.

## Reporting

`REPORT.md` opens with the base and head refs, the number of changed files and lines, and this statement: "This is a change-scoped review. Code outside the change was read only where the change depends on it; it was not otherwise audited." List pre-existing issues the hunters noticed but did not assign as hardening notes or `out_of_scope` units, never as findings of this change.

## CI usage

Diff mode runs headless in CI. `examples/github-actions/security-scan-pr.yml` in this repository shows a GitHub Actions workflow that checks out the PR, runs a coding agent with this skill in diff mode, validates the outputs, and uploads `results.sarif` to code scanning. Keep these properties if you adapt it:

- Trigger on `pull_request`, never `pull_request_target`. Untrusted PR code must not run with repository secrets or write tokens.
- Give the agent job a read-only `GITHUB_TOKEN` (`contents: read`). Only the separate upload step gets `security-events: write`.
- Treat the agent's output as untrusted until `validate-findings.cjs` and `validate-chains.cjs` pass. Fail the job on a validator failure, not on the presence of findings, unless the team chooses to gate merges on `confirmed` high or critical records.
- The CI runner is the sandbox boundary for the agent itself. Target execution inside the run still goes through `sandbox-run.sh`, with network disabled.
