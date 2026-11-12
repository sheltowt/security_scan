# Deterministic Prefilter

### Phase 0: Build `signals.json` before any agent runs

Agent time is the expensive resource in this workflow. Spend a few seconds of deterministic scanning first, so reconnaissance and hunters start from the code most likely to matter. Phase 0 is a triage aid, never a source of findings:

- A **signal** is a repository-relative `file:line` plus a rule, class, CWE list, and severity hint. It records that a pattern appeared, not that a vulnerability exists.
- Signals **reorder** coverage units and **seed** hunter context. They never close, skip, or remove a unit, and an absent signal is not evidence of safety. Business logic, authorization, and most chained bugs produce no signal at all. Hunters must cover them anyway.
- No signal enters `findings.json`. A record may list `signal_ids` as provenance, and only after a hunter established the trace and a verifier reproduced it.

The parent runs Phase 0 itself. It needs no sandbox because it never executes target code, and it costs no agent invocations.

## Step 1 (diff mode only): change set

```sh
node <skill-dir>/tools/diff-scope.cjs --target <target> --base <base-ref> [--head <head-ref>] --out <output-dir>/diff-scope.json
```

See [DIFF-MODE.md](DIFF-MODE.md) for choosing refs.

## Step 2: regex prefilter

```sh
node <skill-dir>/tools/prefilter.cjs --target <target> --out <output-dir>/signals.json \
  [--diff-scope <output-dir>/diff-scope.json] [--exclude <path-prefix>]...
```

The prefilter lists files with `git ls-files` (respecting `.gitignore`) or a no-symlink walk, skips vendored and generated directories, lockfiles, minified files, binaries, files over 1 MiB, and lines over 4,096 characters. It then applies the line-oriented signatures in `tools/signatures.json`. It never copies source text into its output: matched lines can contain secrets, and hunters read the source themselves. Signal IDs hash the normalized line text, not the line number, so they stay stable across runs when unrelated lines move.

Git runs with fsmonitor, hooks, external diff, textconv, and global/system config disabled, because a target checkout can carry configuration that executes commands.

Use `--exclude` only for paths the user put out of scope. Excluding a directory because it "looks noisy" hides real surfaces.

## Step 3: import local SAST results (optional, recommended)

If a SAST tool is already installed locally, run it read-only against the target and import its SARIF. Do not install tools or download rule packs during the run. Use only rules already present on the machine, and never let a tool upload results.

| Tool | Example (offline, local rules) |
|---|---|
| Semgrep / OpenGrep | `semgrep scan --config <local-rules-dir> --sarif --output semgrep.sarif --metrics=off <target>` |
| CodeQL | `codeql database create db --language=<lang> --source-root <target> --build-mode=none` then `codeql database analyze db <local-pack> --format=sarif-latest --output codeql.sarif` |
| Bandit (Python) | `bandit -r <target> -f sarif -o bandit.sarif` |
| gosec (Go) | `gosec -fmt sarif -out gosec.sarif ./...` (run from a disposable copy) |
| Brakeman (Rails) | `brakeman -f sarif -o brakeman.sarif <target>` |

A tool that builds or loads target code (CodeQL with a traced build, gosec loading packages, linters that execute plugins or config from the repo) is running target-controlled code. Run it through `tools/sandbox-run.sh` under the same controls as any other target execution. Otherwise prefer source-only modes such as CodeQL `--build-mode=none`.

```sh
node <skill-dir>/tools/import-sarif.cjs --sarif semgrep.sarif [--sarif codeql.sarif]... \
  --into <output-dir>/signals.json --out <output-dir>/signals.json --source-root <target>
```

Import drops suppressed results and any result whose location is absolute outside `--source-root`, traverses upward, or is otherwise not a safe repository-relative path. It maps CWE tags to attack classes. Files flagged by two independent sources (prefilter and a SAST tool, or two tools) get a corroboration boost in the hotspot ranking.

## How later phases use signals

- **Reconnaissance** (RECONNAISSANCE.md) receives `hotspots.files`, `hotspots.directories`, and `summary.by_class`, never the full signal list. Agent 1c uses hotspots to make sure every high-scoring file appears in the surface inventory. A high-scoring file with no mapped entry surface is itself a coverage question for the critic.
- **Ledger seeding** stores each unit's matching signal IDs in the `signal_ids` bookkeeping field and its summed hotspot score in `priority.signal_score`.
- **Hunters** (HUNTING.md) receive the signals for their own units as an explicit lead list and return a disposition for each one.
- **Reporting** (Phase 6) states the prefilter's lead rate: dispositioned signals that became candidates, versus `false_positive`. That feedback is what tunes `signatures.json` for the next run.

## Tuning signatures

`tools/signatures.json` is plain data. To add a rule, give it a unique `id`, `languages` from `language_groups`, an optional `paths` regex, a linear `pattern` (no nested quantifiers; use bounded `{0,N}` repetitions), a `class` that names a real block (`FILE.md#Exact block name`), `cwe`, and `severity_hint`. `tools/tools.test.cjs` checks that every class resolves and that every pattern stays fast on hostile input. Prefer rules that point at sinks and trust decisions over rules that flag style.
