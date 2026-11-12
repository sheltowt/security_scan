#!/usr/bin/env node
"use strict";

/**
 * Diff (PR) mode scope.
 *
 * Usage:
 *   node diff-scope.cjs --target <repo> --base <ref> [--head <ref>] --out <diff-scope.json>
 *
 * Without --head, the diff is base..worktree. Writes the changed files and
 * their changed new-file line ranges. The parent uses this to seed in-scope
 * coverage units (changed surfaces plus their callers and callees) and
 * prefilter.cjs uses it to flag in-diff signals. Unchanged code that the diff
 * relies on stays in scope for tracing; it is not a reason to skip a unit.
 */

const { escapeDiagnostic, parseArgs, writeAtomic } = require("./lib/common.cjs");
const { diffScope, isGitWorktree } = require("./lib/git.cjs");

function run(argv) {
  let options;
  try {
    options = parseArgs(argv);
    if (!options.target || !options.base || !options.out) throw new Error("--target, --base, and --out are required");
  } catch (error) {
    console.error(`diff-scope: ${escapeDiagnostic(error.message)}`);
    console.error("Usage: node diff-scope.cjs --target <repo> --base <ref> [--head <ref>] --out <diff-scope.json>");
    return 2;
  }
  if (!isGitWorktree(options.target)) {
    console.error("diff-scope: target is not a git worktree");
    return 1;
  }
  let scope;
  try {
    scope = diffScope(options.target, options.base, options.head || null);
  } catch (error) {
    console.error(`diff-scope: ${escapeDiagnostic(error.message.split("\n")[0])}`);
    return 1;
  }
  const document = { version: 1, mode: "diff", ...scope };
  writeAtomic(options.out, `${JSON.stringify(document, null, 2)}\n`);
  const lines = scope.files.reduce((total, file) => total + file.ranges.reduce((sum, [start, end]) => sum + end - start + 1, 0), 0);
  console.log(`PASS: ${scope.files.length} changed files, ${lines} changed lines`);
  return 0;
}

if (require.main === module) process.exit(run(process.argv.slice(2)));
