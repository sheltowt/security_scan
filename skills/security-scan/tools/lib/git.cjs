"use strict";

/**
 * Read-only git helpers for an untrusted target checkout.
 *
 * A target repository can carry configuration and attributes that make git
 * run commands (fsmonitor, external diff, textconv, hooks). Every call here
 * disables those paths and never uses the user's global or system config.
 */

const { execFileSync } = require("child_process");

const SAFE_GIT_ARGS = [
  "-c", "core.fsmonitor=false",
  "-c", "core.hooksPath=/dev/null",
  "-c", "diff.external=",
  "-c", "core.pager=cat",
  "-c", "protocol.allow=never",
  "--no-pager",
];

function gitEnv() {
  // Start from an allowlist rather than inheriting the caller's environment.
  const env = {
    PATH: process.env.PATH || "/usr/bin:/bin",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_OPTIONAL_LOCKS: "0",
    LC_ALL: "C",
  };
  if (process.env.HOME) env.HOME = process.env.HOME;
  return env;
}

function git(target, args, { maxBuffer = 64 * 1024 * 1024 } = {}) {
  return execFileSync("git", [...SAFE_GIT_ARGS, "-C", target, ...args], {
    encoding: "buffer",
    env: gitEnv(),
    maxBuffer,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
  });
}

function isGitWorktree(target) {
  try {
    return git(target, ["rev-parse", "--is-inside-work-tree"]).toString("utf8").trim() === "true";
  } catch {
    return false;
  }
}

/** Tracked plus untracked-but-not-ignored files, NUL-separated to survive odd names. */
function listFiles(target) {
  const output = git(target, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]);
  return [...new Set(output.toString("utf8").split("\0").filter(Boolean))];
}

function sourceRef(target) {
  try {
    const head = git(target, ["rev-parse", "HEAD"]).toString("utf8").trim();
    const dirty = git(target, ["status", "--porcelain", "-z", "--untracked-files=no"]).length > 0;
    return { commit: head, dirty };
  } catch {
    return null;
  }
}

const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/@^~+-]*$/;

/**
 * Changed line ranges between `base` and `head` (or the worktree when head is
 * null). Returns { files: [{ path, status, ranges: [[start, end], ...] }] }
 * where ranges are inclusive new-file line numbers. Deleted files have no ranges.
 */
function diffScope(target, base, head = null) {
  for (const ref of [base, head].filter((value) => value !== null)) {
    if (!REF_PATTERN.test(ref) || ref.includes("..")) throw new Error(`unsafe git ref ${JSON.stringify(ref)}`);
  }
  const revs = head === null ? [base] : [base, head];
  const diffArgs = ["-c", "core.quotePath=false", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames"];
  const status = git(target, [...diffArgs, "--name-status", "-z", ...revs, "--"]).toString("utf8").split("\0").filter(Boolean);
  const files = new Map();
  for (let index = 0; index + 1 < status.length; index += 2) {
    // Until a hunk header maps to the file, every line counts as changed.
    files.set(status[index + 1], { path: status[index + 1], status: status[index][0], ranges: [], ranges_known: false });
  }
  const patch = git(target, [...diffArgs, "--unified=0", ...revs, "--"]).toString("utf8");
  let current = null;
  for (const line of patch.split("\n")) {
    if (line.startsWith("+++ ")) {
      const name = line.slice(4);
      current = name === "/dev/null" ? null : files.get(name.replace(/^b\//, "")) || null;
      if (current) current.ranges_known = true;
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk && current) {
      const start = Number(hunk[1]);
      const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
      if (count > 0) current.ranges.push([start, start + count - 1]);
    }
  }
  return { base, head, files: [...files.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) };
}

module.exports = { diffScope, git, isGitWorktree, listFiles, sourceRef };
