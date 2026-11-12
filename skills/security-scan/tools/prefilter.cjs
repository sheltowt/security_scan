#!/usr/bin/env node
"use strict";

/**
 * Phase 0 deterministic prefilter.
 *
 * Usage:
 *   node prefilter.cjs --target <repo> --out <signals.json>
 *     [--diff-scope <diff-scope.json>] [--signatures <file>]
 *     [--exclude <path-prefix>]... [--max-file-bytes N] [--max-signals N]
 *
 * Scans the target with linear, line-oriented regular expressions and writes
 * signals.json: ranked hotspots plus file:line triage signals. It never runs
 * target code, never follows symlinks, and never copies source text into its
 * output (matched lines can contain secrets), only repository-relative
 * locations and rule metadata.
 */

const fs = require("fs");
const path = require("path");
const { TextDecoder } = require("util");
const { SafeInputError, escapeDiagnostic, isSafeRelativePath, parseArgs, readBoundedBuffer, readBoundedJson, writeAtomic } = require("./lib/common.cjs");
const { isGitWorktree, listFiles, sourceRef } = require("./lib/git.cjs");
const { buildDocument, isTestPath, normalizeLine, signalId } = require("./lib/signals.cjs");

const DEFAULTS = Object.freeze({
  maxFileBytes: 1024 * 1024,
  maxSignals: 20000,
  maxPerRulePerFile: 20,
  maxLineLength: 4096,
});
const EXCLUDED_DIRECTORIES = new Set([
  ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "third_party", "third-party",
  "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache", "coverage",
  ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".gradle", ".idea",
  ".terraform", "Pods", "DerivedData",
]);
const EXCLUDED_FILE = /(?:\.min\.(?:js|css)|\.map|(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|poetry\.lock|composer\.lock|Gemfile\.lock))$/;
const LOOSE_DECODER = new TextDecoder("utf-8", { fatal: false });

function loadSignatures(file) {
  const document = readBoundedJson(file, 2 * 1024 * 1024);
  if (!document || !Array.isArray(document.rules) || typeof document.language_groups !== "object") {
    throw new Error("signatures file must contain language_groups and rules");
  }
  const ids = new Set();
  return document.rules.map((rule) => {
    if (typeof rule.id !== "string" || !/^[a-z0-9][a-z0-9.-]*$/.test(rule.id) || ids.has(rule.id)) {
      throw new Error(`invalid or duplicate rule id ${JSON.stringify(rule.id)}`);
    }
    ids.add(rule.id);
    const extensions = new Set();
    for (const group of rule.languages) {
      const members = document.language_groups[group];
      if (!Array.isArray(members)) throw new Error(`rule ${rule.id}: unknown language group ${JSON.stringify(group)}`);
      members.forEach((member) => extensions.add(member));
    }
    return {
      id: rule.id,
      title: rule.title,
      class: rule.class || null,
      cwe: rule.cwe || [],
      severity_hint: rule.severity_hint,
      // Drop stateful flags: a global or sticky regex would carry lastIndex between lines.
      regex: new RegExp(rule.pattern, (rule.flags || "").replace(/[gy]/g, "")),
      paths: rule.paths ? new RegExp(rule.paths) : null,
      extensions,
    };
  });
}

function fileMatchesRule(rule, file) {
  if (rule.paths && !rule.paths.test(file)) return false;
  if (rule.extensions.has("*")) return true;
  const base = path.posix.basename(file);
  const extension = path.posix.extname(base).toLowerCase();
  if (rule.extensions.has(extension)) return true;
  if (rule.extensions.has(base)) return true;
  // Dockerfile.dev, Containerfile.prod
  return [...rule.extensions].some((entry) => !entry.startsWith(".") && entry !== "*" && base.startsWith(`${entry}.`));
}

function walk(root) {
  const files = [];
  const stack = [""];
  while (stack.length > 0) {
    const relative = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(path.join(root, relative), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) stack.push(child);
      } else if (entry.isFile()) {
        files.push(child);
      }
    }
  }
  return files;
}

function isExcluded(file, prefixes) {
  if (EXCLUDED_FILE.test(file)) return true;
  if (file.split("/").slice(0, -1).some((segment) => EXCLUDED_DIRECTORIES.has(segment))) return true;
  return prefixes.some((prefix) => file === prefix || file.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`));
}

function loadDiffScope(file) {
  const document = readBoundedJson(file, 16 * 1024 * 1024);
  if (!document || !Array.isArray(document.files)) throw new Error("diff scope must contain a files array");
  const map = new Map();
  for (const entry of document.files) {
    if (!isSafeRelativePath(entry.path) || entry.status === "D") continue;
    map.set(entry.path, entry);
  }
  return { document, map };
}

function inRanges(scopeEntry, line) {
  if (!scopeEntry.ranges_known) return true;
  return scopeEntry.ranges.some(([start, end]) => line >= start && line <= end);
}

function scan(options) {
  const target = fs.realpathSync(options.target);
  const rules = loadSignatures(options.signatures);
  const diff = options.diffScope ? loadDiffScope(options.diffScope) : null;
  const useGit = isGitWorktree(target);
  let files = useGit ? listFiles(target) : walk(target);
  files = files.filter((file) => isSafeRelativePath(file) && !isExcluded(file, options.exclude));
  if (diff) files = files.filter((file) => diff.map.has(file));
  files.sort();

  const stats = { listing: useGit ? "git" : "walk", files_considered: files.length, files_scanned: 0, skipped_binary: 0, skipped_large: 0, skipped_unreadable: 0, long_lines_skipped: 0, truncated: false };
  const signals = [];

  for (const file of files) {
    if (signals.length >= options.maxSignals) {
      stats.truncated = true;
      break;
    }
    const applicable = rules.filter((rule) => fileMatchesRule(rule, file));
    if (applicable.length === 0) continue;
    const absolute = path.join(target, file);
    let buffer;
    try {
      // Reject a path whose parent components resolve outside the target.
      const real = fs.realpathSync(absolute);
      if (real !== absolute && !real.startsWith(`${target}${path.sep}`)) throw new SafeInputError("outside target");
      buffer = readBoundedBuffer(absolute, options.maxFileBytes);
    } catch (error) {
      if (error instanceof SafeInputError && /byte limit/.test(error.message)) stats.skipped_large++;
      else stats.skipped_unreadable++;
      continue;
    }
    if (buffer.subarray(0, 8000).includes(0)) {
      stats.skipped_binary++;
      continue;
    }
    stats.files_scanned++;
    const lines = LOOSE_DECODER.decode(buffer).split(/\r?\n/);
    const inTest = isTestPath(file);
    const scopeEntry = diff ? diff.map.get(file) : null;
    const perRule = new Map();
    const occurrences = new Map();

    for (let index = 0; index < lines.length; index++) {
      const text = lines[index];
      if (text.length > DEFAULTS.maxLineLength) {
        stats.long_lines_skipped++;
        continue;
      }
      for (const rule of applicable) {
        if (!rule.regex.test(text)) continue;
        const count = perRule.get(rule.id) || 0;
        if (count >= DEFAULTS.maxPerRulePerFile) continue;
        perRule.set(rule.id, count + 1);
        const normalized = normalizeLine(text);
        const occurrenceKey = `${rule.id}\0${normalized}`;
        const occurrence = occurrences.get(occurrenceKey) || 0;
        occurrences.set(occurrenceKey, occurrence + 1);
        const signal = {
          id: signalId("prefilter", rule.id, file, normalized, occurrence),
          source: "prefilter",
          rule_id: rule.id,
          title: rule.title,
          file,
          line: index + 1,
          class: rule.class,
          cwe: rule.cwe,
          severity_hint: rule.severity_hint,
          in_test: inTest,
        };
        if (scopeEntry) signal.in_diff = inRanges(scopeEntry, index + 1);
        signals.push(signal);
      }
    }
  }

  const scope = diff
    ? { mode: "diff", base: diff.document.base || null, head: diff.document.head || null, changed_files: diff.map.size }
    : { mode: "full" };
  return buildDocument({ signals, scope, sourceRef: useGit ? sourceRef(target) : null, scanned: stats, tools: ["prefilter"] });
}

function run(argv) {
  let options;
  try {
    const parsed = parseArgs(argv, { repeatable: ["exclude"] });
    if (!parsed.target || !parsed.out) throw new Error("--target and --out are required");
    options = {
      target: parsed.target,
      out: parsed.out,
      diffScope: parsed["diff-scope"] || null,
      signatures: parsed.signatures || path.join(__dirname, "signatures.json"),
      exclude: parsed.exclude,
      maxFileBytes: parsed["max-file-bytes"] ? Number(parsed["max-file-bytes"]) : DEFAULTS.maxFileBytes,
      maxSignals: parsed["max-signals"] ? Number(parsed["max-signals"]) : DEFAULTS.maxSignals,
    };
    if (!Number.isInteger(options.maxFileBytes) || options.maxFileBytes < 1) throw new Error("--max-file-bytes must be a positive integer");
    if (!Number.isInteger(options.maxSignals) || options.maxSignals < 1) throw new Error("--max-signals must be a positive integer");
  } catch (error) {
    console.error(`prefilter: ${escapeDiagnostic(error.message)}`);
    console.error("Usage: node prefilter.cjs --target <repo> --out <signals.json> [--diff-scope <file>] [--exclude <prefix>]...");
    return 2;
  }
  let document;
  try {
    document = scan(options);
  } catch (error) {
    console.error(`prefilter: ${escapeDiagnostic(error.message)}`);
    return 1;
  }
  writeAtomic(options.out, `${JSON.stringify(document, null, 2)}\n`);
  const { summary, scanned } = document;
  console.log(`PASS: ${summary.total} signals from ${scanned.files_scanned} files${scanned.truncated ? " (truncated at --max-signals)" : ""}`);
  return 0;
}

module.exports = { fileMatchesRule, loadSignatures, scan };

if (require.main === module) process.exit(run(process.argv.slice(2)));
