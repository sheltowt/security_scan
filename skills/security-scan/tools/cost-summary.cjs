#!/usr/bin/env node
"use strict";

/**
 * Summarize agent spend for a run.
 *
 * Usage:
 *   node cost-summary.cjs --ledger <cost-ledger.jsonl> [--metadata <run-metadata.json>]
 *     [--prices <prices.json>] [--out <COST.md>] [--json]
 *
 * The parent appends one JSON object per agent invocation to cost-ledger.jsonl:
 *   {"agent_id":"h-auth-1","phase":"2","role":"hunter","model":"<model id>",
 *    "model_tier":"frontier","input_tokens":51234,"output_tokens":3810,
 *    "cache_read_tokens":0,"wall_seconds":212}
 * Token counts come from the platform's usage report for that sub-agent; when
 * the platform does not expose them, record null and the summary counts
 * invocations only. Prices are optional and supplied by the user, because
 * model prices change; nothing here hardcodes them.
 */

const { compareStrings, escapeDiagnostic, parseArgs, readBoundedJson, readBoundedText, writeAtomic } = require("./lib/common.cjs");

const ROLES = new Set(["recon", "hunter", "critic", "verifier", "record-verifier", "chain", "remediator", "fix-verifier", "reporter", "other"]);
const TIERS = new Set(["triage", "frontier"]);
const PHASES = new Set(["0", "1", "2", "3", "3b", "4", "5", "6", "7"]);
const TOKEN_FIELDS = ["input_tokens", "output_tokens", "cache_read_tokens"];

function parseLedger(text) {
  const entries = [];
  const errors = [];
  text.split("\n").forEach((line, index) => {
    if (line.trim() === "") return;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      errors.push(`line ${index + 1}: invalid JSON`);
      return;
    }
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`line ${index + 1}: expected an object`);
      return;
    }
    if (typeof entry.agent_id !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(entry.agent_id)) errors.push(`line ${index + 1}: agent_id must be a canonical lowercase agent ID`);
    if (!PHASES.has(String(entry.phase))) errors.push(`line ${index + 1}: phase must be one of ${[...PHASES].join(", ")}`);
    if (!ROLES.has(entry.role)) errors.push(`line ${index + 1}: role must be one of ${[...ROLES].join(", ")}`);
    if (entry.model_tier !== undefined && !TIERS.has(entry.model_tier)) errors.push(`line ${index + 1}: model_tier must be triage or frontier`);
    for (const field of TOKEN_FIELDS) {
      const value = entry[field];
      if (value !== undefined && value !== null && (!Number.isInteger(value) || value < 0)) errors.push(`line ${index + 1}: ${field} must be a non-negative integer or null`);
    }
    entries.push(entry);
  });
  return { entries, errors };
}

function emptyBucket() {
  return { invocations: 0, input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, unreported: 0, usd: 0, unpriced: 0 };
}

function add(bucket, entry, prices) {
  bucket.invocations++;
  const reported = TOKEN_FIELDS.some((field) => Number.isInteger(entry[field]));
  if (!reported) bucket.unreported++;
  for (const field of TOKEN_FIELDS) if (Number.isInteger(entry[field])) bucket[field] += entry[field];
  const price = prices && entry.model ? prices[entry.model] : null;
  if (price && reported) {
    bucket.usd += ((entry.input_tokens || 0) * (price.input_per_mtok || 0) +
      (entry.output_tokens || 0) * (price.output_per_mtok || 0) +
      (entry.cache_read_tokens || 0) * (price.cache_read_per_mtok || 0)) / 1e6;
  } else if (reported) {
    bucket.unpriced++;
  }
}

function summarize(entries, { prices = null, budget = null } = {}) {
  const total = emptyBucket();
  const groups = { phase: new Map(), role: new Map(), model_tier: new Map(), model: new Map() };
  for (const entry of entries) {
    add(total, entry, prices);
    for (const [key, map] of Object.entries(groups)) {
      const name = entry[key] === undefined || entry[key] === null ? "unspecified" : String(entry[key]);
      if (!map.has(name)) map.set(name, emptyBucket());
      add(map.get(name), entry, prices);
    }
  }
  const toObject = (map) => Object.fromEntries([...map.entries()].sort(([a], [b]) => compareStrings(a, b)));
  return {
    total,
    budget,
    budget_remaining: Number.isInteger(budget) ? budget - total.invocations : null,
    priced: Boolean(prices),
    by_phase: toObject(groups.phase),
    by_role: toObject(groups.role),
    by_model_tier: toObject(groups.model_tier),
    by_model: toObject(groups.model),
  };
}

function formatNumber(value) {
  return value.toLocaleString("en-US");
}

function toMarkdown(summary) {
  const lines = ["# Run cost", ""];
  const { total } = summary;
  lines.push(`- Agent invocations: ${formatNumber(total.invocations)}${Number.isInteger(summary.budget) ? ` of budget ${formatNumber(summary.budget)} (${formatNumber(summary.budget_remaining)} remaining)` : ""}`);
  lines.push(`- Tokens: ${formatNumber(total.input_tokens)} input, ${formatNumber(total.output_tokens)} output, ${formatNumber(total.cache_read_tokens)} cache read`);
  if (total.unreported > 0) lines.push(`- ${total.unreported} invocation(s) had no token report; token totals are a lower bound`);
  if (summary.priced) lines.push(`- Estimated cost: $${total.usd.toFixed(2)} (user-supplied prices${total.unpriced > 0 ? `; ${total.unpriced} invocation(s) used an unpriced model` : ""})`);
  for (const [title, key] of [["By phase", "by_phase"], ["By role", "by_role"], ["By model tier", "by_model_tier"]]) {
    lines.push("", `## ${title}`, "", "| Group | Invocations | Input tokens | Output tokens |" + (summary.priced ? " Est. USD |" : ""), "|---|---:|---:|---:|" + (summary.priced ? "---:|" : ""));
    for (const [name, bucket] of Object.entries(summary[key])) {
      lines.push(`| ${name} | ${formatNumber(bucket.invocations)} | ${formatNumber(bucket.input_tokens)} | ${formatNumber(bucket.output_tokens)} |` + (summary.priced ? ` ${bucket.usd.toFixed(2)} |` : ""));
    }
  }
  return `${lines.join("\n")}\n`;
}

function run(argv) {
  let options;
  try {
    options = parseArgs(argv, { booleans: ["json"] });
    if (!options.ledger) throw new Error("--ledger is required");
  } catch (error) {
    console.error(`cost-summary: ${escapeDiagnostic(error.message)}`);
    return 2;
  }
  let parsed;
  let prices = null;
  let budget = null;
  try {
    parsed = parseLedger(readBoundedText(options.ledger, 32 * 1024 * 1024));
    if (options.prices) prices = readBoundedJson(options.prices, 1024 * 1024);
    if (options.metadata) {
      const metadata = readBoundedJson(options.metadata, 1024 * 1024);
      budget = Number.isInteger(metadata.budget) ? metadata.budget : null;
    }
  } catch (error) {
    console.error(`cost-summary: ${escapeDiagnostic(error.message)}`);
    return 1;
  }
  if (parsed.errors.length > 0) {
    parsed.errors.slice(0, 50).forEach((message) => console.error(`ERROR: ${escapeDiagnostic(message)}`));
    console.error(`FAIL: ${parsed.errors.length} ledger error(s)`);
    return 1;
  }
  const summary = summarize(parsed.entries, { prices, budget });
  const output = options.json ? `${JSON.stringify(summary, null, 2)}\n` : toMarkdown(summary);
  if (options.out) writeAtomic(options.out, output);
  else process.stdout.write(output);
  return 0;
}

module.exports = { parseLedger, summarize, toMarkdown };

if (require.main === module) process.exit(run(process.argv.slice(2)));
