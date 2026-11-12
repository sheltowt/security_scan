#!/usr/bin/env node
"use strict";

/**
 * Import SAST results (SARIF 2.1.0) as Phase 0 signals.
 *
 * Usage:
 *   node import-sarif.cjs --sarif <file.sarif> [--sarif <more.sarif>]...
 *     --out <signals.json> [--into <existing signals.json>] [--source-root <abs path>]
 *
 * Works with any SARIF producer already installed locally (Semgrep, OpenGrep,
 * CodeQL, Bandit, gosec, Brakeman, ...). Imported results become signals:
 * they raise the priority of coverage units and are handed to hunters as
 * leads. They are never copied into findings.json; a hunter must establish
 * the trace and a verifier must reproduce it like any other candidate.
 */

const path = require("path");
const { escapeDiagnostic, isSafeRelativePath, parseArgs, readBoundedJson, sha256, writeAtomic } = require("./lib/common.cjs");
const { buildDocument, isTestPath, validateSignalsDocument } = require("./lib/signals.cjs");

const MAX_SARIF_BYTES = 64 * 1024 * 1024;
const MAX_RESULTS = 50000;
const CWE_TO_CLASS = new Map([
  ...[77, 78, 79, 89, 90, 91, 94, 95, 98, 113, 117, 643, 917, 943, 1336].map((id) => [id, "ATTACK-CLASSES.md#Injection"]),
  ...[22, 23, 36, 59, 73, 367, 377, 502, 601, 611, 776, 918].map((id) => [id, "ATTACK-CLASSES.md#Resource and file handling"]),
  ...[269, 284, 285, 287, 306, 352, 639, 732, 862, 863, 915].map((id) => [id, "ATTACK-CLASSES.md#Access control"]),
  ...[208, 295, 310, 311, 319, 326, 327, 328, 329, 330, 338, 347, 916].map((id) => [id, "ATTACK-CLASSES.md#Cryptography and secrets"]),
  ...[200, 209, 215, 489, 532, 798].map((id) => [id, "ATTACK-CLASSES.md#Obvious things"]),
  ...[119, 120, 121, 122, 125, 134, 190, 191, 415, 416, 476, 787].map((id) => [id, "MEMORY-SAFETY-AND-BINARY.md#Out-of-bounds read or write"]),
]);

function sanitizeIdPart(value, fallback) {
  const cleaned = String(value || "").replace(/[^A-Za-z0-9._/-]+/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 120);
  return cleaned || fallback;
}

function extractCwes(tags) {
  const found = new Set();
  for (const tag of Array.isArray(tags) ? tags : []) {
    const match = /\bcwe[-_/:\s]?0*([1-9][0-9]{0,4})\b/i.exec(String(tag));
    if (match) found.add(`CWE-${match[1]}`);
  }
  return [...found].sort();
}

function severityHint(rule, result) {
  const raw = (result.properties && result.properties["security-severity"]) || (rule && rule.properties && rule.properties["security-severity"]);
  const score = Number(raw);
  if (Number.isFinite(score) && raw !== undefined) return score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  const level = result.level || (rule && rule.defaultConfiguration && rule.defaultConfiguration.level) || "warning";
  return level === "error" ? "high" : level === "warning" ? "medium" : "low";
}

function relativeUri(uri, base, sourceRoot) {
  if (typeof uri !== "string" || uri.length === 0) return null;
  let value = uri;
  try {
    value = decodeURIComponent(value);
  } catch {
    return null;
  }
  if (value.startsWith("file://")) value = value.slice("file://".length);
  if (base && typeof base === "string" && !path.posix.isAbsolute(value)) value = path.posix.join(base.replace(/^file:\/\//, ""), value);
  if (path.posix.isAbsolute(value)) {
    if (!sourceRoot) return null;
    const root = sourceRoot.endsWith("/") ? sourceRoot : `${sourceRoot}/`;
    if (!value.startsWith(root)) return null;
    value = value.slice(root.length);
  }
  value = value.replace(/^(?:\.\/)+/, "");
  return isSafeRelativePath(value) ? value : null;
}

function importRun(run, sourceRoot, counters) {
  const driver = (run.tool && run.tool.driver) || {};
  const tool = sanitizeIdPart(String(driver.name || "sarif").toLowerCase(), "sarif").replace(/[/.]/g, "-");
  const rules = new Map();
  const ruleList = [...(driver.rules || []), ...((run.tool && run.tool.extensions) || []).flatMap((extension) => extension.rules || [])];
  ruleList.forEach((rule, index) => {
    if (rule && typeof rule.id === "string") rules.set(rule.id, rule);
    rules.set(`#${index}`, rule);
  });
  const baseIds = run.originalUriBaseIds || {};
  const signals = [];

  for (const result of Array.isArray(run.results) ? run.results : []) {
    if (counters.results >= MAX_RESULTS) {
      counters.truncated = true;
      break;
    }
    counters.results++;
    if (!result || result.suppressions && result.suppressions.length > 0) {
      counters.suppressed++;
      continue;
    }
    const ruleId = result.ruleId || (result.rule && result.rule.id) || (result.rule && Number.isInteger(result.rule.index) ? `#${result.rule.index}` : null);
    const rule = rules.get(ruleId) || (result.rule && Number.isInteger(result.rule.index) ? rules.get(`#${result.rule.index}`) : null) || null;
    const location = result.locations && result.locations[0] && result.locations[0].physicalLocation;
    const artifact = location && location.artifactLocation;
    const baseId = artifact && artifact.uriBaseId;
    const base = baseId && baseIds[baseId] && baseIds[baseId].uri;
    const file = artifact ? relativeUri(artifact.uri, base, sourceRoot) : null;
    const line = location && location.region && Number.isInteger(location.region.startLine) ? location.region.startLine : null;
    if (!file || !line || line < 1) {
      counters.unlocated++;
      continue;
    }
    const tags = [...((rule && rule.properties && rule.properties.tags) || []), ...((result.properties && result.properties.tags) || [])];
    const cwe = extractCwes(tags);
    const ruleName = sanitizeIdPart(rule && rule.id || ruleId, "rule");
    const stable = (result.partialFingerprints && Object.values(result.partialFingerprints).find((value) => typeof value === "string")) || `${line}`;
    const klass = cwe.map((id) => CWE_TO_CLASS.get(Number(id.slice(4)))).find(Boolean) || null;
    signals.push({
      id: `sarif-${tool}:${ruleName}:${sha256(`${file}\0${ruleName}\0${stable}`).slice(0, 16)}`,
      source: `sarif:${tool}`,
      rule_id: ruleName,
      title: String((rule && rule.shortDescription && rule.shortDescription.text) || (result.message && result.message.text) || ruleName).split("\n")[0].slice(0, 200),
      file,
      line,
      class: klass,
      cwe,
      severity_hint: severityHint(rule, result),
      in_test: isTestPath(file),
    });
  }
  return { tool: `sarif:${tool}`, signals };
}

function run(argv) {
  let options;
  try {
    options = parseArgs(argv, { repeatable: ["sarif"] });
    if (options.sarif.length === 0 || !options.out) throw new Error("--sarif and --out are required");
    if (options["source-root"] && !path.isAbsolute(options["source-root"])) throw new Error("--source-root must be absolute");
  } catch (error) {
    console.error(`import-sarif: ${escapeDiagnostic(error.message)}`);
    console.error("Usage: node import-sarif.cjs --sarif <file> [--sarif <file>]... --out <signals.json> [--into <signals.json>] [--source-root <abs>]");
    return 2;
  }

  let existing = null;
  if (options.into) {
    try {
      existing = readBoundedJson(options.into, 64 * 1024 * 1024);
    } catch (error) {
      console.error(`import-sarif: cannot read --into: ${escapeDiagnostic(error.message)}`);
      return 1;
    }
    const errors = validateSignalsDocument(existing);
    if (errors.length > 0) {
      errors.slice(0, 20).forEach((message) => console.error(`ERROR: ${escapeDiagnostic(message)}`));
      return 1;
    }
  }

  const counters = { results: 0, suppressed: 0, unlocated: 0, truncated: false };
  const imported = [];
  const tools = existing ? [...(existing.tools || [])] : [];
  for (const file of options.sarif) {
    let sarif;
    try {
      sarif = readBoundedJson(file, MAX_SARIF_BYTES);
    } catch (error) {
      console.error(`import-sarif: cannot read SARIF: ${escapeDiagnostic(error.message)}`);
      return 1;
    }
    if (!sarif || !Array.isArray(sarif.runs)) {
      console.error("import-sarif: input is not a SARIF log (missing runs array)");
      return 1;
    }
    for (const sarifRun of sarif.runs) {
      const { tool, signals } = importRun(sarifRun || {}, options["source-root"] || null, counters);
      tools.push(tool);
      imported.push(...signals);
    }
  }

  const document = buildDocument({
    signals: [...(existing ? existing.signals : []), ...imported],
    scope: existing ? existing.scope : { mode: "full" },
    sourceRef: existing ? existing.source_ref : null,
    scanned: { ...(existing && existing.scanned ? existing.scanned : {}), sarif_import: counters },
    tools,
  });
  writeAtomic(options.out, `${JSON.stringify(document, null, 2)}\n`);
  console.log(`PASS: imported ${imported.length} signals (${counters.suppressed} suppressed, ${counters.unlocated} without a safe repository location)${counters.truncated ? "; truncated" : ""}`);
  return 0;
}

module.exports = { extractCwes, importRun, relativeUri };

if (require.main === module) process.exit(run(process.argv.slice(2)));
