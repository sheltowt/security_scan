#!/usr/bin/env node
"use strict";

/**
 * Convert a validated findings.json into SARIF 2.1.0.
 *
 * Usage:
 *   node to-sarif.cjs --findings <findings.json> --out <results.sarif>
 *     [--chains <chains.json>] [--no-needs-validation] [--version <tool version>]
 *
 * `confirmed` records become results with GitHub `security-severity`.
 * `needs_validation` records become `note` results with kind "review" so a
 * code-scanning UI shows them as leads, never as confirmed alerts.
 * `rejected` records are never exported.
 *
 * Run validate-findings.cjs first; this converter assumes a valid document.
 */

const path = require("path");
const { escapeDiagnostic, parseArgs, readBoundedJson, writeAtomic } = require("./lib/common.cjs");

const TOOL_NAME = "security-scan";
const INFORMATION_URI = "https://github.com/sheltowt/security_scan";
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", informational: "0.5" };
const LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", informational: "note" };

function region(entry) {
  return { startLine: entry.line };
}

function location(entry, message) {
  const value = {
    physicalLocation: {
      artifactLocation: { uri: entry.file, uriBaseId: "%SRCROOT%" },
      region: region(entry),
    },
  };
  if (message) value.message = { text: message };
  return value;
}

function codeFlow(trace) {
  return [{
    threadFlows: [{
      locations: trace.map((step) => ({
        location: location(step, `${step.kind}: ${step.scope} — ${step.description}`),
      })),
    }],
  }];
}

function tagsFor(record) {
  const tags = ["security", `verdict:${record.verdict}`];
  for (const cwe of record.cwe || []) tags.push(`external/cwe/${cwe.toLowerCase()}`);
  return tags;
}

function markdownFor(record) {
  const lines = [`**${record.title}**`, "", record.description, ""];
  if (record.verdict === "confirmed") {
    lines.push(`**Root cause:** ${record.root_cause}`, "", `**Intended behavior:** ${record.intended_behavior}`, "");
    lines.push(`**Observed (local, sandboxed):** ${record.execution.observed_result}`, "");
    lines.push(`**Evidence level:** ${record.evidence_level}`, "");
    lines.push(`**Fix:** ${record.remediation.strategy}`);
    if (record.fix_verification && record.fix_verification.status === "verified") {
      lines.push("", `**Fix verified:** ${record.fix_verification.poc_after} Patch: \`${record.fix_verification.patch}\`.`);
    }
  } else {
    lines.push(`**Claimed root cause:** ${record.claimed_root_cause}`, "", "**Blocked on:**");
    record.blockers.forEach((blocker) => lines.push(`- ${blocker}`));
    if (record.validation_plan.local) lines.push("", `**Local validation:** ${record.validation_plan.local}`);
    if (record.validation_plan.deployment) lines.push("", `**Owner-observed check:** ${record.validation_plan.deployment}`);
  }
  return lines.join("\n");
}

function ruleFor(record) {
  const rule = {
    id: record.fingerprint,
    name: record.fingerprint.replace(/[^A-Za-z0-9]+/g, "_"),
    shortDescription: { text: record.title },
    fullDescription: { text: record.description },
    help: { text: record.verdict === "confirmed" ? record.remediation.strategy : record.validation_plan.local || record.validation_plan.deployment, markdown: markdownFor(record) },
    properties: { tags: tagsFor(record) },
  };
  if (record.verdict === "confirmed") {
    rule.defaultConfiguration = { level: LEVEL[record.severity.overall_severity] };
    rule.properties["security-severity"] = SECURITY_SEVERITY[record.severity.overall_severity];
    rule.properties.precision = record.confidence.score === "high" ? "high" : record.confidence.score === "medium" ? "medium" : "low";
  } else {
    rule.defaultConfiguration = { level: "note" };
    rule.properties.precision = "low";
  }
  return rule;
}

function resultFor(record, index) {
  const sink = record.trace[record.trace.length - 1];
  const result = {
    ruleId: record.fingerprint,
    ruleIndex: index,
    level: record.verdict === "confirmed" ? LEVEL[record.severity.overall_severity] : "note",
    message: { text: record.verdict === "confirmed" ? `${record.title}: ${record.execution.observed_result}` : `Needs validation: ${record.title}. Blocked on: ${record.blockers.join("; ")}` },
    locations: [location(sink)],
    partialFingerprints: { "securityScanFingerprint/v1": record.fingerprint },
    properties: { verdict: record.verdict, tags: tagsFor(record) },
  };
  if (record.verdict === "needs_validation") result.kind = "review";
  if (record.trace.length > 1) result.codeFlows = codeFlow(record.trace);
  if (record.evidence.length > 0) {
    result.relatedLocations = record.evidence.map((entry, id) => ({ id, ...location(entry, entry.description) }));
  }
  if (record.verdict === "confirmed") {
    result.properties["security-severity"] = SECURITY_SEVERITY[record.severity.overall_severity];
    result.properties.evidence_level = record.evidence_level;
    if (record.fix_verification) result.properties.fix_verification = record.fix_verification.status;
  }
  return result;
}

function chainResults(chains, rulesByFingerprint) {
  // A chain is reported as an extra result on its final link so code-scanning
  // UIs show the combined impact next to the individual findings.
  return chains.filter((chain) => chain.verdict === "confirmed").map((chain) => {
    const last = rulesByFingerprint.get(chain.links[chain.links.length - 1].fingerprint);
    return {
      ruleId: `chain/${chain.chain_id}`,
      level: LEVEL[chain.severity.overall_severity],
      message: { text: `Chain: ${chain.title}. ${chain.combined_result}` },
      locations: last ? last.locations : [],
      partialFingerprints: { "securityScanFingerprint/v1": `chain/${chain.chain_id}` },
      properties: {
        verdict: "confirmed",
        "security-severity": SECURITY_SEVERITY[chain.severity.overall_severity],
        links: chain.links.map((link) => link.fingerprint),
        tags: ["security", "chain"],
      },
    };
  });
}

function convert(findings, { includeNeedsValidation = true, chains = [], version = "0.1.0" } = {}) {
  const exported = findings.filter((record) => record.verdict === "confirmed" || (includeNeedsValidation && record.verdict === "needs_validation"));
  const rules = exported.map(ruleFor);
  const results = exported.map(resultFor);
  const byFingerprint = new Map(exported.map((record, index) => [record.fingerprint, results[index]]));
  const chained = chainResults(chains, byFingerprint);
  for (const chain of chains.filter((entry) => entry.verdict === "confirmed")) {
    rules.push({
      id: `chain/${chain.chain_id}`,
      name: `chain_${chain.chain_id.replace(/[^A-Za-z0-9]+/g, "_")}`,
      shortDescription: { text: chain.title },
      fullDescription: { text: chain.combined_result },
      defaultConfiguration: { level: LEVEL[chain.severity.overall_severity] },
      properties: { tags: ["security", "chain"], "security-severity": SECURITY_SEVERITY[chain.severity.overall_severity] },
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: TOOL_NAME, version, informationUri: INFORMATION_URI, rules } },
      originalUriBaseIds: { "%SRCROOT%": { description: { text: "Repository root of the audited target." } } },
      results: [...results, ...chained],
      properties: { exported_verdicts: includeNeedsValidation ? ["confirmed", "needs_validation"] : ["confirmed"] },
    }],
  };
}

function run(argv) {
  let options;
  try {
    options = parseArgs(argv, { booleans: ["no-needs-validation"] });
    if (!options.findings || !options.out) throw new Error("--findings and --out are required");
  } catch (error) {
    console.error(`to-sarif: ${escapeDiagnostic(error.message)}`);
    console.error("Usage: node to-sarif.cjs --findings <findings.json> --out <results.sarif> [--chains <chains.json>] [--no-needs-validation]");
    return 2;
  }
  let findings;
  let chains = [];
  try {
    findings = readBoundedJson(options.findings, 5 * 1024 * 1024);
    if (options.chains) chains = readBoundedJson(options.chains, 5 * 1024 * 1024);
  } catch (error) {
    console.error(`to-sarif: ${escapeDiagnostic(error.message)}`);
    return 1;
  }
  if (!Array.isArray(findings) || !Array.isArray(chains)) {
    console.error("to-sarif: findings and chains must be JSON arrays; run the validators first");
    return 1;
  }
  const sarif = convert(findings, { includeNeedsValidation: !options["no-needs-validation"], chains, version: options.version || require(path.join(__dirname, "..", "package.json")).version });
  writeAtomic(options.out, `${JSON.stringify(sarif, null, 2)}\n`);
  console.log(`PASS: wrote ${sarif.runs[0].results.length} SARIF results`);
  return 0;
}

module.exports = { convert };

if (require.main === module) process.exit(run(process.argv.slice(2)));
