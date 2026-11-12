#!/usr/bin/env node
"use strict";

/**
 * Validates chains.json against chain-schema.json and against findings.json.
 * Usage: node validate-chains.cjs <chains.json> <findings.json>
 *
 * Cross-file rules:
 * - every link names an existing, non-rejected findings.json fingerprint;
 * - a confirmed chain contains only confirmed links;
 * - a needs_validation chain names its blockers and carries no severity;
 * - a link appears once per chain, a chain ID once per file, sorted by ID;
 * - overall severity never exceeds demonstrated impact.
 */

const path = require("path");
const fs = require("fs");
const { collect, collectSchemaErrors, hasVisibleProse } = require("./validate-findings.cjs");
const { SafeInputError, escapeDiagnostic, readBoundedJson } = require("./tools/lib/common.cjs");

const SEVERITY_RANK = new Map([["informational", 0], ["low", 1], ["medium", 2], ["high", 3], ["critical", 4]]);
const MAX_BYTES = 5 * 1024 * 1024;

function collectChainSemanticErrors(chains, findings) {
  const errors = [];
  if (!Array.isArray(chains) || !Array.isArray(findings)) return errors;
  const byFingerprint = new Map(findings.filter((record) => record && typeof record === "object").map((record) => [record.fingerprint, record]));
  const seen = new Set();
  let previous = null;

  chains.forEach((chain, index) => {
    if (!chain || typeof chain !== "object" || Array.isArray(chain)) return;
    const base = `$[${index}]`;
    if (seen.has(chain.chain_id)) errors.push(`${base}.chain_id: duplicate chain_id`);
    seen.add(chain.chain_id);
    if (previous !== null && typeof chain.chain_id === "string" && previous > chain.chain_id) errors.push(`${base}.chain_id: chains must be sorted lexicographically`);
    previous = chain.chain_id;
    if (byFingerprint.has(chain.chain_id)) errors.push(`${base}.chain_id: must not reuse a finding fingerprint`);

    const links = Array.isArray(chain.links) ? chain.links : [];
    const linkVerdicts = [];
    const linkSet = new Set();
    links.forEach((link, linkIndex) => {
      if (!link || typeof link !== "object") return;
      if (linkSet.has(link.fingerprint)) errors.push(`${base}.links[${linkIndex}].fingerprint: appears more than once in this chain`);
      linkSet.add(link.fingerprint);
      const record = byFingerprint.get(link.fingerprint);
      if (!record) {
        errors.push(`${base}.links[${linkIndex}].fingerprint: no findings.json record with this fingerprint`);
        return;
      }
      if (record.verdict === "rejected") errors.push(`${base}.links[${linkIndex}].fingerprint: a rejected record cannot be a chain link`);
      linkVerdicts.push(record.verdict);
    });

    if (chain.verdict === "confirmed") {
      if (linkVerdicts.some((verdict) => verdict !== "confirmed")) {
        errors.push(`${base}: a confirmed chain requires every link to be a confirmed finding`);
      }
      if (!chain.execution || !hasVisibleProse(chain.execution.observed_result)) {
        errors.push(`${base}: a confirmed chain requires an end-to-end observed_result`);
      }
      const overall = chain.severity && chain.severity.overall_severity;
      const impact = chain.severity && chain.severity.impact && chain.severity.impact.score;
      if (SEVERITY_RANK.has(overall) && SEVERITY_RANK.has(impact) && SEVERITY_RANK.get(overall) > SEVERITY_RANK.get(impact)) {
        errors.push(`${base}.severity.overall_severity: cannot exceed demonstrated impact ${JSON.stringify(impact)}`);
      }
    } else if (chain.verdict === "needs_validation") {
      if (Object.prototype.hasOwnProperty.call(chain, "severity")) errors.push(`${base}: needs_validation chain must not contain "severity"`);
    }
  });
  return errors;
}

function validateChains(chains, findings, schema) {
  const schemaErrors = collectSchemaErrors(schema);
  if (schemaErrors.length > 0) return schemaErrors;
  const errors = collect(chains, schema, "$");
  if (errors.length === 0) errors.push(...collectChainSemanticErrors(chains, findings));
  return errors;
}

function run(chainsFile, findingsFile) {
  if (!chainsFile || !findingsFile) {
    console.error("Usage: node validate-chains.cjs <chains.json> <findings.json>");
    return 1;
  }
  let schema;
  let chains;
  let findings;
  try {
    schema = JSON.parse(fs.readFileSync(path.join(__dirname, "chain-schema.json"), "utf8"));
    chains = readBoundedJson(chainsFile, MAX_BYTES);
    findings = readBoundedJson(findingsFile, MAX_BYTES);
  } catch (error) {
    const reason = error instanceof SafeInputError ? error.message : "input could not be read safely";
    console.error(`Failed to read chains or findings JSON: ${escapeDiagnostic(reason)}`);
    return 1;
  }
  const errors = validateChains(chains, findings, schema);
  for (const message of errors.slice(0, 100)) console.error("ERROR:", escapeDiagnostic(message));
  if (errors.length > 0) {
    console.error(`FAIL: ${errors.length} validation error(s)`);
    return 1;
  }
  console.log(`PASS: ${chains.length} chains valid`);
  return 0;
}

module.exports = { collectChainSemanticErrors, validateChains };

if (require.main === module) process.exit(run(process.argv[2], process.argv[3]));
