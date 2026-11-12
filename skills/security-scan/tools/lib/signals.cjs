"use strict";

/**
 * signals.json model shared by prefilter.cjs and import-sarif.cjs.
 *
 * A signal is a cheap, deterministic triage hint (regex prefilter or external
 * SAST result) pinned to a repository-relative file and line. Signals rank
 * coverage units and seed hunter context. They are never findings.
 */

const { compareStrings, isSafeRelativePath, sha256 } = require("./common.cjs");

const SIGNALS_VERSION = 1;
const SEVERITY_WEIGHT = { high: 5, medium: 3, low: 1 };
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|examples?|e2e|mocks?)(?:\/|$)|[._-](?:test|spec)\.[^/]+$|_test\.go$/i;
const MAX_HOTSPOTS = 50;

function isTestPath(file) {
  return TEST_PATH.test(file);
}

/**
 * Stable signal ID. It survives line shifts because it hashes the normalized
 * line text plus its occurrence index in the file, not the line number.
 */
function signalId(source, ruleId, file, normalizedText, occurrence) {
  const digest = sha256(`${file}\0${normalizedText}\0${occurrence}`).slice(0, 16);
  return `${source}:${ruleId}:${digest}`;
}

function normalizeLine(text) {
  return text.trim().replace(/\s+/g, " ");
}

function sortSignals(signals) {
  return signals.sort((a, b) =>
    compareStrings(a.file, b.file) || a.line - b.line || compareStrings(a.id, b.id));
}

/** Score files and top-level directories so the parent can rank ledger units. */
function computeHotspots(signals) {
  const files = new Map();
  for (const signal of signals) {
    const entry = files.get(signal.file) || { path: signal.file, score: 0, signal_count: 0, classes: new Set(), sources: new Set() };
    const weight = SEVERITY_WEIGHT[signal.severity_hint] || 1;
    entry.score += signal.in_test ? weight * 0.25 : weight;
    if (signal.in_diff) entry.score += weight;
    entry.signal_count += 1;
    if (signal.class) entry.classes.add(signal.class);
    entry.sources.add(signal.source);
    files.set(signal.file, entry);
  }
  // Corroboration across independent sources (regex + a SAST tool) is a stronger hint.
  for (const entry of files.values()) {
    if (entry.sources.size > 1) entry.score *= 1.5;
  }
  const finalize = (entry) => ({
    path: entry.path,
    score: Math.round(entry.score * 100) / 100,
    signal_count: entry.signal_count,
    classes: [...entry.classes].sort(compareStrings),
  });
  const ranked = [...files.values()].map(finalize)
    .sort((a, b) => b.score - a.score || compareStrings(a.path, b.path));

  const directories = new Map();
  for (const entry of ranked) {
    const top = entry.path.includes("/") ? entry.path.slice(0, entry.path.indexOf("/")) : ".";
    const dir = directories.get(top) || { path: top, score: 0, signal_count: 0, classes: new Set() };
    dir.score += entry.score;
    dir.signal_count += entry.signal_count;
    entry.classes.forEach((value) => dir.classes.add(value));
    directories.set(top, dir);
  }
  return {
    files: ranked.slice(0, MAX_HOTSPOTS),
    directories: [...directories.values()].map(finalize)
      .sort((a, b) => b.score - a.score || compareStrings(a.path, b.path)),
  };
}

function summarize(signals) {
  const bySource = {};
  const byClass = {};
  const bySeverity = {};
  for (const signal of signals) {
    bySource[signal.source] = (bySource[signal.source] || 0) + 1;
    if (signal.class) byClass[signal.class] = (byClass[signal.class] || 0) + 1;
    bySeverity[signal.severity_hint] = (bySeverity[signal.severity_hint] || 0) + 1;
  }
  const sortKeys = (object) => Object.fromEntries(Object.entries(object).sort(([a], [b]) => compareStrings(a, b)));
  return { total: signals.length, by_source: sortKeys(bySource), by_class: sortKeys(byClass), by_severity_hint: sortKeys(bySeverity) };
}

function buildDocument({ signals, scope, sourceRef, scanned, tools }) {
  const sorted = sortSignals(dedupe(signals));
  return {
    version: SIGNALS_VERSION,
    note: "Triage signals only. A signal is never a finding and never closes a coverage unit.",
    source_ref: sourceRef || null,
    scope: scope || { mode: "full" },
    tools: [...new Set(tools || [])].sort(compareStrings),
    scanned: scanned || null,
    summary: summarize(sorted),
    hotspots: computeHotspots(sorted),
    signals: sorted,
  };
}

function dedupe(signals) {
  const seen = new Map();
  for (const signal of signals) {
    if (!seen.has(signal.id)) seen.set(signal.id, signal);
  }
  return [...seen.values()];
}

/** Light structural check used when merging into an existing signals.json. */
function validateSignalsDocument(document) {
  const errors = [];
  if (!document || typeof document !== "object" || Array.isArray(document)) return ["signals document must be an object"];
  if (document.version !== SIGNALS_VERSION) errors.push(`unsupported signals version ${JSON.stringify(document.version)}`);
  if (!Array.isArray(document.signals)) return [...errors, "signals must be an array"];
  document.signals.forEach((signal, index) => {
    if (!signal || typeof signal !== "object") {
      errors.push(`signals[${index}]: must be an object`);
      return;
    }
    if (typeof signal.id !== "string" || signal.id.length === 0) errors.push(`signals[${index}].id: required`);
    if (!isSafeRelativePath(signal.file)) errors.push(`signals[${index}].file: must be a safe repository-relative path`);
    if (!Number.isInteger(signal.line) || signal.line < 1) errors.push(`signals[${index}].line: must be a positive integer`);
    if (!Object.prototype.hasOwnProperty.call(SEVERITY_WEIGHT, signal.severity_hint)) errors.push(`signals[${index}].severity_hint: must be high, medium, or low`);
  });
  return errors;
}

module.exports = {
  SIGNALS_VERSION,
  buildDocument,
  computeHotspots,
  isTestPath,
  normalizeLine,
  signalId,
  sortSignals,
  validateSignalsDocument,
};
