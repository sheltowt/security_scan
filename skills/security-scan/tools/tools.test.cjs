"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const test = require("node:test");

const { loadSignatures, scan } = require("./prefilter.cjs");
const { diffScope, listFiles } = require("./lib/git.cjs");
const { extractCwes, importRun, relativeUri } = require("./import-sarif.cjs");
const { convert } = require("./to-sarif.cjs");
const { parseLedger, summarize, toMarkdown } = require("./cost-summary.cjs");
const { validateChains } = require("../validate-chains.cjs");
const { validateDocument } = require("../validate-findings.cjs");
const reportSchema = require("../report-schema.json");
const chainSchema = require("../chain-schema.json");

const SKILL_DIR = path.join(__dirname, "..");
const SIGNATURES = path.join(__dirname, "signatures.json");
const SANDBOX = path.join(__dirname, "sandbox-run.sh");

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `security-scan-${prefix}-`));
}

function sh(cwd, ...args) {
  return execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] }).toString();
}

function write(root, file, contents) {
  fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  fs.writeFileSync(path.join(root, file), contents);
}

function fixtureRepo() {
  const root = tempDir("repo");
  sh(root, "init", "-q", "-b", "main");
  write(root, "src/db.js", [
    "const express = require('express');",
    "function find(req, db) {",
    "  return db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    "}",
    "",
  ].join("\n"));
  write(root, "src/load.py", "import pickle\n\ndef load(blob):\n    return pickle.loads(blob)\n");
  write(root, "config/settings.py", "AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n");
  write(root, "test/db.test.js", "child_process.exec('ls')\n");
  write(root, "node_modules/pkg/index.js", "eval(x)\n");
  write(root, "assets/blob.bin", Buffer.from([0x65, 0x76, 0x61, 0x6c, 0x28, 0x00, 0x29]));
  write(root, ".github/workflows/ci.yml", "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n      - uses: someone/action@v1\n");
  sh(root, "add", "-A", "-f", "src", "config", "test", "assets", ".github");
  sh(root, "commit", "-q", "-m", "base");
  return root;
}

function scanRepo(root, extra = {}) {
  return scan({ target: root, signatures: SIGNATURES, exclude: [], maxFileBytes: 1024 * 1024, maxSignals: 20000, diffScope: null, ...extra });
}

// ---------------------------------------------------------------- signatures

test("every signature compiles, has a unique id, and references a real attack-class block", () => {
  const rules = loadSignatures(SIGNATURES);
  assert(rules.length >= 60, "expected a substantial signature pack");
  const raw = JSON.parse(fs.readFileSync(SIGNATURES, "utf8"));
  for (const rule of raw.rules) {
    assert.match(rule.severity_hint, /^(?:high|medium|low)$/, rule.id);
    for (const cwe of rule.cwe) assert.match(cwe, /^CWE-[1-9][0-9]*$/, rule.id);
    const [file, block] = rule.class.split("#");
    const text = fs.readFileSync(path.join(SKILL_DIR, file), "utf8");
    const headings = new Set([
      ...[...text.matchAll(/^\*\*(.+?)\*\*/gm)].map((match) => match[1]),
      ...[...text.matchAll(/^#{2,4} (.+?)(?: \(.*\))?$/gm)].map((match) => match[1]),
    ]);
    assert(headings.has(block), `${rule.id}: ${rule.class} does not name a block in ${file}`);
  }
});

test("signature regexes stay fast on adversarial lines at the scan length cap", () => {
  const rules = loadSignatures(SIGNATURES);
  const hostile = [
    "a".repeat(4096),
    " ".repeat(4096),
    "(".repeat(2048) + ")".repeat(2048),
    "password = \"" + "x".repeat(4000),
    "${{ github.event." + "a.".repeat(2000),
    "query(`" + "${".repeat(2000),
  ];
  for (const rule of rules) {
    const started = process.hrtime.bigint();
    for (const line of hostile) rule.regex.test(line);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert(elapsedMs < 250, `${rule.id} took ${elapsedMs.toFixed(1)}ms on hostile input`);
  }
});

// ----------------------------------------------------------------- prefilter

test("prefilter finds seeded sinks, skips vendored, binary, and ignored files, and copies no source text", () => {
  const root = fixtureRepo();
  try {
    const document = scanRepo(root);
    const rules = new Set(document.signals.map((signal) => `${signal.rule_id}@${signal.file}`));
    for (const expected of ["js.sql-concat@src/db.js", "py.unsafe-deserialize@src/load.py", "secret.aws-access-key@config/settings.py", "gha.pull-request-target@.github/workflows/ci.yml", "gha.expression-injection@.github/workflows/ci.yml", "gha.unpinned-action@.github/workflows/ci.yml"]) {
      assert(rules.has(expected), `missing ${expected}`);
    }
    assert(!document.signals.some((signal) => signal.file.startsWith("node_modules/")));
    assert(!document.signals.some((signal) => signal.file === "assets/blob.bin"));
    assert.equal(document.scanned.listing, "git");
    const serialized = JSON.stringify(document);
    assert(!serialized.includes("AKIAABCDEFGHIJKLMNOP"), "secret value leaked into signals.json");
    assert(!serialized.includes("SELECT * FROM"), "source text leaked into signals.json");
    const testSignal = document.signals.find((signal) => signal.file === "test/db.test.js");
    assert(testSignal && testSignal.in_test === true);
    assert.equal(document.hotspots.files[0].path === "test/db.test.js", false, "test files must not top the hotspot ranking");
    assert(document.signals.every((signal) => /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(signal.id)));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("signal IDs survive unrelated line shifts", () => {
  const root = fixtureRepo();
  try {
    const before = scanRepo(root).signals.find((signal) => signal.rule_id === "js.sql-concat");
    const file = path.join(root, "src/db.js");
    fs.writeFileSync(file, `// header\n// another\n${fs.readFileSync(file, "utf8")}`);
    const after = scanRepo(root).signals.find((signal) => signal.rule_id === "js.sql-concat");
    assert.equal(after.id, before.id);
    assert.equal(after.line, before.line + 2);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("prefilter never follows a symlink out of the target", () => {
  const root = fixtureRepo();
  const outside = tempDir("outside");
  try {
    write(outside, "secret.py", "pickle.loads(x)\n");
    fs.symlinkSync(path.join(outside, "secret.py"), path.join(root, "src/link.py"));
    fs.symlinkSync(outside, path.join(root, "linked-dir"));
    const document = scanRepo(root);
    assert(!document.signals.some((signal) => signal.file === "src/link.py" || signal.file.startsWith("linked-dir/")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("prefilter walks a non-git directory and still applies default exclusions", () => {
  const root = tempDir("plain");
  try {
    write(root, "app.py", "os.system(cmd)\n");
    write(root, "venv/lib/x.py", "os.system(cmd)\n");
    const document = scanRepo(root);
    assert.equal(document.scanned.listing, "walk");
    assert.deepEqual(document.signals.map((signal) => signal.file), ["app.py"]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- git safety

test("git helpers do not execute a target-configured fsmonitor", () => {
  const root = fixtureRepo();
  const marker = path.join(root, "..", `${path.basename(root)}-pwned`);
  try {
    const hook = path.join(root, "fsmonitor.sh");
    fs.writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
    sh(root, "config", "core.fsmonitor", hook);
    listFiles(root);
    diffScope(root, "HEAD");
    assert.equal(fs.existsSync(marker), false, "fsmonitor hook ran");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(marker, { force: true });
  }
});

test("diff scope maps changed lines and prefilter flags in-diff signals", () => {
  const root = fixtureRepo();
  try {
    write(root, "src/db.js", `${fs.readFileSync(path.join(root, "src/db.js"), "utf8")}function run(req) { return require('child_process').exec(req.query.cmd); }\n`);
    write(root, "src/new.py", "subprocess.run(cmd, shell=True)\n");
    sh(root, "add", "-A", "src");
    sh(root, "commit", "-q", "-m", "change");
    const scope = diffScope(root, "HEAD~1", "HEAD");
    const db = scope.files.find((file) => file.path === "src/db.js");
    assert.deepEqual(db.ranges, [[5, 5]]);
    assert.equal(scope.files.find((file) => file.path === "src/new.py").status, "A");
    assert.throws(() => diffScope(root, "--output=/tmp/x"), /unsafe git ref/);

    const scopeFile = path.join(root, "..", `${path.basename(root)}-scope.json`);
    fs.writeFileSync(scopeFile, JSON.stringify({ version: 1, mode: "diff", ...scope }));
    try {
      const document = scanRepo(root, { diffScope: scopeFile });
      assert.equal(document.scope.mode, "diff");
      assert(document.signals.every((signal) => signal.file === "src/db.js" || signal.file === "src/new.py"));
      assert.equal(document.signals.find((signal) => signal.rule_id === "js.sql-concat").in_diff, false);
      assert.equal(document.signals.find((signal) => signal.rule_id === "js.child-process").in_diff, true);
    } finally {
      fs.rmSync(scopeFile, { force: true });
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// -------------------------------------------------------------- SARIF import

function sampleSarif() {
  return {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Semgrep OSS", rules: [{ id: "python.lang.security.audit.dangerous-subprocess-use", shortDescription: { text: "Dangerous subprocess use" }, properties: { tags: ["CWE-78: OS Command Injection", "security"] } }] } },
      results: [
        { ruleId: "python.lang.security.audit.dangerous-subprocess-use", level: "error", message: { text: "subprocess with shell" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.py" }, region: { startLine: 12 } } }] },
        { ruleId: "python.lang.security.audit.dangerous-subprocess-use", message: { text: "abs" }, locations: [{ physicalLocation: { artifactLocation: { uri: "file:///work/repo/src/other.py" }, region: { startLine: 3 } } }] },
        { ruleId: "python.lang.security.audit.dangerous-subprocess-use", message: { text: "escape" }, locations: [{ physicalLocation: { artifactLocation: { uri: "../../etc/passwd" }, region: { startLine: 1 } } }] },
        { ruleId: "python.lang.security.audit.dangerous-subprocess-use", message: { text: "suppressed" }, suppressions: [{ kind: "inSource" }], locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.py" }, region: { startLine: 20 } } }] },
      ],
    }, {
      tool: { driver: { name: "CodeQL", rules: [{ id: "js/sql-injection", properties: { tags: ["security", "external/cwe/cwe-089"], "security-severity": "8.8" } }] } },
      results: [{ ruleId: "js/sql-injection", rule: { index: 0 }, message: { text: "sqli" }, partialFingerprints: { primaryLocationLineHash: "abc:1" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/db.js", uriBaseId: "%SRCROOT%" }, region: { startLine: 3 } } }] }],
    }],
  };
}

test("SARIF import extracts CWEs, maps classes, confines paths, and skips suppressions", () => {
  assert.deepEqual(extractCwes(["CWE-78: OS Command Injection", "external/cwe/cwe-089", "nope"]), ["CWE-78", "CWE-89"]);
  assert.equal(relativeUri("file:///work/repo/src/a.py", null, "/work/repo"), "src/a.py");
  assert.equal(relativeUri("/elsewhere/a.py", null, "/work/repo"), null);
  assert.equal(relativeUri("../x", null, null), null);

  const counters = { results: 0, suppressed: 0, unlocated: 0, truncated: false };
  const [semgrep, codeql] = sampleSarif().runs.map((run) => importRun(run, "/work/repo", counters));
  assert.equal(semgrep.tool, "sarif:semgrep-oss");
  assert.deepEqual(semgrep.signals.map((signal) => signal.file), ["src/app.py", "src/other.py"]);
  assert.equal(semgrep.signals[0].class, "ATTACK-CLASSES.md#Injection");
  assert.equal(semgrep.signals[0].severity_hint, "high");
  assert.equal(counters.suppressed, 1);
  assert.equal(counters.unlocated, 1);
  assert.equal(codeql.signals[0].severity_hint, "high");
  assert.deepEqual(codeql.signals[0].cwe, ["CWE-89"]);
});

test("import-sarif CLI merges into an existing signals.json and corroboration raises hotspot score", () => {
  const root = fixtureRepo();
  const work = tempDir("sarif");
  try {
    const signalsPath = path.join(work, "signals.json");
    fs.writeFileSync(signalsPath, JSON.stringify(scanRepo(root)));
    const before = JSON.parse(fs.readFileSync(signalsPath, "utf8")).hotspots.files.find((entry) => entry.path === "src/db.js").score;
    const sarifPath = path.join(work, "codeql.sarif");
    fs.writeFileSync(sarifPath, JSON.stringify({ version: "2.1.0", runs: [sampleSarif().runs[1]] }));
    const result = spawnSync(process.execPath, [path.join(__dirname, "import-sarif.cjs"), "--sarif", sarifPath, "--into", signalsPath, "--out", signalsPath], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const merged = JSON.parse(fs.readFileSync(signalsPath, "utf8"));
    assert(merged.tools.includes("prefilter") && merged.tools.includes("sarif:codeql"));
    const after = merged.hotspots.files.find((entry) => entry.path === "src/db.js").score;
    assert(after > before, "corroborated file should rank higher");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(work, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------ findings fixtures

function confirmedFinding() {
  return {
    verdict: "confirmed",
    fingerprint: "src-db-find-sqli",
    title: "SQL injection in user lookup",
    description: "The id route parameter is interpolated into SQL.",
    root_cause: "find interpolates req.params.id into a query string.",
    intended_behavior: "The id is bound as a parameter.",
    trace: [
      { kind: "entrypoint", file: "src/routes.js", line: 4, scope: "GET /users/:id", description: "Route parameter enters." },
      { kind: "sink", file: "src/db.js", line: 3, scope: "find", description: "Interpolated into SQL." },
    ],
    evidence: [{ file: "src/db.js", line: 3, description: "Template literal query." }],
    conditions: [],
    execution: { attacker_perspective: "Unauthenticated client.", payloads: ["1 OR 1=1"], instructions: ["Call find with the payload in a sqlite fixture."], observed_result: "All fixture rows are returned." },
    remediation: { strategy: "Use a bound parameter." },
    severity: { likelihood: { score: "high", reason: "Public route." }, impact: { score: "high", reason: "Reads all users." }, overall_severity: "high" },
    confidence: { score: "high", reason: "Reproduced locally." },
    evidence_level: "local_check",
    cwe: ["CWE-89"],
  };
}

function needsValidationFinding() {
  return {
    verdict: "needs_validation",
    fingerprint: "src-load-pickle",
    title: "Pickle deserialization of uploaded blob",
    description: "Uploaded blobs may reach pickle.loads.",
    claimed_root_cause: "load passes request bytes to pickle.loads.",
    trace: [{ kind: "sink", file: "src/load.py", line: 4, scope: "load", description: "pickle.loads." }],
    evidence: [{ file: "src/load.py", line: 4, description: "Unsafe loader." }],
    blockers: ["The upload route that calls load is generated at deploy time."],
    validation_plan: { deployment: "Owner confirms whether the upload route calls load." },
  };
}

function rejectedFinding() {
  return {
    verdict: "rejected",
    fingerprint: "src-x-rejected",
    title: "Rejected",
    description: "Rejected claim.",
    claimed_root_cause: "Claimed.",
    trace: [{ kind: "sink", file: "src/x.js", line: 1, scope: "x", description: "x." }],
    evidence: [{ file: "src/x.js", line: 1, description: "x." }],
    reason: "Guarded by middleware.",
  };
}

test("fixture findings are valid under the extended schema", () => {
  assert.deepEqual(validateDocument([confirmedFinding(), needsValidationFinding(), rejectedFinding()], reportSchema), []);
});

// ------------------------------------------------------------------ to-sarif

test("to-sarif exports confirmed and needs_validation records and never rejected ones", () => {
  const sarif = convert([confirmedFinding(), needsValidationFinding(), rejectedFinding()]);
  assert.equal(sarif.version, "2.1.0");
  const [run] = sarif.runs;
  assert.deepEqual(run.results.map((result) => result.ruleId), ["src-db-find-sqli", "src-load-pickle"]);
  const [confirmed, lead] = run.results;
  assert.equal(confirmed.level, "error");
  assert.equal(confirmed.properties["security-severity"], "8.0");
  assert.equal(confirmed.locations[0].physicalLocation.artifactLocation.uri, "src/db.js");
  assert.equal(confirmed.codeFlows[0].threadFlows[0].locations.length, 2);
  assert(run.tool.driver.rules[0].properties.tags.includes("external/cwe/cwe-89"));
  assert.equal(lead.level, "note");
  assert.equal(lead.kind, "review");
  assert.equal(convert([confirmedFinding(), needsValidationFinding()], { includeNeedsValidation: false }).runs[0].results.length, 1);
  assert.equal(run.results.every((result, index) => result.ruleIndex === undefined || run.tool.driver.rules[result.ruleIndex].id === result.ruleId), true);
});

// -------------------------------------------------------------------- chains

function secondConfirmed() {
  const finding = confirmedFinding();
  finding.fingerprint = "src-admin-session-forge";
  finding.title = "Session forge";
  return finding;
}

function chain(overrides = {}) {
  return {
    verdict: "confirmed",
    chain_id: "chain-sqli-to-admin",
    title: "SQL injection yields admin session",
    description: "Read the session secret through SQLi, then forge an admin session.",
    starting_principal: "Unauthenticated client.",
    links: [
      { fingerprint: "src-db-find-sqli", requires: "Network access to the public route.", provides: "Read access to the settings table, including the session signing key." },
      { fingerprint: "src-admin-session-forge", requires: "The session signing key.", provides: "An admin session." },
    ],
    combined_result: "An unauthenticated client obtains an admin session in the fixture.",
    execution: { instructions: ["Run both steps against the sqlite fixture."], observed_result: "The forged cookie is accepted by the admin handler." },
    severity: { likelihood: { score: "high", reason: "Public." }, impact: { score: "critical", reason: "Admin takeover." }, overall_severity: "critical" },
    ...overrides,
  };
}

test("validate-chains accepts a composed confirmed chain and enforces link verdicts", () => {
  const findings = [secondConfirmed(), confirmedFinding(), needsValidationFinding(), rejectedFinding()].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));
  assert.deepEqual(validateChains([chain()], findings, chainSchema), []);

  const withLead = chain({ links: [chain().links[0], { fingerprint: "src-load-pickle", requires: "x", provides: "y" }] });
  assert(validateChains([withLead], findings, chainSchema).some((error) => error.includes("every link to be a confirmed")));

  const withRejected = chain({ links: [chain().links[0], { fingerprint: "src-x-rejected", requires: "x", provides: "y" }] });
  assert(validateChains([withRejected], findings, chainSchema).some((error) => error.includes("rejected record")));

  const unknown = chain({ links: [chain().links[0], { fingerprint: "nope", requires: "x", provides: "y" }] });
  assert(validateChains([unknown], findings, chainSchema).some((error) => error.includes("no findings.json record")));

  const inflated = chain({ severity: { ...chain().severity, impact: { score: "high", reason: "x" } } });
  assert(validateChains([inflated], findings, chainSchema).some((error) => error.includes("cannot exceed")));

  assert.notEqual(validateChains([chain({ links: [chain().links[0]] })], findings, chainSchema).length, 0, "a chain needs two links");

  const lead = {
    verdict: "needs_validation",
    chain_id: "chain-pickle-rce",
    title: "Upload to code execution",
    description: "If the upload route calls load, pickle gives code execution.",
    starting_principal: "Authenticated uploader.",
    links: [{ fingerprint: "src-db-find-sqli", requires: "a", provides: "b" }, { fingerprint: "src-load-pickle", requires: "b", provides: "c" }],
    claimed_result: "Code execution in the worker.",
    blockers: ["Route wiring is deploy-time."],
    validation_plan: "Owner confirms the route mapping.",
  };
  assert.deepEqual(validateChains([lead, chain()].sort((a, b) => (a.chain_id < b.chain_id ? -1 : 1)), findings, chainSchema), []);
  assert.notEqual(validateChains([{ ...lead, severity: chain().severity }], findings, chainSchema).length, 0);
});

// -------------------------------------------------------------- cost summary

test("cost summary totals invocations, tokens, budget, and optional prices", () => {
  const ledger = [
    { agent_id: "recon-1a", phase: "1", role: "recon", model: "m-small", model_tier: "triage", input_tokens: 1000, output_tokens: 100 },
    { agent_id: "h-auth-1", phase: "2", role: "hunter", model: "m-big", model_tier: "frontier", input_tokens: 50000, output_tokens: 4000 },
    { agent_id: "v-1", phase: "3", role: "verifier", model: "m-big", model_tier: "frontier", input_tokens: null, output_tokens: null },
  ].map((entry) => JSON.stringify(entry)).join("\n");
  const parsed = parseLedger(ledger);
  assert.deepEqual(parsed.errors, []);
  const summary = summarize(parsed.entries, { budget: 10, prices: { "m-big": { input_per_mtok: 10, output_per_mtok: 50 } } });
  assert.equal(summary.total.invocations, 3);
  assert.equal(summary.total.input_tokens, 51000);
  assert.equal(summary.total.unreported, 1);
  assert.equal(summary.budget_remaining, 7);
  assert.equal(summary.total.unpriced, 1);
  assert.equal(summary.by_model_tier.frontier.invocations, 2);
  assert.ok(Math.abs(summary.total.usd - 0.7) < 1e-9);
  assert.match(toMarkdown(summary), /lower bound/);
  assert.notEqual(parseLedger("{\"agent_id\":\"BAD ID\",\"phase\":\"9\",\"role\":\"x\"}").errors.length, 0);
});

// ------------------------------------------------------------------- sandbox

function sandbox(args) {
  return spawnSync("bash", [SANDBOX, ...args], { encoding: "utf8" });
}

test("sandbox-run --check reports backends as JSON", () => {
  const result = sandbox(["--check"]);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert(["docker", "podman", "bwrap"].every((name) => name in report.backends));
  assert.match(report.backends.docker.disk_total, /size-limited/);
});

test("sandbox-run builds a locked-down container command and refuses unsafe layouts", () => {
  const target = tempDir("sb-target");
  const scratch = tempDir("sb-scratch");
  try {
    const result = sandbox(["--backend", "docker", "--image", "local/test:1", "--target", target, "--scratch", scratch, "--env", "CI=1", "--dry-run", "--", "npm", "test"]);
    assert.equal(result.status, 0, result.stderr);
    const args = result.stdout.trim().split("\n");
    for (const expected of ["--network", "none", "--read-only", "--pull", "never", "ALL", "no-new-privileges", "--pids-limit"]) {
      assert(args.includes(expected), `missing ${expected}`);
    }
    const realTarget = fs.realpathSync(target);
    assert(args.some((arg) => arg.replace(/\\/g, "") === `${realTarget}:/src:ro`), "target must be mounted read-only");
    assert.deepEqual(args.slice(-3), ["local/test:1", "npm", "test"]);
    assert(!args.some((arg) => arg.includes(os.homedir()) && !arg.startsWith(fs.realpathSync(os.tmpdir()))), "home directory must not be mounted");

    const inside = path.join(target, "scratch");
    fs.mkdirSync(inside);
    assert.equal(sandbox(["--backend", "docker", "--image", "x", "--target", target, "--scratch", inside, "--dry-run", "--", "true"]).status, 2);
    assert.equal(sandbox(["--backend", "docker", "--image", "x", "--target", target, "--scratch", scratch, "--env", "HOME=/root", "--dry-run", "--", "true"]).status, 2);
    assert.equal(sandbox(["--backend", "docker", "--image", "x", "--target", target, "--scratch", scratch, "--env", "LD_PRELOAD=/x.so", "--dry-run", "--", "true"]).status, 2);
    assert.equal(sandbox(["--backend", "docker", "--target", target, "--scratch", scratch, "--dry-run", "--", "true"]).status, 2, "image is required");
    assert.equal(sandbox(["--backend", "docker", "--image", "x", "--target", target, "--scratch", scratch, "--ro", os.homedir(), "--dry-run", "--", "true"]).status, 2, "home must not be mounted via --ro");
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------- promote

const PROMOTE = path.join(__dirname, "promote.py");
const HAS_PYTHON = spawnSync("python3", ["-I", "-c", "import os; assert os.open in os.supports_dir_fd"]).status === 0;

function promote(scratch, artifacts, allow, { maxFile = 1024, maxTotal = 4096 } = {}) {
  const args = ["-I", PROMOTE, "--scratch", scratch, "--artifacts", artifacts, "--max-file-bytes", String(maxFile), "--max-total-bytes", String(maxTotal)];
  for (const entry of allow) args.push("--allow", entry);
  const result = spawnSync("python3", args, { encoding: "utf8", timeout: 10000 });
  const lines = result.stdout.trim() ? result.stdout.trim().split("\n").map((line) => JSON.parse(line)) : [];
  return { status: result.status, lines, byPath: Object.fromEntries(lines.map((line) => [line.path, line])), stderr: result.stderr };
}

test("promote.py copies declared regular files and refuses every unsafe shape", { skip: !HAS_PYTHON || process.platform === "win32" }, () => {
  const root = tempDir("promote");
  const outside = tempDir("promote-outside");
  try {
    const scratch = path.join(root, "scratch");
    const artifacts = path.join(root, "artifacts");
    fs.mkdirSync(scratch);
    fs.mkdirSync(artifacts);
    write(scratch, "results/asan.txt", "ERROR: AddressSanitizer: heap-buffer-overflow\n");
    write(scratch, "big.txt", "x".repeat(2000));
    write(outside, "secret.txt", "host secret\n");
    fs.symlinkSync(path.join(outside, "secret.txt"), path.join(scratch, "leaf-link.txt"));
    fs.symlinkSync(outside, path.join(scratch, "dir-link"));
    write(scratch, "hard-a.txt", "same inode\n");
    fs.linkSync(path.join(scratch, "hard-a.txt"), path.join(scratch, "hard-b.txt"));
    execFileSync("mkfifo", [path.join(scratch, "pipe")]);
    fs.mkdirSync(path.join(scratch, "a-dir"));
    write(scratch, "exists.txt", "new\n");
    write(artifacts, "exists.txt", "old\n");
    write(scratch, "planted/x.txt", "x\n");
    fs.symlinkSync(outside, path.join(artifacts, "planted"));

    const result = promote(scratch, artifacts, [
      "results/asan.txt", "big.txt", "leaf-link.txt", "dir-link/secret.txt", "hard-a.txt", "pipe", "a-dir",
      "exists.txt", "planted/x.txt", "../escape.txt", "/etc/passwd", "results/asan.txt",
    ]);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.lines[0].path, "results/asan.txt");
    assert.equal(result.lines[0].status, "promoted");
    assert.match(result.lines[0].sha256, /^[0-9a-f]{64}$/);
    assert.equal(fs.readFileSync(path.join(artifacts, "results/asan.txt"), "utf8"), "ERROR: AddressSanitizer: heap-buffer-overflow\n");
    const refused = result.lines.filter((line) => line.status === "refused").map((line) => line.path);
    assert.deepEqual(refused.sort(), ["../escape.txt", "/etc/passwd", "a-dir", "big.txt", "dir-link/secret.txt", "exists.txt", "hard-a.txt", "leaf-link.txt", "pipe", "planted/x.txt", "results/asan.txt"].sort());
    assert.match(result.lines[result.lines.length - 1].reason, /duplicate/);
    assert.equal(fs.readFileSync(path.join(artifacts, "exists.txt"), "utf8"), "old\n", "existing artifact must not be overwritten");
    assert.equal(fs.existsSync(path.join(outside, "x.txt")), false, "must not write through a planted destination symlink");
    assert.equal(fs.existsSync(path.join(artifacts, "leaf-link.txt")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("promote.py enforces the cumulative byte limit", { skip: !HAS_PYTHON }, () => {
  const root = tempDir("promote-total");
  try {
    const scratch = path.join(root, "scratch");
    const artifacts = path.join(root, "artifacts");
    fs.mkdirSync(artifacts, { recursive: true });
    write(scratch, "a.txt", "a".repeat(600));
    write(scratch, "b.txt", "b".repeat(600));
    const result = promote(scratch, artifacts, ["a.txt", "b.txt"], { maxFile: 1000, maxTotal: 1000 });
    assert.equal(result.byPath["a.txt"].status, "promoted");
    assert.equal(result.byPath["b.txt"].status, "refused");
    assert.match(result.byPath["b.txt"].reason, /cumulative/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
