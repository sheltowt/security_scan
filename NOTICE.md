# Notice

This project is a derivative of **cloudflare/security-audit-skill**
(<https://github.com/cloudflare/security-audit-skill>), imported at upstream commit
`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`. Copyright (c) 2025-2026 Cloudflare, Inc.
It is used under the MIT License, whose full text is in
[`LICENSES/cloudflare-security-audit-skill.txt`](LICENSES/cloudflare-security-audit-skill.txt).

Files carried over from upstream, some with modifications:

| File (under `skills/security-scan/`) | Status |
|---|---|
| `AI-AND-LLM.md`, `CLIENT-SIDE.md`, `CLOUD-AND-DEPLOYMENT.md`, `DATA-ISOLATION-AND-LIFECYCLE.md`, `DESKTOP-MOBILE-AND-LOCAL-IPC.md`, `MEMORY-SAFETY-AND-BINARY.md`, `PROTOCOLS-RPC-AND-MESSAGING.md`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, `SUPPLY-CHAIN-AND-RELEASE.md`, `WEB-PROTOCOL-AND-AUTH.md`, `validate-coverage-ledger.cjs` | unchanged |
| `SKILL.md`, `RECONNAISSANCE.md`, `HUNTING.md`, `VALIDATION-AND-REPORTING.md`, `ATTACK-CLASSES.md`, `report-schema.json`, `validate-findings.cjs`, `validate-findings.test.cjs`, `validate-coverage-ledger.test.cjs` | modified |

Everything else is new to this project and is covered by the root [`LICENSE`](LICENSE).

The new features draw on ideas published by these open-source projects. No code was copied from them:

- vercel-labs/deepsec: regex prefilter before agent review, PR-diff mode, per-batch cost reporting, resumable runs
- trailofbits/skills: SAST (Semgrep/CodeQL) integration, SARIF output, cryptography and smart-contract specialist coverage
- gadievron/raptor: SAST plus LLM orchestration, execution-validated findings, multi-model consensus
- cisco-open/ai-deep-sast: Semgrep candidates triaged by an LLM behind an evidence gate, fast/deep model tiers
- visa/visa-vulnerability-agentic-harness: threat-modeling stage, exploit-chain synthesis, fix proposal with validation, SARIF
- capitalone/vulnhunter: find, fix, verify remediation loop
- anthropics/defending-code-reference-harness: sanitizer-verified reproduction, execution-verified patches, sandboxed execution
- anthropics/claude-code-security-review: diff-aware PR review in CI
