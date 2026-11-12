# Cryptography Hunting

#### When to use this file

Reach for this file when reconnaissance finds code that generates, stores, compares, or verifies secrets, keys, tokens, signatures, MACs, ciphertexts, certificates, or password hashes, or that implements or composes a cryptographic protocol. The ordinary `ATTACK-CLASSES.md#Cryptography and secrets` block covers the obvious misuse checklist; this file is for targets where cryptography is a trust boundary in its own right (token issuers, session signing, envelope encryption, license or update verification, E2E messaging, KMS wrappers, custom protocols). Use `WEB-PROTOCOL-AND-AUTH.md` for JWT/OAuth/SAML claim binding and `SUPPLY-CHAIN-AND-RELEASE.md` for release signing policy; use this file for the primitive, construction, and key-lifecycle layer underneath them.

Pick relevant classes from Phase 1 and split by key or protocol, not by file: one agent per key hierarchy or per verify path keeps the invariant in one head.

## Core discipline (include in every agent prompt for this domain)

```
- Name the asset each primitive protects (confidentiality of X, integrity of Y, authenticity of Z) and the principal who must not forge, read, or replay it. A weak primitive with no protected asset is a hardening note.
- Trace every key from generation to use to rotation to destruction. Most real defects are key handling, encoding, or verification-path logic, not broken math.
- Read the verify path harder than the sign/encrypt path. Check every branch that can return "valid": error handlers, legacy formats, algorithm switches, empty inputs, and caches.
- Prove a defect locally with dummy keys and a bounded harness: a forged token accepted, a ciphertext decrypted or malleated, a nonce repeated across two encryptions, a comparison whose timing or result is wrong. Do not attack real keys, deployed endpoints, or KMS/HSM services.
- Timing side channels need a local measurement that separates the cases with statistical confidence under the sandbox limits, or remain needs_validation. Never infer remote exploitability from a non-constant-time comparison alone.
- Classify as `confirmed` only after source evidence and bounded local validation establish the forged, disclosed, or replayed result. Use `needs_validation` when a KMS policy, HSM behavior, library build flag, or deployment key setting decides the outcome.
```

## Primitive and construction attack classes (subagent_type: `general`)

**Primitive and mode selection**
Unauthenticated encryption (CBC/CTR without a MAC, ECB anywhere), MAC-then-encrypt with distinguishable padding errors, home-grown constructions, RSA without OAEP/PSS, raw or textbook RSA, small or fixed DH groups, curves without point validation, and broken hashes in collision-sensitive positions (signatures over attacker-chosen data, content addressing, certificate pinning). Confirm what the attacker controls and the concrete forge/read result. MD5 for a non-adversarial cache key is not a finding.

**Nonce, IV, and key reuse**
Static, zero, counter-reset, or truncated IVs and nonces; random 96-bit GCM nonces under one key at volumes that approach the birthday bound; nonce derived from attacker-influenced data; the same key used for encryption and MAC, or across tenants, environments, or protocol roles. Show two operations that share key and nonce in one local run.

**Signature and MAC verification**
Verify paths that accept a missing signature, an empty or truncated MAC, `alg` or key-type switching, a key selected by attacker-controlled `kid`/URL, a signature over a different canonicalization than the one consumed, or a boolean that is computed and then ignored. Check for verify-then-parse-again disagreements (the verified bytes differ from the bytes used).

**Comparison, encoding, and timing**
Ordinary equality on MACs, tokens, password hashes, or API keys; early-exit loops; comparisons on hex/base64 strings of different case or padding; type-juggling loose comparisons; length checks that leak. Pair with encoding confusion: base64url vs base64, hex case, Unicode normalization of secrets, and truncation at NUL.

## Key and secret lifecycle attack classes (subagent_type: `general`)

**Randomness and key generation**
Non-CSPRNG sources (`Math.random`, `random`, `math/rand`, `rand()`, time or PID seeds) for tokens, keys, nonces, salts, reset codes, or session IDs; CSPRNG output reduced with modulo bias into a small space; fork-unsafe RNG state in prefork servers; deterministic seeds in tests that leak into production configuration.

**Password storage and key derivation**
Fast hashes (SHA-*, MD5) for passwords, missing or global salts, low or attacker-chosen work factors, PBKDF2 with tiny iteration counts, password-derived encryption keys without a KDF, pepper stored beside the hash, and silent hash-upgrade paths that accept the legacy format forever.

**Key management and rotation**
Keys in source, images, logs, error messages, or client bundles; long-lived keys with no rotation path; rotation that keeps accepting the retired key indefinitely; key IDs that let a caller select another tenant's key; envelope-encryption wrappers that cache plaintext data keys beyond their scope; destruction paths that leave usable copies.

## Protocol and transport attack classes (subagent_type: `general`)

**Transport and certificate validation**
Disabled verification (`verify=False`, `InsecureSkipVerify`, `rejectUnauthorized: false`, custom trust managers that accept all), hostname checks skipped, pinning that falls back to system trust on failure, plaintext fallbacks, and TLS settings controlled by an attacker-influenced configuration value. Confirm which connection carries which secret or integrity-relevant data.

**Protocol composition and downgrade**
Version or cipher negotiation the attacker can steer, missing transcript binding, replayable handshakes or messages without nonces or sequence numbers, reflection of a message back to its sender, and state machines that accept messages out of order. Use a local loopback fixture with both peers.

## Universal moves (apply across the above)

- Build a key table: key, generator, storage, every consumer, every verifier, rotation, and destruction. A defect is usually a row where two consumers disagree on what the key authorizes.
- Diff every verify path against its sign path for canonicalization, encoding, and algorithm selection.
- For each "valid" return in a verifier, write the smallest dummy input that reaches it. If a forged input does, you have the finding.
- Compare against the library's documented safe API (for example AEAD `seal`/`open`, `hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`). A wrapper that reimplements it is a hotspot.

## Validation rules (apply before reporting ANY finding here)

1. Name the protected asset, the lower-trust principal, and the forge/read/replay result. A deprecated primitive with no reachable asset is hardening.
2. Reproduce with dummy keys in a bounded local harness: show the forged object accepted, the plaintext recovered or modified, the nonce repeated, or the wrong comparison result.
3. For timing, separate the cases locally with repeated measurement under the sandbox limits; otherwise use `needs_validation` with the measurement plan.
4. Do not claim key recovery, mass decryption, or remote exploitability beyond what the local result demonstrates.
5. Return `needs_validation` when a KMS policy, HSM, library build option, or deployment key setting decides the outcome, and name the exact fact.
