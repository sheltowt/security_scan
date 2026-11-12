# Smart Contract Hunting

#### When to use this file

Reach for this file when the target contains on-chain programs or code that builds, signs, or relays transactions for them: Solidity/Vyper (EVM), Move (Aptos/Sui), Rust programs (Solana/Anchor, CosmWasm, NEAR), Cairo, and their deployment scripts, upgrade proxies, keepers, relayers, and bridge components. Use `CRYPTOGRAPHY.md` for signature primitives in off-chain services and `SUPPLY-CHAIN-AND-RELEASE.md` for deployment-pipeline trust; use this file for contract state, value flow, and on-chain authorization.

Contracts hold value directly, so a single missing check can move real funds. That raises the evidence bar: every confirmed finding is demonstrated on a local chain with dummy accounts.

Pick relevant classes from Phase 1 and split by value-moving entry point (deposit, withdraw, liquidate, swap, claim, bridge receive, upgrade, governance execute).

## Core discipline (include in every agent prompt for this domain)

```
- Name the asset (token balance, share price, collateral, role, upgrade authority, bridged message) and the account that must not gain it. Gas inefficiency and style issues are not findings.
- Write the invariant first: total shares vs total assets, sum of balances, collateral ratio, role membership, nonce monotonicity. Then find the call sequence that breaks it.
- Every external call is a re-entry point and every token is adversarial until the code restricts it: fee-on-transfer, rebasing, ERC-777 hooks, missing return values, blocklists, and decimals other than 18.
- Validate only on a local chain or in-process test VM (Foundry/anvil without forking, Hardhat network, solana-test-validator, Move unit tests, cw-multi-test) with dummy accounts and locally deployed mocks. Forking mainnet or calling any public RPC is external network access: do not do it. If live state (a real pool's reserves, a deployed proxy's implementation) is decisive, use needs_validation with the exact on-chain fact and the read-only owner check.
- Never sign or broadcast a transaction to a public network, use a funded key, or interact with a deployed contract.
- Classify as `confirmed` only after a local test shows the invariant broken and the attacker's balance or authority change. Use `needs_validation` when deployment parameters, oracle configuration, or deployed state decide the outcome.
```

## Authorization and upgrade attack classes (subagent_type: `general`)

**Access control and privileged roles**
Missing or wrong modifiers on state-changing functions, `tx.origin` authorization, roles granted in constructors that never run behind a proxy, two-step ownership transfers that can be front-run or skipped, role admin loops, and functions callable by anyone because they were assumed internal. Map every role to every function it can reach.

**Upgradeability, proxies, and storage layout**
Uninitialized implementations or proxies (`initialize` callable by anyone or twice), `_authorizeUpgrade` without a check, storage-slot collisions between proxy and implementation or across versions, `delegatecall` to attacker-controllable addresses, `selfdestruct` reachable on an implementation, and function-selector clashes between proxy admin and implementation.

## Value-flow attack classes (subagent_type: `general`)

**Reentrancy and external-call ordering**
State updated after an external call (classic, cross-function, cross-contract, and read-only reentrancy through view functions consumed by other protocols), callbacks from token standards (ERC-721/1155 receivers, ERC-777 hooks, flash-loan callbacks), and reentrancy guards that do not cover every entry point sharing the state.

**Arithmetic, rounding, and precision**
Rounding direction that favors the caller in share/asset conversions, first-depositor share inflation, division before multiplication, decimals mismatch between tokens and oracles, unchecked blocks and pre-0.8 overflow, and casts that truncate. Show the attacker's profit over repeated calls in a local test.

**Token integration assumptions**
Fee-on-transfer and rebasing balances assumed constant, unchecked `transfer`/`transferFrom` return values, approval race and infinite approvals to upgradeable spenders, permit front-running that breaks a flow, and tokens with blocklists or pausing that can freeze a shared pool.

**Oracle, price, and randomness manipulation**
Spot prices from a single pool (flash-loan manipulable), stale or zero oracle answers accepted, missing sequencer-uptime checks on L2s, TWAP windows short enough to move, and randomness from block values or `blockhash`. Demonstrate with a local mock pool or oracle you control.

**MEV and transaction ordering**
Missing slippage or deadline parameters, commit-reveal schemes with a predictable reveal, sandwichable public functions, and first-come claims an observer can front-run. Report only with a concrete ordering that moves value in a local test.

## Message and signature attack classes (subagent_type: `general`)

**Signatures, permits, and replay**
Signatures without chain ID, contract address, nonce, or deadline in the signed payload; `ecrecover` returning `address(0)` accepted; malleable `s` values; EIP-712 domain or type-hash mismatches; signatures reusable across functions or after cancellation.

**Cross-chain and bridge message validation**
Messages accepted without verifying the source chain, sender contract, and nonce; replay across chains or after an upgrade; relayer-controlled fields trusted as authenticated; and finality assumptions on the source chain. Separate on-chain verification bugs (confirmable locally) from off-chain relayer or validator-set configuration (needs_validation).

**Denial of service and gas griefing**
Unbounded loops over user-growable arrays, push payments that a reverting receiver can block, `require` on external call success that one participant can force to fail, and storage growth that makes a shared function exceed the block gas limit. Report only when one principal can stop another's funds or a shared function.

## Universal moves (apply across the above)

- Write the invariant as a Foundry/Hardhat/Anchor test before hunting; let a local fuzzer or invariant test search for the breaking sequence within the sandbox limits.
- Compare every sibling entry point that touches the same storage (deposit vs mint, withdraw vs redeem, single vs batch) for the same checks and ordering.
- Re-read every external call site with the question "what if this calls me back, reverts, returns false, or returns a different amount?"
- Diff the current implementation against the previous version's storage layout and initializer whenever a proxy is present.

## Validation rules (apply before reporting ANY finding here)

1. State the broken invariant, the attacker account, and the asset or authority gained, with the exact call sequence.
2. Reproduce on a local chain or test VM with locally deployed contracts and mocks. Record the test command, the attacker's balance or role before and after, and the block/transaction sequence.
3. Do not fork mainnet, query a public RPC, or touch a deployed contract. Live reserves, oracle configuration, deployed implementation addresses, and admin key custody are `needs_validation` facts with a read-only owner check.
4. Do not claim protocol insolvency, total value at risk, or profit at mainnet scale beyond what the local test demonstrates.
5. Report gas-only, style-only, and centralization-by-design observations (an owner who can pause by design) as hardening unless they break a documented guarantee to another principal.
