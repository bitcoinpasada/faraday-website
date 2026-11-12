# Faraday: finalized inputs bypass the `amount_unverified` guard (private report)

**Repository:** https://github.com/bitcoinpasada/faraday
**Commit audited:** `11da09a2a5ab36868d782922a2a255390c1b36c1` (tag v0.1.7)
**Rechecked:** main on 2026-10-26. `core/faraday-psbt/src/classify.rs` is unchanged since v0.1.7, so the issue is still present.
**How it was found:** an AI-assisted audit (DeepSeek V4.1, Kimi K3, GLM 5.3). Each finding was cross-checked by the two models that did not report it, then this one was confirmed by reading the source. Nothing was built or run.
**Relation to GHSA-7h4m-p8qx-pxrf (sent 2026-10-25):** this is a separate issue. The three findings in that report are also still present in v0.1.7.

---

## High: a coordinator-finalized input skips the SegWit v0 amount check, re-opening the two-round fee attack

**Files:**
- `core/faraday-psbt/src/classify.rs`: `classify()`, the finalized early return (L281–302), and the `amount_unverified` rule (L389–400).
- `core/faraday-psbt/src/inspect.rs`: L582 (the warning) and L589–592 (`total_in`).
- `core/faraday-psbt/src/sign.rs`: L269 (finalized inputs are skipped).

**What goes wrong:**
- `amount_unverified` exists, per its own comment (classify.rs L389–394), to stop the BIP-143 multi-input amount lie. A SegWit v0 input's amount counts only when the PSBT carries the previous transaction.
- For an input that has `final_script_sig` or `final_script_witness`, `classify()` returns early with `amount_unverified: false`, before that rule runs.
- That input's utxo comes from `witness_utxo` when no `non_witness_utxo` is given (classify.rs L256–266), and the coordinator controls that value.
- `inspect` adds it to `total_in`, so the displayed fee uses the coordinator's number. Nothing is blocked, because the AmountUnverified warning is skipped for that input.
- `sign` skips finalized inputs, so the user signs only the other inputs.

**How to trigger** (compromised coordinator, two SegWit v0 inputs A and B that the victim's key controls):
1. **Round 1:** A is honest (carries `non_witness_utxo`). B carries `final_script_witness` (any junk) and a `witness_utxo` that understates its amount. The fee shown is small. The victim signs A, and A's BIP-143 signature commits only to A's amount and the outputs.
2. **Round 2:** the roles swap. B is honest; A is "finalized" with an understated amount. The victim signs B.
3. The coordinator combines the two real signatures over the same outputs. The transaction is valid, and its real fee is A's real amount plus B's real amount minus the outputs, far above what either screen showed.

**Impact:** the user approves and signs a transaction whose real fee is arbitrarily larger than displayed, up to the full input value. This is the attack the flag was added to prevent. Taproot inputs are not affected, because BIP-341 commits to every amount.

**Suggested fix:**
- Apply the same rule in the finalized branch: more than one input, no `non_witness_utxo`, and a SegWit v0 kind read from the scriptPubKey mean `amount_unverified: true`.
- Or refuse to sign or display a multi-input PSBT where any input's amount cannot be checked, finalized or not.
- Either way, treat a coordinator-supplied final witness as untrusted data, not as proof of anything.
