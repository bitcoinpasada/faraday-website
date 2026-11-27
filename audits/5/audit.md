# Audit of Faraday v0.1.7 (AI-assisted)

**Repository:** https://github.com/bitcoinpasada/faraday
**Commit:** `11da09a2a5ab36868d782922a2a255390c1b36c1` (tag v0.1.7, `git rev-parse HEAD`)
**Date:** 2026-10-25 to 2026-10-26
**Models:** DeepSeek V4.1 (deepseek-v4.1-flash-1017), Kimi K3, GLM 5.3. Claude (Opus 5.5) read the source for the findings rated critical or high.
**Tools run:** none. The models read the source as bundled text. Nothing was built or executed.

## Scope

The 629 files listed in `prompt.md`, read in chunks with the prompt there.

## How the findings were confirmed

Each of the three models audited every chunk. Each finding was then checked by the two models that did not report it, with a strict verdict (confirmed, partly, refuted, missing). Below, "confirmed by both checkers" means both said confirmed; "likely" means one confirmed and one said partly. Nobody has reproduced any finding by running code; each is a lead to verify.

Four findings rated critical or high went to the private route instead of this file, as `SECURITY.md` asks. Three are the findings already reported from the audit of `baf4c9f` (GHSA-7h4m-p8qx-pxrf), still present at v0.1.7. One is new (GHSA-vxpw-8g7c-8qmr). Their numbers (1–4), and #10, which describes the same carry-file issue as one of them, are left out below, with two disputed notes on the same component.

Source-check notes (Claude, by reading):
- **#7** (codex32 vault records matched without the set identifier): holds. In `c32_round_records` (`backups/mod.rs`, around line 1949), the `here` match discards the first two header fields. A medium-high backup-correctness issue, not an attack.
- **#5** (a secret file assigned to the public stick blocks the write): holds. The refusal is the safe behaviour; the bug is that a custom plan can reach it and then cannot complete.

## Confirmed by both checkers

### 5. A secret file assigned to the public stick makes the write refuse the whole stick
**Severity:** High (GLM 5.3); Medium (Kimi K3)  
**Affected:** [faraday/faraday-core/src/backup_flow/wallet.rs:400](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backup_flow/wallet.rs#L400)  
**Preconditions:** Wallet plan where `public_slot()` is a place stick that also keeps a seed, SeedQR, passphrase, or codex32 share file.  
**Scenario:** `wallet_slot_files` sets public files for the public stick, then for a place stick also adds every file the plan keeps there, including secret files. At write, `flow_write_go` sees a secret file and requires `f.public_slot() != Some(slot)`; since the slot is the public slot, the condition is false, `refused = true`, and the whole write is refused with `Problem::NotChecked`. After the lock, `flow_changes_files` blocks moving the file, so the stick can never be written and the gate holds the key.  
**Impact:** Backup cannot complete; affected seeds can remain unspendable with no in-app recovery.  
**Suggested fix:** Never add secret files to a slot that is `public_k`; or allow only with an explicit warning and plan validation. Ensure `plan_of_on` does not choose `PublicOn::Place` for a place that keeps seed files.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (medium): code does this; default plan avoids sharing but a custom plan can hit it; after lock the stick is blocked.  
- GLM 5.3 — CONFIRMED (high): `plan_of_on` chooses `PublicOn::Place` without excluding seed files; failure appears after lock; F6 hold keeps seeds unspendable.

### 6. `sealed_marks` omits codex32 shares, so plan changes to codex32 vault shares are not detected
**Severity:** Medium (Kimi K3, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/backup_flow/wallet.rs:1500](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backup_flow/wallet.rs#L1500)  
**Preconditions:** Wallet plan keeps codex32 shares in a vault; user changes the plan after the lock to add/remove a codex32 share in that vault.  
**Scenario:** `sealed_marks` records seeds, wallet description, shares, omit, and passphrases, but not codex32 shares. `made_plan_changed` compares marks; adding/removing a codex32 share changes no marks, so the vault is not marked stale and the round does not run. The vault keeps the old share and never receives the new one; `flow_takes_out_foreign` also cannot detect it.  
**Impact:** Backup does not match the plan; new share missing, old share remains; restore from intended set may fail.  
**Suggested fix:** Include codex32 share marks in `sealed_marks` (distinct mark per seed/share index) so plan changes are detected and the round runs.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (medium): no codex32 mark; `flow_takes_out_foreign` same; silent divergence.  
- GLM 5.3 — CONFIRMED (medium): same; post-lock vault changes are designed; medium because loss requires losing paper copies.

### 7. Codex32 vault records are matched without the set identifier and stale records are never removed
**Severity:** High (GLM 5.3); Medium (Kimi K3)  
**Affected:** [faraday/faraday-core/src/backups/mod.rs:1200](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backups/mod.rs#L1200)  
**Preconditions:** Codex32 set is rotated (new identifier/threshold/length) or the plan stops keeping a codex32 share in a vault.  
**Scenario:** `c32_round_records`’s `here` closure checks only `CODEX32_KEY` and share index, ignoring the set identifier. After rotation, an old record with the same key/index is considered present, so the new share is not added. Removal logic never removes `CODEX32_SHARE` records the plan no longer keeps.  
**Impact:** New codex32 set is not backed up in the vault; old shares remain. If old paper shares are destroyed, the new set may have too few shares to restore; funds loss.  
**Suggested fix:** Compare the full codex32 header (identifier, threshold, length) in `here`, and remove codex32 records for this seed/key not in the plan’s `vault_strings`.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (medium): `here` ignores header; removal covers KEY/WALLET/WALLET_SHARE/PASSPHRASE only; stale remains.  
- GLM 5.3 — CONFIRMED (high): same; silent failure of a secret-share backup can lose funds.

### 8. Codex32 share files are not recorded as secret, so the Backups screen does not warn they are unprotected
**Severity:** Medium (GLM 5.3); Low (Kimi K3)  
**Affected:** [faraday/faraday-core/src/backups/mod.rs:400](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backups/mod.rs#L400)  
**Preconditions:** Wallet plan keeps a codex32 share as a file (`Codex32ShareFile` or `Codex32QrFile`) on a stick.  
**Scenario:** `backup_spots` handles seed files, sheets, shares, and wallet files, but not `What::Codex32ShareFile`/`What::Codex32QrFile`; they fall through to `_ => {}`, so `Spot.secret` is empty. `record_lines` shows “Not seen” instead of “Unprotected.”  
**Impact:** Secret codex32 share can be written to a stick in the clear without the Backups screen flagging it; leak risk.  
**Suggested fix:** Add match arms for `What::Codex32ShareFile` and `What::Codex32QrFile` in `backup_spots` to push the file name into `out.secret`.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): no arms; “Unprotected” requires non-empty secret; shows “Not seen.”  
- GLM 5.3 — CONFIRMED (medium): same; no pre-lock warning for codex32 stick files; Backups screen was the only flag.

### 9. Inbox Load ignores the wallets the user excluded
**Severity:** Medium (Kimi K3, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/inbox.rs:953](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/inbox.rs#L953)  
**Preconditions:** User unchecks (skips) one or more wallets in the Inbox with `InboxChoose`, then presses Load.  
**Scenario:** `inbox_load` does `let inbox = std::mem::take(&mut self.inbox);` and then reads `let skip = self.inbox.skip().clone();`. After `take`, `self.inbox` is default with an empty skip set; the user’s skip set lives in the taken value and is never passed to `load_found_in`. Every wallet the Inbox describes is loaded, including excluded ones. `inbox_load_named` also never consults `skip`.  
**Impact:** A wallet the user deliberately excluded (e.g. malicious descriptor/BSMS) is loaded into the session and appears in the wallet list; exclusion control silently ineffective.  
**Suggested fix:** Read the skip from the taken value before calling `load_found_in`; apply the same skip set in `inbox_load_named`.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (medium): code exactly; skip always empty; loads all; signing still gated by per-wallet Check.  
- GLM 5.3 — CONFIRMED (medium): same; normal flow; no funds moved by the load itself.

### 11. Serialized carry-file bytes containing secret nonces are not zeroized
**Severity:** Medium (GLM 5.3, F25); Low (Kimi K3; GLM 5.3, F26)  
**Affected:** [core/faraday-psbt/src/threshold.rs:400](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/threshold.rs#L400), [:450](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/threshold.rs#L450)  
**Preconditions:** Threshold signing pass produces a carry section; core serializes it to the shell; or core reads a carry file from the shell.  
**Scenario:** `CarrySection::to_bytes`/`carry_bytes` build `Vec<u8>` copies of secret nonces and return them; they are dropped without zeroization. `Carry::parse` takes `&[u8]` and parses secret nonces; the original file bytes are not zeroized by this crate.  
**Impact:** Secret nonces can outlive the session; with later published partial signatures, share compromise.  
**Suggested fix:** Use a zeroizing buffer for the serialized carry file; take ownership of input bytes and zeroize after parsing; require the shell to zeroize its copy after writing.  
**Reported by:** DeepSeek V4.1 (F25, F26).  
**Checkers:**  
- Kimi K3 — CONFIRMED (low, both): accurate hygiene gap; same bytes are also written to media by design; marginal memory remnants.  
- GLM 5.3 — CONFIRMED (medium, F25): `to_bytes`/`carry_bytes` plain `Vec`; nonces later signed under; shell `WriteFile` handling speculative.  
- GLM 5.3 — CONFIRMED (low, F26): `parse` borrows `&[u8]`; crate cannot zeroize borrowed input; gap lives with the shell.

### 12. Threshold signing secret nonces are not zeroized on early return
**Severity:** Medium (GLM 5.3); Low (Kimi K3)  
**Affected:** [core/faraday-psbt/src/sign.rs:1200](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/sign.rs#L1200)  
**Preconditions:** `sign_threshold` populates `secrets` with `SecNonce`s and then returns an error before consuming them.  
**Scenario:** Many `?`/`return Err` paths after `secrets` is populated drop the `Vec` without zeroizing the `SecNonce`s; `SecNonce` may not implement `Drop`.  
**Impact:** Secret nonces remain in memory after a failed signing attempt; with later partial signatures, share compromise.  
**Suggested fix:** Wrap `secrets` in a zeroizing container or explicitly zeroize each `SecNonce` before returning on every error path.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): many early returns; no zeroize; crate’s explicit zeroize elsewhere implies no self-wiping `Drop`.  
- GLM 5.3 — CONFIRMED (medium): same; carry-file copies later signed under; realistic error paths.

### 13. AEZ extracted subkeys left in the un-zeroized `sub` local
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [core/faraday-bip/src/aez.rs:285](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/aez.rs#L285)  
**Preconditions:** Any AEZ operation (aezeed decode) runs; process later discloses stack memory.  
**Scenario:** `State::new` copies the 48-byte extracted key into `sub`, zeroizes `extracted`, but never zeroizes `sub`; the I/J/L subkeys remain on the stack after `State::new` returns.  
**Impact:** Secret key material persists beyond intended lifetime; partially defeats the module’s zeroization guarantee.  
**Suggested fix:** Zeroize `sub` and the `ik`/`jk`/`lk` copies after building `State`.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): code does; module otherwise zeroizes diligently; defense-in-depth.  
- GLM 5.3 — CONFIRMED (low): same; understated (`ik`, `jk`, `lk` are additional copies).

### 14. FROST `sign()` copies the secret nonce halves into un-zeroized locals
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [core/faraday-bip/src/frost.rs:700](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/frost.rs#L700)  
**Preconditions:** `sign()` is called; process later discloses stack memory.  
**Scenario:** `sign()` does `let (k1_, k2_) = (secnonce.k1, secnonce.k2); drop(secnonce);` and derives `k1`/`k2`. The `SecNonce` is zeroized on drop, but the copies are plain `[u8;32]` locals never zeroized.  
**Impact:** Secret nonce material persists on the stack after signing; with partial signature, share recovery.  
**Suggested fix:** Zeroize `k1_`, `k2_`, `k1`, `k2` and intermediate `s` inputs before returning.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): code does; `d` and `s` also not zeroized; requires stack disclosure.  
- GLM 5.3 — CONFIRMED (low): same.

### 15. `read_header` integer overflow on 32-bit with a crafted length field
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [core/faraday-backup/src/kdbx.rs:385](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-backup/src/kdbx.rs#L385)  
**Preconditions:** 32-bit build reads an attacker-supplied KDBX header through `cost_of()` or `verify()`.  
**Scenario:** `read_header` does `at += 5; if at + len > bytes.len() { return None; } let value = &bytes[at..at + len];`. With `len` near `2^32` and small `at`, `at + len` wraps on 32-bit, the bounds check passes, and the slice has start > end, panicking.  
**Impact:** DoS panic on 32-bit targets; no memory unsafety.  
**Suggested fix:** Use checked arithmetic (`at.checked_add(len)`) and reject overflow before slicing.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): code does; `blocks_verify` has the same pattern; no memory unsafety.  
- GLM 5.3 — CONFIRMED (low): same; entry point needs no passphrase.

### 16. Base64 decode accepts non-canonical encodings (non-zero padding bits)
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [core/faraday-bip/src/base64.rs:95](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/base64.rs#L95)  
**Preconditions:** A base64 string with non-zero bits in the final partial sextet is supplied.  
**Scenario:** `decode()` checks padding count against dangling-sextet count but never verifies discarded low bits are zero; `"Zh=="` and `"Zg=="` both decode to the same byte.  
**Impact:** Encoding malleability; decoded value identical; minimal practical impact; violates RFC 4648 canonical form.  
**Suggested fix:** Reject non-zero discarded bits after the final partial group.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): traced; only padding count validated; decoded bytes identical.  
- GLM 5.3 — CONFIRMED (low): same; canonicality defect, not key/fund risk.

### 17. `read()` classifies hex strings containing no `0` as Base58 before ever trying Hex
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [core/faraday-codec/src/encodings.rs:80](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-codec/src/encodings.rs#L80)  
**Preconditions:** A caller uses `read()` to auto-detect encoding of user/coordinator-supplied hex material.  
**Scenario:** `read()` tries bech32, Base58Check, plain Base58, then hex. Every hex digit except `0` is in the Base58 alphabet, so `"deadbeef"` decodes as Base58 with different bytes and never reaches the hex branch. The doc comment’s “cannot mistake a string for something else” is false for the hex/Base58 overlap.  
**Impact:** Wrong-byte decode of hex input misidentified as Base58; wrong key/address derivation if caller uses bytes without checking `encoding == Hex`.  
**Suggested fix:** Try hex before plain Base58, or require callers to state expected encoding; correct the doc comment.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): verified; doc claim false; caller-dependent.  
- GLM 5.3 — CONFIRMED (low): same; `Reading` exposes encoding so a careful caller can reject.

### 18. Fountain decoder state grows per distinct part with no bound on the number of parts
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [core/faraday-codec/src/ur/fountain.rs:233](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-codec/src/ur/fountain.rs#L233)  
**Preconditions:** Malicious coordinator supplies UR parts via USB-stick file or long QR session; UR layer caps `MAX_FRAGMENTS = 2048`, but nothing caps distinct parts fed to `Decoder::receive`.  
**Scenario:** Each new index set is inserted into `Decoder::received` and unresolved mixes into `Decoder::buffer` with a fragment-sized `Vec`. Attacker crafts millions of parts with distinct sequence numbers all claiming the same small message; memory grows until allocation aborts.  
**Impact:** DoS of signing device via memory exhaustion; no key/signature impact.  
**Suggested fix:** Cap the number of received parts (e.g. multiple of `sequence_count`) and refuse further parts past it.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): no cap; DoS only.  
- GLM 5.3 — CONFIRMED (low): verified; `sequence` u32 unchecked; deterministic `choose_fragments`; memory growth; `MAX_FRAGMENTS` detail immaterial.

### 19. `mlock` failure is tolerated with one stderr line, leaving long-lived secret pages swappable
**Severity:** Low (DeepSeek V4.1, Kimi K3)  
**Affected:** [core/faraday-crypto/src/pinned.rs:265](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-crypto/src/pinned.rs#L265)  
**Preconditions:** `pin-pages` build on a machine with swap and low `RLIMIT_MEMLOCK`; desktop build handling real seeds.  
**Scenario:** `raw::hold` sets `PIN_FAILURE` and carries on; the shell prints one stderr line; the kernel can page session key/seed words/seed bytes to swap, where they survive shutdown.  
**Impact:** Key material outlives the session on disk; weaker form of the leak pinned pages exist to prevent.  
**Suggested fix:** Treat `mlock` failure as fatal for secret pages, or surface it prominently in the UI at key load.  
**Reported by:** GLM 5.3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; documented trade-off; air-gapped device has no swap.  
- Kimi K3 — CONFIRMED (low): same; requires swap, memlock exhaustion, and later storage access.

### 20. MuSig2 pass reports a partial signature that a later Share round clears
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [core/faraday-psbt/src/sign.rs:800](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/sign.rs#L800)  
**Preconditions:** MuSig2 input with two participants of this device; one has nonce/session secret (`Sign`), the other stale nonce/no session secret (`Share`); `Sign` processed before `Share`.  
**Scenario:** `sign_musig` processes `mine` in order. `Sign` writes a partial signature and pushes it to `written`. Later `Share` calls `clear_partial_sigs`, removing every partial signature on the input, including the one just written. `SignResult.signed_inputs` still contains the removed signature.  
**Impact:** UI may show a signature not in the PSBT; user may send incomplete transaction or believe a participant signed.  
**Suggested fix:** Process all `Share` rounds before any `Sign`/`SignLast`, or remove cleared signatures from `written`.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): code does; reporting bug only; PSBT cannot finalize without cleared sig.  
- GLM 5.3 — CONFIRMED (low): same; PSBT correct; false report to UI.

### 21. `build_final`’s `index_err` closure hardcodes `input: 0`
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [core/faraday-psbt/src/finalize.rs:130](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/finalize.rs#L130)  
**Preconditions:** Error paths only (overlong redeem/witness script or unknown script type).  
**Scenario:** `let index_err = |reason| Error::Finalize { input: 0, reason };` ignores the `index` parameter; a finalize failure on input 3 is reported as input 0.  
**Impact:** Misleading error message; no funds impact.  
**Suggested fix:** Capture the index: `|reason| Error::Finalize { input: index, reason }`.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; error still aborts finalization.  
- GLM 5.3 — CONFIRMED (low): same.

### 22. A multisig input’s “yours” cosigner claim is never derived or checked against the script key
**Severity:** Low (DeepSeek V4.1, Kimi K3)  
**Affected:** [core/faraday-psbt/src/inspect.rs:1420](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/inspect.rs#L1420)  
**Preconditions:** Malicious PSBT states the user’s master fingerprint in `bip32_derivation` beside a multisig script key that is not the user’s.  
**Scenario:** `cosigners()` marks a cosigner “ours” purely because the PSBT states the user’s fingerprint next to the script key; the `ScriptKind::Multisig` arm sets `is_ours = true` and adds the fingerprint to `participating_keys` without the derivation-and-script check the single-sig arms perform. `NoParticipatingKey` danger is suppressed. Signing fails closed afterwards with `KeyMismatch`.  
**Impact:** Misleading review; spoofable “yours” label on multisig inputs; no direct fund loss.  
**Suggested fix:** Derive the stated path and require the derived key to equal the script key before marking a cosigner ours; otherwise warn `UnknownDerivation`.  
**Reported by:** GLM 5.3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; signing fails closed.  
- Kimi K3 — CONFIRMED (low): same; documented “claimed, not verified.”

### 23. Step-6 stick identity check ignores extra files sharing a stem with a slot file
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/backup_flow/steps.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backup_flow/steps.rs) — `own_name` closure in `flow_after_check` (line not supplied)  
**Preconditions:** Attacker-prepared/tampered stick presented at step 6 in place of the stick bound at step 2.  
**Scenario:** `flow_after_check` compares label, serial, and file listings, but `own_name` excludes any file whose name starts with the stem of a slot file followed by `-`, without checking extension. A stick carrying `seed-<fp>-evil.exe` beside `seed-<fp>.txt` passes the `NotRead` check because the extra file is filtered out of `l2`.  
**Impact:** Weakens the “same stick as step 2” assurance; no secret is written to/read from the extra file.  
**Suggested fix:** Require the extension to match, or restrict the allowance to exact renamed forms the shell produces.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; extra file neither written nor read.  
- GLM 5.3 — CONFIRMED (low): same; writes go by Outbox name.

### 24. TOTP codes are computed and displayed for Unix epoch when the device clock is unknown
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/codes/screen.rs:130](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/codes/screen.rs#L130)  
**Preconditions:** Device booted without a known clock (`clock_now()` returns `None`) and at least one open vault containing a TOTP entry.  
**Scenario:** `draw()` and `compact()` do `let now = app.clock_now().unwrap_or(0); let rows = codes_rows(app, now);`. `codes_rows()` computes a valid TOTP for timestamp 0; `code_row()` renders it with a normal progress bar/countdown. Only the separate “Now” row says the time is not known.  
**Impact:** User is shown a plausible-looking but wrong authentication code and may copy it; misleading display, no key exposure.  
**Suggested fix:** When `clock_now()` is `None`, do not compute/display codes; render an explicit “time not known” state.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; misleading display.  
- GLM 5.3 — CONFIRMED (low): same; `codes_rows` internals not shown but natural reading.

### 25. Boot import reads every readable file into memory at first insertion, before consent, with no size bound visible
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/boot_import/mod.rs:345](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/boot_import/mod.rs#L345)  
**Preconditions:** Boot stick carrying large/numerous files; low-RAM target.  
**Scenario:** `import_start()` iterates `boot.files` and unconditionally queues `Read`/`ReadQr` for every recognized file at first insertion, before the sheet/consent. Each answer is held as an `Item`; no per-file/total size cap appears in this chunk; declared sizes are only used for display.  
**Impact:** Memory exhaustion/DoS at boot; pre-consent parsing attack surface; no key material at rest.  
**Suggested fix:** Enforce per-file and aggregate byte caps before issuing reads; skip/mark oversized files; defer unticked reads until Import is pressed.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; availability only.  
- GLM 5.3 — CONFIRMED (low): same; module doc states it; unticked files wiped on drop.

### 26. Boot import’s Later exits the vault-unlock sheet without clearing the typed passphrase
**Severity:** Low (DeepSeek V4.1, Kimi K3)  
**Affected:** [faraday/faraday-core/src/boot_import/mod.rs:640](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/boot_import/mod.rs#L640)  
**Preconditions:** Physical access to the powered-on device during the same session, after the user typed a vault passphrase at the import sheet’s Unlock step and pressed Later; boot import still pending.  
**Scenario:** `I::Later` does `self.sheet = None; self.vaults.clear_unlock(); self.vaults.set_focus(None);` and never calls `clear_passphrase()`. Every other exit via `import_next()` explicitly calls `clear_passphrase()`. The passphrase remains in the vault area; reopening the sheet or navigating to Vaults unlock can present it again, one Show-Typed press away from clear text.  
**Impact:** Typed passphrase survives after the user closed the sheet; revealable by anyone with the device while the session is live; vault stays locked.  
**Suggested fix:** Add `clear_passphrase()` and reset `typed_shown` to `I::Later`; clear on any sheet dismissal.  
**Reported by:** GLM 5.3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; inconsistency; physical access.  
- Kimi K3 — CONFIRMED (low): central claim verified; need for explicit call in `import_next` is evidence; reachability supported; low.

### 27. Decode screen takes input amounts and fee for an Inbox transaction from any Inbox PSBT with a matching txid
**Severity:** Low (DeepSeek V4.1, Kimi K3)  
**Affected:** [faraday/faraday-core/src/decode.rs:300](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/decode.rs#L300)  
**Preconditions:** Compromised coordinator delivers a raw finished transaction and a PSBT with the same txid but falsified `witness_utxo`/`non_witness_utxo` amounts to the Inbox; user opens the raw transaction on the Decode screen to verify before broadcasting.  
**Scenario:** `Action::DecodeInbox` decodes the raw transaction, then looks up prevouts first from the open spend’s PSBT, else any Inbox PSBT with the same txid. The coordinator’s PSBT claims inflated/deflated input values, so the fee line (`paid_in - paid_out`) is false. Outputs/addresses come from the raw transaction and cannot be falsified this way.  
**Impact:** User verifies/broadcasts believing the fee shown; true fee different; exposure bounded to the fee.  
**Suggested fix:** When prevouts come from an Inbox PSBT rather than the spend signed here, label fee/input amounts as reported by the coordinator’s file, or omit the fee.  
**Reported by:** GLM 5.3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (low): code does; fee from untrusted data.  
- Kimi K3 — CONFIRMED (low): same; txid match binds outpoints/outputs, not amounts; loss requires reliance on secondary screen.

### 28. `family_use_psbt` marks the spend’s WALLET and CHECK steps done without the user performing the address check
**Severity:** Low (DeepSeek V4.1, Kimi K3, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/family/mod.rs:1097](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/family/mod.rs#L1097), [:1245](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/family/mod.rs#L1245)  
**Preconditions:** User on Spend tab with wallet loaded or route taken; PSBT arrives by QR/USB or user picks one from Files.  
**Scenario:** `family_use_psbt` unconditionally sets `done[WALLET] = true` and `done[CHECK] = true` with the comment “The addresses were checked on the tab’s own page.” `family_arrived` accepts a PSBT when `family_ready()` or `route.is_some()`, which can be true with `closed[CHECK] == false`. The spend opens at the first undone step with the coordinator-verification step pre-marked done.  
**Impact:** One verification layer silently skipped; transaction summary still shown; defense-in-depth weakening.  
**Suggested fix:** Only pre-mark `CHECK` done when `family_page_done(page::CHECK)` or `is_checked(wallet.checksum())`; otherwise leave it undone.  
**Reported by:** Kimi K3 (F51), GLM 5.3 (F54).  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (F51/F54): code does; CHECK card remains in column but not forced; low.  
- Kimi K3 — CONFIRMED (F54): every claim supported; all three reachability paths; low.  
- GLM 5.3 — CONFIRMED (F51): code matches; realistic Paper route path; low.

---

## Likely

### 1. A made flow with no sticks is never considered written; `waiting()` stays true and the gate holds the key
**Severity:** High (Kimi K3); Low (GLM 5.3)  
**Affected:** [faraday/faraday-core/src/backup_flow/mod.rs:700](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backup_flow/mod.rs#L700)  
**Preconditions:** Wallet backup plan with no sticks (allowed for wallets; `flow_continue` does not enforce `min_places` for `Kind::Wallet`), or restored kept state with `made=true` and empty slots.  
**Scenario:** User chooses a wallet plan keeping the wallet only in a vault and on no stick. `flow_before_lock` maps Lock to Write then Done because slots is empty. `all_written()` returns false because it requires `!slots.is_empty()`; `waiting()` returns true; `gate_encode` writes the key into the gate; `done_body` returns 0; `wallet_seed_released` returns false, so held seeds are never released.  
**Impact:** Funds can be locked indefinitely; backup cannot complete.  
**Suggested fix:** Make `all_written()` true when `made` and slots is empty, or make `waiting()` require `!slots.is_empty()`; make `valid()` set Done for a restored Write step with no slots; make `done_body` show done when no sticks.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (high): every checkable claim holds; wallet may keep nothing on a stick; `waiting()` true; gate holds key; `wallet_seed_released` false; `valid()` repair guarded; only `done_body` in screen.rs not provided.  
- GLM 5.3 — PARTLY (low): mechanics accurate but impact wrong and state unreachable: `wallet_lock_write` requires the sticks item; plan edits cannot remove the last stick; `wallet_hold_move` leaves `held` empty if no sticks; at most UI inconsistency.

### 2. KDBX `verify()` runs Argon2id with attacker-controlled passes/lanes before authentication; only memory is capped
**Severity:** Medium (GLM 5.3); Low (DeepSeek V4.1)  
**Affected:** [core/faraday-backup/src/kdbx.rs:291](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-backup/src/kdbx.rs#L291)  
**Preconditions:** Attacker gets a crafted KDBX file onto the device (USB/QR) and the device calls `verify()` or derives keys from its header before the user notices; no passphrase knowledge needed.  
**Scenario:** `verify()` calls `read_header()`, checks the unkeyed SHA-256 of the header (attacker computes it), then calls `keys()`/`argon2id()` at the header-stated cost before the keyed header HMAC is verified. `stretch()`/`read_kdf()` reject only `memory_kib > MAX_MEMORY_KIB` (4 GiB); passes and lanes are unbounded. A header with `memory_kib = 8` and `passes = 0xFFFFFFFF` makes the device run Argon2id billions of times; a huge memory value forces a 4 GiB allocation attempt.  
**Impact:** Malicious backup file hangs the air-gapped device indefinitely; DoS mid-session; future callers inherit.  
**Suggested fix:** Reject `passes > DEVICE_PARAMS.passes` and `lanes > DEVICE_PARAMS.lanes`; consider capping memory at 64 MiB; document/gate `verify()` on attacker-supplied bytes.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): code accurate; exploit precondition not established: module documents `verify()` as self-check on bytes it wrote; no caller feeding attacker KDBX shown; 4 GiB allocation capped before allocation; latent hardening gap.  
- GLM 5.3 — CONFIRMED (medium): every code claim holds; unkeyed hash trivially satisfiable; passes/lanes unbounded; cited test only corrupts header; 4 GiB variant mostly failed allocation; unbounded passes/lanes real defect.

### 3. `Pinned` assumes a 4096-byte OS page; on 16K/64K-page Linux kernels `munlock` unpins a live neighbour secret
**Severity:** Medium (GLM 5.3); Low (DeepSeek V4.1)  
**Affected:** [core/faraday-crypto/src/pinned.rs:62](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-crypto/src/pinned.rs#L62)  
**Preconditions:** Faraday on a Linux kernel with base page >4096 (aarch64 16K/64K; some Pi kernels); code special-cases 16K only for macOS/aarch64; two+ `Pinned` allocations on the same physical page.  
**Scenario:** `layout::<T>()` rounds to `PAGE = 4096` and aligns to 4096. On a 16K-page kernel, four such allocations share one physical page. `mlock` locks the whole page; dropping the first `Pinned` calls `munlock` on its 4096-byte range, unlocking the entire 16K page. Remaining live `Pinned` secrets become pageable and can reach swap.  
**Impact:** Long-lived secrets (session key, sealed seeds) can reach swap despite the `mlock` guarantee; no warning.  
**Suggested fix:** Determine page size at runtime (`sysconf(_SC_PAGESIZE)`/`GetSystemInfo`) for alignment and rounding; keep compile-time value as a lower bound; assert runtime page size divides alignment.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): mechanism real; supported pin-pages targets x86-64/armv7 use 4K; claim some Pi 64-bit kernels use 16K not established; allocator not guaranteed same larger page; latent platform bug.  
- GLM 5.3 — CONFIRMED (medium): mechanism exactly; `PAGE` hardcoded; `munlock` whole kernel page; macOS special-case proves 16K considered but Linux aarch64 missed; caveat targets 4K; medium fair.

### 4. A made flow can reach Write with an unsealed used vault; the repair sets `adding` without removing the vault from `made_in`
**Severity:** Medium (GLM 5.3); Low (Kimi K3)  
**Affected:** [faraday/faraday-core/src/backup_flow/steps.rs:900](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backup_flow/steps.rs#L900)  
**Preconditions:** Made flow with a used vault not open at lock time (user closes vault after Make, or restored kept state has `made=true`, `made_in` contains the vault, no sealing).  
**Scenario:** `flow_before_lock` only checks sealing when `was_write` is true. If at Lock or Make, it maps to Write without checking. The lock seals only open vaults; the unsealed vault remains in `made_in`. `valid()`/`flow_before_lock` set `adding=true` but do not remove the vault from `made_in`; `flow_needed_vaults` for adding only includes vaults not in `made_in`, so the round does not copy the key into the unsealed vault. At Write, `flow_write_go` finds no `sealed_of(v)` and refuses the stick.  
**Impact:** Backup cannot complete for that vault; incomplete backup.  
**Suggested fix:** When setting `adding=true` for missing sealing, remove unsealed vaults from `made_in`; check sealing for any made flow going to Write.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — PARTLY (low): mechanism exists; preconditions not reachable in provided code: `wallet_lock_write` requires every used vault open and seals all; key flows have all used vaults open; single-vault key flow self-heals; only multi-vault key flow with vault lost key by unseen means could stick.  
- GLM 5.3 — CONFIRMED (medium): verified; sealing check gated on `was_write`; vault closed between Make and lock keeps `made_in` no sealing; repair doesn’t remove; round never reopens; `flow_write_go` refuses; realistic for GPG/SecureBoot; mitigation unlock affected vault at Write sends back to Lock but UI unclear.

### 5. Kept backup-flow state is unauthenticated: forged `wrote`/`wsealed` lines decode as a completed backup and release held keys
**Severity:** Medium (DeepSeek V4.1, GLM 5.3); reported High  
**Affected:** [faraday/faraday-core/src/backup_flow/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/backup_flow/mod.rs) — `decode` function (line not supplied)  
**Preconditions:** Physical access to the medium storing kept state across a lock; kept state writable; attacker knows public data (wallet descriptor checksum, seed fingerprints, file-name patterns).  
**Scenario:** Attacker rewrites kept state for a wallet flow: `made=1`, `step=Done`, a `wallet` line with the real checksum, `wshape`/`wseed`/`wans` plan lines, `slot`+`wrote`+`wfile` lines marking every slot written with file names matching `is_seed_file` and arbitrary SHA-256s, and `wsealed` marks covering each seed. `valid()` accepts made/subject/checksum consistency and named targets matching the plan; `step == Done` with `all_written()` passes. `wallet_seed_released` returns true for every held seed; keys F6 holds become spendable; UI shows backup written.  
**Impact:** Keys sign before any backup exists; false “Written to every place”; real backup may never be made; later device loss loses funds.  
**Suggested fix:** Authenticate kept state with an HMAC keyed from device secret material; refuse restore if tag fails; never let decoded `written`/`sealed` state alone release held keys; require fresh read-back of at least one written stick before `wallet_seed_released` returns true.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — CONFIRMED (medium): kept state unauthenticated; `encode`/`decode` plain tab-separated; `valid()` only self-consistency; forged state passes; attacker needs public data; physical write access real; medium because precondition strong.  
- GLM 5.3 — PARTLY (medium): core real; forged flow passes `valid()` and releases F6 hold; but malicious-coordinator variant no basis; gate state separate and equally unauthenticated; attacker with full storage write can tamper anything; sabotage of safety net, not key theft; medium.

### 6. Checklist step numbers collide for wallets with >=28 seeds (and >=56 passphrases / >=128 vaults)
**Severity:** Medium (GLM 5.3); Low (DeepSeek V4.1)  
**Affected:** [faraday/faraday-core/src/bstep.rs:56](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/bstep.rs#L56)  
**Preconditions:** Wallet plan with 29+ seeds (e.g. multisig `n >= 29`), or 56+ passphrases, or 128+ vaults in one backup plan; whether wallet creation permits that many keys is not shown.  
**Scenario:** `bstep::of()` clamps the index into a fixed sub-range: `Copy(i) => COPY + i.min(27)`, `Codex32(i) => CODEX32 + i.min(27)`, `Passphrase(i) => PASSPHRASE + i.min(55)`, `Vault(v) => VAULT + v.min(127)`. For seed index 28, `of(Copy(28)) == 43`, and `item(43) == Copy(27)`. The checklist entry for seed 29 opens the copy-and-check flow for seed 28; same for codex32/passphrases/vault 128.  
**Impact:** Backup that does not restore; one or more seeds silently omitted; if needed for threshold multisig recovery, funds unrecoverable; silent and passes checklist verification.  
**Suggested fix:** Widen the step number space (e.g. `u16`), or enforce the wallet key limit at creation and `debug_assert!`/refuse in `bstep::of` when `i` exceeds the range.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): clamp real; title off by one (28 seeds indices 0..27 map cleanly; collision starts at 29 seeds/index 28); reachability of 29+ seeds unrealistic (P2WSH caps at 20 keys); checklist use outside chunk; code defect genuine but impact speculative.  
- GLM 5.3 — CONFIRMED (medium): math checks out; `Copy(28)` and `Copy(27)` collide on 43; same for others; clamping silent; doc says checklist mapping; caveat reachability unproven; if plan exists, silent omission.

### 7. Derived intermediate key in `grind_account` is not explicitly zeroized
**Severity:** Low (DeepSeek V4.1, Kimi K3)  
**Affected:** [core/faraday-bip/src/vanity.rs:348](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/vanity.rs#L348)  
**Preconditions:** User runs the vanity address grinder in account mode on a device with a loaded master key; `MasterKey::derive` result in `node` holds secret key material for `purpose'/coin'`.  
**Scenario:** `grind_account` creates `node = master.derive(c, &head)` holding a derived extended private key at `purpose'/coin'`. Secret key bytes are copied into `parent` (`Xpriv`), and `parent` is erased via `erase_xpriv` at the end. `node` itself is never explicitly zeroized; it relies on the return type’s `Drop`.  
**Impact:** If the type does not zeroize on drop, intermediate BIP-32 secret remains in RAM after the grind; reduced risk on air-gapped device (cold-boot/memory disclosure); `parent` properly erased shows intent.  
**Suggested fix:** Explicitly zeroize `node` after extracting secret key/chain code into `parent`; or confirm/document `ZeroizeOnDrop`.  
**Reported by:** GLM 5.3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): observation correct; security conclusion conditional/unverified: return type not shown; finding hedges; legitimate defense-in-depth note, not confirmed leak.  
- Kimi K3 — CONFIRMED (low): code matches; `node` holds `purpose'/coin'` private key; `parent` erased; `node` not; conditional on `Drop`; low.

### 8. `qr_png` does not zeroize the rendered pixel buffer, unlike `grey_png`
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [core/faraday-codec/src/png.rs:50](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-codec/src/png.rs#L50)  
**Preconditions:** Caller passes a secret-bearing `QrMatrix` (e.g. SeedQR) to `qr_png`, e.g. “save SeedQR as picture to USB”; physical access or later memory disclosure.  
**Scenario:** `qr_png` builds `raw`, the full filtered pixel image, and returns `file(side, side, 1, &raw)` without wiping it. Adjacent `grey_png` explicitly zeroizes its `raw` with the comment “The picture may be of a secret”; `file()` zeroizes the intermediate zlib `data`. If a SeedQR matrix is rendered through `qr_png`, the complete seed image remains in freed heap.  
**Impact:** Seed/key material persists in process memory after PNG production; recoverable via physical/cold-boot or memory-read bug; contrary to documented SeedQR zeroization.  
**Suggested fix:** Zeroize `raw` in `qr_png` after the `file(...)` call, as `grey_png` does.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): code asymmetry real; impact conditional on caller passing secret-bearing matrix; no such caller in provided code; feature hypothetical; core code claim holds.  
- GLM 5.3 — CONFIRMED (low): every code claim checks out; `qr_png` no zeroize; `grey_png` does; `file()` wipes zlib; rendered image equivalent to secret; caller decides; low.

### 9. `read_input` returns empty bytes for invalid hex in Hex mode instead of an error
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [core/faraday-codec/src/encodings.rs:195](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-codec/src/encodings.rs#L195)  
**Preconditions:** Caller uses `read_input` with `ReadAs::Hex` for secret/key-determining material (entropy import, passphrase, key bytes) and does not reject an empty result.  
**Scenario:** `ReadAs::Hex => from_hex(text).unwrap_or_default()` maps invalid hex (odd length, non-hex character) to an empty `Vec`. A user who mistypes one character gets `[]` instead of an error. If that empty value flows into entropy import/passphrase handling, the device derives a key from empty input — a valid but wrong/trivially known wallet — with no indication.  
**Impact:** Caller-dependent; worst case wallet from empty/attacker-guessable input after a typo; silent wrong-passphrase wallet; parser fails open.  
**Suggested fix:** Make the Hex arm return an error or `Option`; only Auto mode should fall back to text bytes.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): behavior accurate; documented intentional API; impact requires unshown caller; entropy import would normally reject empty; fail-open concern caller-dependent.  
- GLM 5.3 — CONFIRMED (low): code exactly; no error channel; doc shows deliberate fail-open; impact correctly conditional; no caller shown; low.

### 10. `CarryEntry` drop does not zeroize its secret nonce
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [core/faraday-psbt/src/threshold.rs:300](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/threshold.rs#L300)  
**Preconditions:** A `CarryEntry` is taken out of a `CarrySection` (e.g. via `take`) and dropped outside the section, or an early return drops a `CarryEntry`.  
**Scenario:** `CarryEntry` implements `Zeroize` to wipe both `sighash` and `secnonce`, but its `Drop` impl only zeroizes `sighash`. If a caller takes an entry and drops it, the secret nonce remains in memory until overwritten.  
**Impact:** Secret nonce can outlive the session and be recovered from memory; potentially share compromise.  
**Suggested fix:** Call `self.zeroize()` in `Drop`, or explicitly zeroize `self.secnonce`.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): `Drop` only `sighash`; `Zeroize` wipes both; entries dropped with section wiped via `CarrySection::drop`; leak limited to entries dropped outside section; `parse` early returns and `take()` path exist; residual nonce + later partial sig enables share recovery given memory disclosure.  
- GLM 5.3 — PARTLY (low): code fact holds; on every path in shown code the dropped nonce is never signed under; failed first-location leaves nonce records no carry file; retry refuses; no caller takes entry and signs under it; share-compromise latent; hygiene bug.

### 11. `check()` prefix-compares typed string against made string (`zip` stops at shorter input)
**Severity:** Low (DeepSeek V4.1, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/codex32_backup/mod.rs:560](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/codex32_backup/mod.rs#L560)  
**Preconditions:** A caller of `pub fn check()` passes `typed` shorter than `made`; all callers shown enforce full length before calling, so not reachable from code shown.  
**Scenario:** `check(form, j, typed, Some(made))` with `typed` a strict prefix of `made`: `want.bytes().zip(typed.bytes()).position(|(a,b)| a != b)` returns `None` because `zip` ends at the shorter input, so the function reports `Found::Holds` for an incomplete string. A future/out-of-chunk caller that does not pre-check length would mark a truncated share string as matching.  
**Impact:** If reached, a truncated typed-back codex32 share is reported as “holds”; user may believe an incomplete paper copy is correct; backup that does not restore.  
**Suggested fix:** Compare lengths first or use full byte equality; return `Found::Differs` at the first missing box when lengths differ.  
**Reported by:** Kimi K3.  
**Checkers:**  
- DeepSeek V4.1 — PARTLY (low): `zip`-prefix behavior real; no caller in shown code triggers; `Strings::key` builds exact length; `scanned` rejects wrong length; `type_in` made=None; latent robustness issue, not live vulnerability.  
- GLM 5.3 — CONFIRMED (low): code exactly; `zip` stops at shorter; callers full-length; `pub fn` relies on callers; future caller or made string different length would let truncated share reported as holding; no attacker-reachable path; low.

### 12. Potential wallet built from the wrong key when the passphrase key is already loaded
**Severity:** Low (Kimi K3, GLM 5.3)  
**Affected:** [faraday/faraday-core/src/inbox.rs:1260](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/inbox.rs#L1260)  
**Preconditions:** User opens the potential-wallet sheet for a seed, types a BIP-39 passphrase whose key is already loaded, and presses Enter/Continue before the 400 ms `TYPED_PAUSE_MS`.  
**Scenario:** `potential_typed` sets `p.with = None` on every typed character and only recomputes it in `potential_refresh` after the pause. `potential_make` adds the key with the typed passphrase; if that key is already loaded, `s.add` returns `Refusal::Duplicate`, and the code falls back to `self.inbox.potential().and_then(|p| p.with).unwrap_or(seed.fingerprint)`. With `p.with` still `None`, it uses `seed.fingerprint` — the seed’s fingerprint with the file passphrase or none — not the typed-passphrase key. The single-key wallet is then built from that wrong key.  
**Impact:** Wallet created for a different key than the user typed/intended; wallet name shows wrong fingerprint; user may use wrong wallet; funds remain spendable by seed holder; wrong-output/confusion, not outright loss.  
**Suggested fix:** Use the fingerprint the duplicate key actually has (carry it in `Refusal::Duplicate`), or look up the key by the typed passphrase; or call `potential_refresh` and require `p.with` to be `Some` before making the wallet.  
**Reported by:** DeepSeek V4.1.  
**Checkers:**  
- Kimi K3 — CONFIRMED (low): all claims check out; `potential_typed` sets `with=None`; `potential_make` doesn’t refresh; `Duplicate` branch uses `seed.fingerprint`; downstream `potential_match` None; wallet name bare fingerprint; low because narrow preconditions and fingerprint shown.  
- GLM 5.3 — PARTLY (low): core race real; fallback yields `seed.fingerprint`; but stated outcome doesn’t always follow: after fallback `potential_make` requires `session.keys.position(fp)` to succeed; if bare/file-passphrase key not loaded, returns silently no wallet; wrong-key wallet only when other key also loaded; stale-`with` bug and wrong-fingerprint fallback confirmed, but “wallet built” needs additional unstated precondition.

---

## Appendix: disputed findings (appendix only)

Duplicates merged into confirmed/likely items above are omitted: F31→F20, F49→F48. F57 is retained below because its supplied checker reason addresses a different issue (`found_in` PBKDF2) than its title. F60/F64/F72 are merged into one places-allocation line; F102/F116 are merged into one scanned-entry capacity line.

- **secp256k1 context blinding factor is derived from the public chain code** — [core/faraday-bip/src/keys.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/keys.rs) — Kimi K3: PARTLY (blind uses master chain code; account xpub does not reveal it; narrow weakening); GLM 5.3: REFUTED (account xpub cannot compute blind; attack precondition fails).
- **Policy key substitution uses unanchored string replacement** — [core/faraday-bip/src/compile.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/compile.rs) — DeepSeek V4.1: PARTLY (mechanism real; example token contains `0`, impossible in xpub; corrupted xpub likely fails closed); GLM 5.3: PARTLY (mechanism real; concrete example wrong; narrower conditions).
- **Extra closing parenthesis in wsh template makes all P2WSH multisig configs unparseable** — [core/faraday-bip/src/multisig_config.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-bip/src/multisig_config.rs) — DeepSeek V4.1: REFUTED (template is balanced; finding misquotes code); Kimi K3: REFUTED (no extra `)`; all three templates balanced; cited test would pass).
- **`amount_unverified` excludes taproot inputs** — [core/faraday-psbt/src/classify.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/classify.rs) — DeepSeek V4.1: CONFIRMED (taproot excluded; foreign taproot input understated; victim signs own input; combined fee larger); Kimi K3: REFUTED (victim’s economic position unchanged; excess fee funded by attacker; taproot exclusion sound for victim-owned case).
- **Silent payment script check accepts sorted order** — [core/faraday-psbt/src/silent.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/silent.rs) — Kimi K3: CONFIRMED (receiver assigns k in tx order; sorted order may not match; standard wallets may not credit; “unspendable” slightly strong); GLM 5.3: REFUTED (receiver computes P_k and matches by value; findability symmetric; no unspendable risk).
- **`MusigSession` drop does not wipe held secret nonces** — [core/faraday-psbt/src/musig.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/core/faraday-psbt/src/musig.rs) — Kimi K3: PARTLY (Drop only zeroizes seed; doc false; but held nonce never signed under; no key recovery); GLM 5.3: PARTLY (same; real hygiene/doc bug, not key-recovery path).
- **`forms_in` defines a seed-file form for the software stick** — [faraday/faraday-core/src/board/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/board/mod.rs) — DeepSeek V4.1: PARTLY (code observation correct; every in-chunk caller gated by `takes()`; exploit needs crafted plan; high overstated); Kimi K3: PARTLY (all code claims verify; no in-chunk path creates placement; high/exploit unsupported; defense-in-depth note).
- **`Parts` pre-allocates 32 slots to avoid leaking shares on realloc, but no cap enforces it** — [faraday/faraday-core/src/forms.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/forms.rs) — DeepSeek V4.1: PARTLY (pre-allocation real; push path not shown; leak not established); GLM 5.3: PARTLY (code observations accurate; push sites not in chunk; exotic precondition; leak not demonstrated).
- **`held_clear_marks` returns early for all remaining vaults when session key info is missing** — [faraday/faraday-core/src/held.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/held.rs) — DeepSeek V4.1: REFUTED (precondition cannot occur; `released` built with `info(k)?`; check is dead code); GLM 5.3: REFUTED (same; synchronous call; no key removal; unreachable).
- **`inbox_load` reads the skip set after `mem::take`** — [faraday/faraday-core/src/inbox.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/inbox.rs) — DeepSeek V4.1: MISSING; Kimi K3: CONFIRMED (reason supplied is about `found_in` PBKDF2, not the skip bug; retained as supplied).
- **`found_in` derives a BIP-39 seed for every words-file × passphrase-file pair** — [faraday/faraday-core/src/inbox.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/inbox.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Unbounded `places` in a saved plan causes a huge allocation or panic** — [faraday/faraday-core/src/plan/text.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/text.rs) — Kimi K3: MISSING; GLM 5.3: PARTLY (parser behavior real; allocation before validation; crafted plan record reachability unproven; DoS only).
- **`seen_rows` overflows on a `vault`/`sticks` line numbered `usize::MAX`** — [faraday/faraday-core/src/plan/text.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/text.rs) — Kimi K3: MISSING; GLM 5.3: PARTLY (code claim accurate; crafted plan record reachability unverified).
- **Seeds are matched to wallet slots by 32-bit fingerprint only** — [faraday/faraday-core/src/restore.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/restore.rs) — DeepSeek V4.1: MISSING; GLM 5.3: PARTLY (slicing hazard real; cosigner text source not shown; malformed/non-ASCII reachability unproven).
- **`merge()` silently drops a share’s key when its fingerprint duplicates a kept key** — [faraday/faraday-core/src/restore.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/restore.rs) — DeepSeek V4.1: MISSING; GLM 5.3: PARTLY (visible gaps real; impact depends on `secret_text` coverage not shown).
- **`Answers::from_text` trusts the `places` count before allocating stick rows** — [faraday/faraday-core/src/plan/text.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/text.rs) — DeepSeek V4.1: MISSING; GLM 5.3: CONFIRMED (all code claims hold; `ScanState` Drop zeroizes only frame; UR/BBQr buffers persist; `keep_parts` moves them; low).
- **`from_text` map validation accepts seed material at `software`/`away` spots** — [faraday/faraday-core/src/plan/text.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/text.rs) — DeepSeek V4.1: MISSING; GLM 5.3: CONFIRMED (code does; >16 places makes `groups` empty and `rebuilds` vacuously true; `add_place` no cap; low).
- **Panicking byte-slice on cosigner text: `&t[1..9.min(t.len())]`** — [faraday/faraday-core/src/screens/create.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/create.rs) — DeepSeek V4.1: MISSING; GLM 5.3: PARTLY (code claim accurate; `reach_on` combinatorial hang; precondition unrealistic; crafted-plan reachability unverified).
- **`pasted_secret` misses non-English wordlists and 15/18/21-word SeedQR digit strings** — [faraday/faraday-core/src/scan_key.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/scan_key.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`ScanState` zeroizes camera frames but not UR/BBQr partial-assembly buffers** — [faraday/faraday-core/src/qr_view.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/qr_view.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`hand_out()` reports `rebuilds: true` with zero groups verified when the plan has more than 16 places** — [faraday/faraday-core/src/plan/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/mod.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`reach_on()`’s subset search has no step budget** — [faraday/faraday-core/src/plan/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/mod.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Unvalidated seed index in a plan’s “part” line causes an out-of-bounds panic** — [faraday/faraday-core/src/plan/text.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/text.rs) — DeepSeek V4.1: MISSING; Kimi K3: PARTLY (reason supplied is about `Receipt::decode`; decode behavior real; exploit chain unverified).
- **Receipt “verified” flags are read from kept-state text with no integrity check** — [faraday/faraday-core/src/receipt.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/receipt.rs) — DeepSeek V4.1: MISSING; Kimi K3: PARTLY (decode behavior real; reachability and gate use unverified; two lookup helpers need hashes).
- **Unbounded “places” answer in a crafted plan allows memory-exhaustion abort** — [faraday/faraday-core/src/plan/text.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/plan/text.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Multisig shares from every open vault are silently merged into the restored wallet** — [faraday/faraday-core/src/restore.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/restore.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **P2TR multisig is rebuilt from shares by an untested hand-rolled descriptor** — [faraday/faraday-core/src/restore.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/restore.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Receipt “verified” flags are read from kept-state text with no integrity check; crafted vault can forge a “written and verified” receipt** — [faraday/faraday-core/src/receipt.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/receipt.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Files screen loads keys while a stick is attached, bypassing `may_load_keys`** — [faraday/faraday-core/src/screens/files.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/files.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Restore offers Type the words and Scan a SeedQR while a stick is attached** — [faraday/faraday-core/src/screens/restore.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/restore.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Wallet key scanner offers Type the words while a stick is attached** — [faraday/faraday-core/src/screens/sheets.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/sheets.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Text and unknown files are classified Public though they may hold a secret** — [faraday/faraday-core/src/secrets.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/secrets.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Spend panel reports Change: Verified when an unverified change output is also present** — [faraday/faraday-core/src/screens/spend.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/spend.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Review labels legacy P2SH txid as unchanged by signing** — [faraday/faraday-core/src/screens/spend.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/spend.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Vault file not in `vault_files` opens vault 0** — [faraday/faraday-core/src/screens/files.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/files.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **“Txid unchanged by signing” label decided by Debug-string matching on `ScriptKind`** — [faraday/faraday-core/src/screens/spend.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/spend.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **SeedQR passphrase sheet silently accepts only printable ASCII** — [faraday/faraday-core/src/seeds/read.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/seeds/read.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Vault rows matched by file name, silently defaulting to vault index 0** — [faraday/faraday-core/src/screens/files.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/files.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Txid-mutability label in the Spend review decided by matching Debug-formatted enum names** — [faraday/faraday-core/src/screens/spend.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/screens/spend.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Silent payments wallet record’s scan key is not verified** — [faraday/faraday-core/src/silent/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/silent/mod.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Closing or locking vaults leaves secret-bearing UI state in memory** — [faraday/faraday-core/src/vault/area.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/area.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Diceware passphrase is concatenated without a separator and its strength is overstated** — [faraday/faraday-core/src/vault/dice.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/dice.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Boot-stick settings file can set idle lock/off despite the module saying it never can** — [faraday/faraday-core/src/stick/settings.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/stick/settings.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Upgrade offers any boot partition, not only Faraday sticks, and does not exclude the source disk** — [faraday/faraday-core/src/upgrade/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/upgrade/mod.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Seed-entry fingerprint cache is not cleared when the BIP-39 passphrase changes** — [faraday/faraday-core/src/state.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/state.rs) — Kimi K3: MISSING; GLM 5.3: MISSING.
- **Set the time marks the clock checked and stores a nonsense offset when no clock reading has arrived** — [faraday/faraday-core/src/set_time.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/set_time.rs) — DeepSeek V4.1: PARTLY (code asymmetry real; precondition narrow startup race; impact depends on `set_clock`/`clock_now`; core issue real); Kimi K3: MISSING.
- **Receive passes the file name carried by a scanned QR code to `SaveDownload` unsanitized** — [faraday/faraday-core/src/transfer/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/transfer/mod.rs) — DeepSeek V4.1: PARTLY (core claim accurate; write-outside-Downloads needs shell join behavior not shown); Kimi K3: MISSING.
- **Zeroing the whole files partition destroys every vault with a plain press, where deleting one vault file requires a hold** — [faraday/faraday-core/src/stick/wipe.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/stick/wipe.rs) — DeepSeek V4.1: CONFIRMED (accurate; `delete_holds()` only for `.ofv`; `What::Whole` uses ordinary DeleteGo; warnings present but hold asymmetry real); Kimi K3: MISSING.
- **Vault detail screens decrypt secrets every frame without checking `may_load_keys`** — [faraday/faraday-core/src/vault/screen.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/screen.rs) — Kimi K3: MISSING; GLM 5.3: CONFIRMED (verified; `Focus::Prompt`/`Field` accept typing while `may_load_keys()` false; `LoadWithPassphrase`/`ExportKdbx` set `Prompt` unconditionally; low).
- **GPG and Secure Boot private-key operations run with a stick attached** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — Kimi K3: MISSING; GLM 5.3: CONFIRMED (verified; `Purpose::KeyPassphrase` calls `load_key_with_passphrase` with no `may_load_keys` check; sibling `pass_seed_try` has it; low).
- **Vault key loading bypasses the stick-attached guard** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — Kimi K3: MISSING; GLM 5.3: CONFIRMED (verified; `item_heading()` for NOTE reveals first line into list title; detail view hides behind hold; inconsistency real; low).
- **Secret prompt and entry fields accept typing with a stick attached** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — Kimi K3: MISSING; GLM 5.3: CONFIRMED (verified; `vault_import_entries` checks `fits`, `vault_scanned_entry` does not; missing capacity check real; medium).
- **Seed word entry and backup copy check accept typing with a stick attached** — [faraday/faraday-core/src/word_entry.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/word_entry.rs) — Kimi K3: MISSING; GLM 5.3: CONFIRMED (verified; `TextBox.text` plain `String`; passphrase cleared with `String::clear`; form/prompt secrets dropped unzeroized; low).
- **Locked vault is marked done without its seed’s BIP-39 passphrase** — [faraday/faraday-core/src/wallet_backup.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/wallet_backup.rs) — Kimi K3: CONFIRMED (every element verified; `Focus::Prompt` bypasses stick guard; `vault_prompt_go` lacks `may_load_keys`; high); GLM 5.3: MISSING.
- **Scanned entries are inserted without a slot-size check** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — Kimi K3: CONFIRMED (verified; `Focus::Field` not in stick guard; `V::Add`/`V::Edit` no `may_load_keys`; form prefills secrets; low); GLM 5.3: MISSING.
- **Stick visit ignores `keep_as` for a different vault and mislabels same-length vaults** — [faraday/faraday-core/src/visit_taken.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/visit_taken.rs) — Kimi K3: CONFIRMED (verified; `gpg_files` serves cached hash; `gpg_code` signs current bytes without re-hash; hold path re-hashes; medium); GLM 5.3: MISSING.
- **Collecting a cosigner’s PSBT does not verify the sighash type** — [faraday/faraday-core/src/wallet.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/wallet.rs) — Kimi K3: CONFIRMED (verified; `visit_taken` decides SameVault/OtherVault by name+length; `visit_write` uses `replace=true`; `keep_as` never applied; medium); GLM 5.3: MISSING.
- **One visit can write two different bytes under one vault name** — [faraday/faraday-core/src/visit_taken.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/visit_taken.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Vault overwrite decided by name+length only; `OtherVault keep_as` is dead code; `replace=true` queued for any Outbox vault** — [faraday/faraday-core/src/visit_taken.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/visit_taken.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **“Nothing secret is typed while a stick is attached” is only enforced for Passphrase/Phrase/Dice focus** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`Purpose::KeyPassphrase` loads a seed into the session without the `may_load_keys()` check** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Note list title shows the first 40 characters of the secret note text in the clear** — [faraday/faraday-core/src/vault/screen.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/screen.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`vault_scanned_entry` inserts parsed entries without the slot-capacity check** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Secret `TextBox` contents are cleared with `String::clear()`/dropped rather than zeroized** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **BIP-39 passphrase can be typed and the key loaded while a stick is attached** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Vault entry secrets can be typed, and revealed into the edit form, while a stick is attached** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **GPG signature shown as QR/PNG is made over the file’s current bytes without re-checking the hash** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Outbox vaults are written with `replace=true` under their own name** — [faraday/faraday-core/src/visit_taken.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/visit_taken.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Scanned entries are inserted into the vault without the slot-capacity (`fits`) check** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Argon2 memory feasibility check is skipped when free memory is unknown** — [faraday/faraday-core/src/vault/mod.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-core/src/vault/mod.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Read-only sticks and locked SD cards are misreported as “not handed out yet”** — [faraday/faraday-disk/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-disk/src/lib.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`codex32_with_typed` loads a seed from typed + vault shares with no fingerprint verification** — [faraday/faraday-keys/src/vault.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-keys/src/vault.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **`Volume::rename` erases old directory entries before writing new ones** — [faraday/faraday-fat/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-fat/src/lib.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **`OpenVaults::words_of` ignores its `Reveal` reason** — [faraday/faraday-keys/src/vault.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-keys/src/vault.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Authenticode `image_hash` does not cover inter-section gaps** — [faraday/faraday-sb/src/pe.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-sb/src/pe.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Confirm re-checks id/serial/size but the `WriteOrder` carries the stale device path** — [faraday/faraday-starter/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-starter/src/lib.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`StarterEvent::Written`/`WriteProgress` are applied to whatever `Making` is current and force `Page::Done`** — [faraday/faraday-starter/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-starter/src/lib.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Vault open/seal accept any same-header file; `seal()` copies unopened slots from the presented file** — [faraday/faraday-vault/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-vault/src/lib.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **BitLocker recovery-key sheet is sent to the shell as a PDF under a fixed temp-folder name** — [faraday/faraday-starter/src/notes.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/faraday-starter/src/notes.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Whitespace-malformed `kernel.forbidden` lines silently become dead rules** — [faraday/image/check-kernel-config.sh](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/image/check-kernel-config.sh) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Cached Buildroot checkout is verified by commit only** — [faraday/image/run-build.sh](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/image/run-build.sh) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Desktop Transfer Receive writes secrets (seed words) into `~/Downloads` in plaintext** — [faraday/shells/snapshot/src/tours/transfer.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/snapshot/src/tours/transfer.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Reconfigure staleness check omits generated kernel fragments** — [faraday/image/build.sh](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/image/build.sh) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **BitLocker recovery-key sheet written world-readable in the shared temp dir** — [faraday/shells/starter/src/pdf.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/starter/src/pdf.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **`sweep_key_sheets`/`wipe_dir` follow symlinks when zeroing** — [faraday/shells/starter/src/pdf.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/starter/src/pdf.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **macOS disk identity has an empty serial** — [faraday/shells/starter/src/macos/diskutil.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/starter/src/macos/diskutil.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **macOS write: disk identity verified before image re-hash and authopen prompt, no re-check after open** — [faraday/shells/starter/src/macos/mac.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/starter/src/macos/mac.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Elevated writer accepts arguments from any caller** — [faraday/shells/starter/src/windows/win.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/starter/src/windows/win.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **BitLocker recovery key written to temp directory and opened in external PDF viewer** — [faraday/shells/starter/src/pdf.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/starter/src/pdf.rs) — DeepSeek V4.1: MISSING; Kimi K3: MISSING.
- **Clean/upgrade marker removal failure is recorded as success** — [faraday/shells/stick/src/main.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/stick/src/main.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.
- **Pointer accumulators use plain `i32` arithmetic on device-controlled event values** — [faraday/shells/stick/src/pointer.rs](https://github.com/bitcoinpasada/faraday/blob/11da09a2a5ab36868d782922a2a255390c1b36c1/faraday/shells/stick/src/pointer.rs) — DeepSeek V4.1: MISSING; GLM 5.3: MISSING.

Prepared with DeepSeek V4.1, Kimi K3, GLM 5.3 for EntropyLab's MrHodlX.

