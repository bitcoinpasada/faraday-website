# Audit of Faraday (AI-assisted)

**Repository:** https://github.com/bitcoinpasada/faraday
**Commit:** `baf4c9f34d535783207da797c96492766ae8b323` (`git rev-parse HEAD`)
**Date:** 2026-10-24
**Models:**
- auditors: DeepSeek V4.1 (`deepseek-v4.1-flash-1017`), Kimi K3 (`kimi-k3`) and GLM 5.3 (`glm-5.3`);
- Claude Opus 5.5 (`claude-opus-5-5`) arranged this file and verified the critical and high findings (sent privately) by reading the source.

**Tools run:** none. The models read the source as bundled text. Nothing was built or executed.

## Scope

- **Read:** every `.rs` and `.sh` file in the repository, bundled into chunks, except files under `third_party/`, `fuzz/`, `target/`, `design/`, `docs/`, `tests/`/`test/` and `benches/`. Each chunk went to each of the three auditor models. The areas named in the prompt (`prompt.md`) cover key material, signing, results, the vault, the air gap, untrusted input, the image and its tools, and access.
- **Not read:** tests, documentation, design files, vendored third-party code, fuzz targets, benchmarks, and any file in another language (C, Python, JavaScript, build configuration). The website repository was not read either.
- `docs/AUDIT.md` was not used to steer the scope.

## How the findings were confirmed

- Each finding was reported by one model, then checked against the code by the two models that did not report it.
- **"Confirmed by both checkers"** means both agreed; **"Likely"** means one confirmed and the other partly confirmed.
- **Every finding here was found by reading only. None was confirmed by running code.** These medium and low findings were not individually re-verified by a human.
- Line numbers refer to the commit above. Severities are the checkers' severities on Faraday's scale.
- 139 further findings that a checker refuted are omitted.
- Findings rated critical or high went to the private route (GHSA-7h4m-p8qx-pxrf) and are not in this file. #12, which overlaps one of them, is left out too.

## Findings confirmed by both checkers

### 7. FROST signing copies secret nonce halves into non-zeroizing locals
**Severity:** medium (kimi-k3: medium; glm-5.3: medium) — reporter rated high
**File:** [core/faraday-bip/src/frost.rs:905](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/frost.rs#L905)
**Preconditions:** The device performs a FROST signing operation and an attacker can dump memory afterward.
**Scenario:** `sign` does `let (k1_, k2_) = (secnonce.k1, secnonce.k2); drop(secnonce);` and then derives `k1`/`k2`. `SecNonce` is zeroized on drop, but `k1_`, `k2_`, `k1`, `k2` are plain `[u8;32]` locals never zeroized. `nonce_gen` and `deterministic_sign` similarly build the nonce in a local `k: [[u8;32];2]` and copy it into `SecNonce` without wiping `k` — while explicitly zeroizing the adjacent `seed`.
**Impact:** A leaked nonce lets an attacker forge a partial signature or recover the secret share from a signature, leading to theft.
**Fix:** Keep nonce material in `Zeroizing`/`Secret` wrappers, or explicitly `zeroize()` every local nonce copy before returning.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: every stated fact matches; the miss is inconsistent with the module's own practice; downgraded because exploitation needs a post-operation memory dump.
- glm-5.3 — CONFIRMED: a leaked FROST nonce is the most dangerous residue of this class, though exploitation still requires a memory dump.

---

### 8. FROST dealer and recovery leave secret share copies on the stack
**Severity:** medium (kimi-k3: low; glm-5.3: medium) — reporter rated high
**File:** [core/faraday-bip/src/frost.rs:1188](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/frost.rs#L1188)
**Preconditions:** The device runs the trusted dealer or recovers a share, and an attacker can dump memory.
**Scenario:** `deal` computes `let share = ...` and passes `&share` to `SecShare::from_bytes`, leaving the local unzeroized. `recover_share` returns `SecShare::from_bytes(&held[position].1.secret_bytes())`, leaving the temporary from `secret_bytes()` unzeroized. `interpolate_secret_at` returns `sum` by value, leaving the local `sum` and intermediate secret products on the stack.
**Impact:** Secret shares can be recovered from memory, allowing reconstruction of the group secret or signing authority.
**Fix:** Zeroize every local share and intermediate secret scalar; return `Secret`/`Zeroizing` types from `interpolate_secret_at`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: accurate on all three points; one share alone is insufficient without t of them, hence low.
- glm-5.3 — CONFIRMED: all three claims match the code.

---

### 9. AEZ key schedule leaves extracted subkeys in non-zeroizing locals
**Severity:** medium (kimi-k3: low; glm-5.3: medium) — reporter rated high
**File:** [core/faraday-bip/src/aez.rs:170](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/aez.rs#L170)
**Preconditions:** The device decodes an aezeed, or runs AEZ vectors, and an attacker can dump memory.
**Scenario:** `State::new` copies the extracted 48-byte key into `sub`, then `ik`, `jk`, `lk`, and uses those to build the `State`. `extracted` is zeroized and `State` zeroizes its fields on drop, but `sub`, `ik`, `jk`, `lk` are plain arrays left on the stack.
**Impact:** The AEZ subkeys can be recovered from memory, allowing decryption of the aezeed ciphertext and recovery of the LND node seed.
**Fix:** Zeroize `sub`, `ik`, `jk`, `lk` after the `State` fields are built, or hold them in `Zeroizing`/`Secret` wrappers.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: `extracted` is zeroized but the four derived locals are not; requires a strong dump precondition, hence low.
- glm-5.3 — CONFIRMED: the gap is real against the module's own discipline.

---

### 10. `tapscript_quorum()` counts the internal key in the sortedmulti_a quorum
**Severity:** medium (kimi-k3: medium; glm-5.3: low) — reporter rated medium
**File:** [core/faraday-bip/src/policy.rs:536](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/policy.rs#L536) (also L556)
**Preconditions:** A `tr(xpub, sortedmulti_a(k, ...))` wallet with an internal MultiXPub key is loaded.
**Scenario:** `tapscript_quorum()` returns `(threshold, self.keys.len())` for `sorted_a` unconditionally. `self.keys` includes the internal xpub, so a 2-of-2 leaf with an internal key is reported as 2-of-3, while the internal key alone can spend via the key path. The unsorted `multi_a` branch correctly declines by requiring `leaf.iter_pk().count() == self.keys.len()`; the sorted branch is missing that check.
**Impact:** The review states "t of 3" while one specific key sweeps the wallet alone. A user relying on the quorum line believes t signatures are required. Mitigation: `spend_paths()` does list the key path and `template_text()` shows `@0` inside `tr()`.
**Fix:** Apply the same guard as the `multi_a` branch in the `sorted_a` branch, or return `None` when the internal key is a wallet key.
**Reported by:** deepseek-v4.1-flash-1017 (also reported independently as F21 by glm-5.3)
**Checks:**
- kimi-k3 — CONFIRMED: the parse-time check also uses the inflated count; partially mitigated because `spend_paths()` still lists the key path.
- glm-5.3 — CONFIRMED: only the sorted form is wrong; display/review error only, hence low.

---

### 11. `input_public_key` uses the taproot output key for script-path spends; BIP-352 specifies the control-block internal key
**Severity:** medium (kimi-k3: medium; glm-5.3: medium) — reporter rated medium
**File:** [core/faraday-bip/src/silent.rs:640](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/silent.rs#L640)
**Preconditions:** An external, BIP-352-conforming sender pays the user's silent payment address in a transaction containing at least one P2TR input spent via the script path whose internal key is not NUMS (taproot multisig, Lightning, Liana-style wallets).
**Scenario:** In the `is_p2tr` branch the code removes any annex, checks the control block's internal key only against NUMS (skipping if equal), and otherwise returns the output key from the prevout scriptPubKey. BIP-352 requires the control-block internal key for script-path spends. A conforming sender includes the internal key in the input sum while this receiver includes the output key, so the two compute different `A_sum`, `input_hash` and shared secret, and `scan()`/`find_payments` never matches. The published vectors' script-path cases exercise the NUMS skip, so vectors do not discriminate.
**Impact:** Payments from any transaction containing a non-NUMS script-path taproot input are never detected; the funds sit on-chain, invisible and unspendable until a corrected rescan.
**Fix:** In the `is_p2tr` branch, when the annex-stripped witness has more than one item, parse the control block, skip if its internal key is NUMS, and otherwise return the even-y lift of the internal key; keep the output-key path only for key-path spends. Add a test vector.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the code always returns the prevout output key; recoverable by corrected rescan, so medium.
- glm-5.3 — CONFIRMED: the code behavior is exactly as stated; the NUMS check on the control block only makes sense under the internal-key reading.

---

### 13. `qr_png` leaves the SeedQR module bits in a non-zeroized heap buffer
**Severity:** medium (kimi-k3: medium; glm-5.3: low) — reporter rated medium
**File:** [core/faraday-codec/src/png.rs:40](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-codec/src/png.rs#L40)
**Preconditions:** The application calls `qr_png` on a `QrMatrix` produced from a SeedQR; attacker has physical access or a memory dump.
**Scenario:** `qr_png` builds `raw`, a `Vec<u8>` containing the filtered PNG rows — a copy of every module of the QR code. For a SeedQR those modules are the seed. `raw` is passed to `file()` and dropped without zeroization. `file()` zeroizes its own `data` and `grey_png()` explicitly zeroizes its `raw` ("The picture may be of a secret"), but `qr_png` does not.
**Impact:** Seed material survives the session in freed heap memory; an attacker with memory access can reconstruct the mnemonic.
**Fix:** Zeroize `raw` before returning, exactly as `grey_png` does.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the contrast with `grey_png` is real; an inconsistency in the crate's own hygiene, not a design choice.
- glm-5.3 — CONFIRMED: the returned PNG contains the same seed by design, so the un-wiped intermediate is defense-in-depth, hence low.

---

### 14. `Decoded.bytes` holds SeedQR digits in a plain `Vec<u8>` that is never zeroized
**Severity:** medium (kimi-k3: medium; glm-5.3: medium) — reporter rated medium
**File:** [core/faraday-codec/src/decode.rs:22](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-codec/src/decode.rs#L22)
**Preconditions:** The application scans a SeedQR and keeps or drops the returned `Decoded` value; attacker has physical access or a memory dump.
**Scenario:** `read()` does `let mut bytes = Vec::new(); grid.decode_to(&mut bytes)` and stores it in `Decoded { bytes, kind }`. For a SeedQR the bytes are the 48/96 decimal digits, i.e. the seed. `Decoded` is a plain struct with no `Drop`/zeroize, contradicting the crate-level doc that SeedQR payloads live in `Secret` wrappers.
**Impact:** The seed's digit stream remains in freed heap memory after a scan, allowing reconstruction of the mnemonic.
**Fix:** Wrap the payload in a zeroizing type when the kind is SeedQr/CompactSeedQr, or add a `Drop` impl to `Decoded`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the substantive claim about decode.rs is exactly what the code does; the quoted lib.rs doc and `seedqr::from_digits` are outside the provided files.
- glm-5.3 — CONFIRMED: the contrast with the documented promise makes this a genuine gap; the compact digit bytes are a direct, easily parsed seed copy.

---

### 15. Multisig parser accepts a key push before `OP_m`, misclassifying non-standard scripts
**Severity:** medium (kimi-k3: low; glm-5.3: medium) — reporter rated medium
**File:** [core/faraday-psbt/src/classify.rs:150](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-psbt/src/classify.rs#L150)
**Preconditions:** A malicious coordinator supplies a PSBT spending a p2wsh/p2sh UTXO with a script of the form `<key> OP_m <keys> OP_n OP_CHECKMULTISIG`.
**Scenario:** `Multisig::parse` matches `PushBytes(bytes) if n.is_none()` before checking that `m` has been set. `<key1> OP_2 <key2> OP_2 OP_CHECKMULTISIG` parses as a standard 2-of-2, is classified as `ScriptKind::Multisig`, and the finalizer builds `OP_0 <sig1> <sig2> <script>`, which cannot satisfy the script.
**Impact:** The user approves and signs a transaction that cannot be spent. Funds are not lost, but the payment fails and the user may believe it succeeded.
**Fix:** Enforce the exact grammar: `OP_m` first, exactly `n` key pushes, `OP_n`, `OP_CHECKMULTISIG`; reject any other order.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the match-arm order is as claimed; CHECKMULTISIG would pop 0x02 as a pubkey and fail; medium overstates it.
- glm-5.3 — CONFIRMED (reason given describes the UR decoder growth issue): no bound on parts accepted; `received`/`buffer` grow linearly with attacker input until allocation fails, and the abort skips zeroize-on-drop.

---

### 16. `sign()` does not zeroize the nonce seed
**Severity:** medium (kimi-k3: medium; glm-5.3: low) — reporter rated medium
**File:** [core/faraday-psbt/src/sign.rs:228](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-psbt/src/sign.rs#L228)
**Preconditions:** Any signing call; memory disclosure after signing.
**Scenario:** `sign` takes `seed: [u8;32]` by value and never zeroizes it. The seed derives MuSig2 and threshold nonces. It remains on the stack after the call.
**Impact:** An attacker who reads memory can recompute nonces and derive keys from signatures.
**Fix:** Take `Zeroizing<[u8;32]>` or zeroize `seed` at the end of `sign`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: every nonce of the pass is recomputable from this seed; gated on a memory-disclosure primitive, hence medium.
- glm-5.3 — CONFIRMED (reason given describes `lock_met`): CLTV fails on a final nSequence and CSV fails for nVersion < 2, but `lock_met` checks neither, so the TimelockNotMet caution can be missed.

---

### 17. `CarryEntry::drop` zeroizes the (public) sighash but not the secret nonce
**Severity:** medium (kimi-k3: medium; glm-5.3: medium) — reporter rated medium
**File:** [core/faraday-psbt/src/threshold.rs:270](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-psbt/src/threshold.rs#L270)
**Preconditions:** A `CarryEntry` is dropped outside `CarrySection`'s drop — via `CarrySection::take()`, or when `CarrySection::parse` fails after some entries were read.
**Scenario:** `impl Drop for CarryEntry` runs only `self.sighash.zeroize()`; the 64-byte secnonce — the actual secret — is left in freed heap memory, contradicting the type's own "wiped on drop" contract.
**Impact:** Residual FROST secret nonces in memory; each recoverable nonce plus its public partial signature yields one secret share.
**Fix:** Make `CarryEntry::drop` call `self.zeroize()`.
**Reported by:** kimi-k3
**Checks:** both checkers CONFIRMED. Their recorded notes concerned a different finding and are omitted.

### 18. Scanned entries are inserted into an open vault without checking the slot size
**Severity:** medium (kimi-k3: low; glm-5.3: low) — reporter rated medium
**File:** [faraday/faraday-core/src/vault/mod.rs:1900](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/vault/mod.rs#L1900)
**Preconditions:** An open vault; attacker can show a QR code containing many `field: value` entries to the camera.
**Scenario:** `vault_scanned_entry` parses the entries and calls `self.vaults.edit(id, |s| { for r in records { s.insert(id, r); } })` without the `fits` check used by `vault_import_entries`. Records can exceed the slot length; sealing can then fail and `vault_seal_all` silently skips the vault, after which `close_all()` wipes it.
**Impact:** Vault data loss or corruption; changes made in the session may not be sealable.
**Fix:** Check `fits` before inserting, as `vault_import_entries` does, and refuse with a toast.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the missing pre-check is real; the supported failure mode is seal failure/loss of changes, not an unreopenable vault.
- glm-5.3 — CONFIRMED (reason given describes the words-buffer sizing issue): the buffer is sized 9 bytes per word, correct only for English; multi-byte wordlists force a reallocation that leaves an unwiped copy.

---

### 19. FAT16 volumes with more clusters than the 16-bit FAT can address are accepted, causing FAT entry truncation and cross-file corruption
**Severity:** medium (kimi-k3: medium; glm-5.3: low) — reporter rated high
**File:** [faraday/faraday-fat/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-fat/src/lib.rs) (`Volume::open`, `Kind::Fat16` branch; `fat_set`)
**Preconditions:** Attacker supplies a FAT16 stick with more than 65524 clusters (e.g. 1 GiB with 512-byte clusters). The app opens it and writes a file.
**Scenario:** `Volume::open` accepts `Kind::Fat16` for any cluster count >= 4085 with no upper bound. `free_clusters` can return cluster numbers > 65535. `store` writes data and calls `fat_set(c, next)`, which for FAT16 writes `(v as u16)`, truncating the pointer. The read-back fails; `put_checked` calls `place.remove(temp)`, which calls `free_chain` and follows the truncated chain into another file's clusters, zeroing their FAT entries.
**Impact:** Loss or corruption of other files on the stick, including vault backups or wallet files.
**Fix:** Reject FAT16 when `clusters > 0xFFF5`; make `fat_set` return `Error::Corrupt` if `v > 0xFFFF`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: every claim checks out; the FAT32 branch has the bound the FAT16 branch lacks; the crafted-stick precondition matches the module's threat model.
- glm-5.3 — CONFIRMED (reason given describes `zero_leftovers`): a chain longer than the size makes the code zero the wrong cluster's tail, leaving the real tail unwiped.

---

### 20. A partially read frame is dropped without zeroizing, leaving secret bytes in the long-lived disk process
**Severity:** medium (kimi-k3: low; glm-5.3: medium) — reporter rated medium
**File:** [faraday/faraday-files/src/proto.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-files/src/proto.rs) (`receive`)
**Preconditions:** A frame carrying a secret is partially read and then the pipe errors or closes.
**Scenario:** `receive()` allocates `vec![0u8; len]` and calls `r.read_exact(&mut buf)?`; on a mid-frame error the partially filled buffer is dropped without zeroization. This contradicts the module's documented wipe discipline, and the disk process is documented to live across app locks.
**Impact:** Secret outlives the session; may be recoverable from process memory.
**Fix:** Use `zeroize::Zeroizing<Vec<u8>>` for `buf`, or zeroize it on the error path.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the module doc explicitly says a file in transit may be a seed in the clear; the remnant outlives the session.
- glm-5.3 — CONFIRMED (reason given describes entry notes): NOTES is fetched as a secret but rendered with `field_row` while PASSWORD/TOTP use `hold_row`.

---

### 21. A file whose FAT chain is longer than its size leaves the actual tail unwiped
**Severity:** medium (kimi-k3: low; glm-5.3: medium) — reporter rated low
**File:** [faraday/faraday-fat/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-fat/src/lib.rs) (`zero_leftovers`)
**Preconditions:** A malicious or corrupt FAT has a file whose chain has more clusters than its size requires; the user runs zero free space.
**Scenario:** `zero_leftovers` computes `tail = size % cluster_bytes` and uses `chain.last()` as the last cluster. If the chain is longer than the file, the actual last cluster is `chain[size / cluster_bytes]`, so the wrong cluster's tail is zeroed and the real tail survives. The over-long chain's extra clusters are allocated, so `zero_free` skips them too.
**Impact:** Secret data not wiped; the user believes zeroing succeeded.
**Fix:** Compute the cluster index from the file size and use `chain[index]`, or validate chain length against size and fail closed.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: no live data is corrupted; the impact is exactly incomplete wiping.
- glm-5.3 — CONFIRMED (reason given describes wallet-name sanitization): `sheet_wallet` writes `name: {wallet.name}` unsanitized while `config()`/`wallet_json()` sanitize; a newline injects fake lines ahead of the genuine ones.

---

### 22. Crafted plan text can panic the signer via out-of-range seed indices
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated medium
**File:** [faraday/faraday-core/src/plan/mod.rs:1300](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/plan/mod.rs#L1300)
**Preconditions:** Attacker supplies a crafted vault or backup containing a plan record with a `part` line or an `exposed` note whose seed index is >= the wallet's seed count; the user opens the plan or chart.
**Scenario:** `Answers::from_text` accepts `part <place> <seed>` without checking `<seed> < shape.seeds.len()`. `with_parts` then adds `What::SeedQr(seed)`, and `Have::add` does `self.seeds[i] = true` without bounds checking. `Note::from_text` accepts `exposed place0 seed999` and reaches the same path. The spot-line path *is* shape-validated; a `lost` note does not panic.
**Impact:** Denial of service: the offline signer crashes when the crafted plan is opened.
**Fix:** Validate every index against the `Shape` before storing; make `Have::add` use `get_mut`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the unvalidated paths are correctly identified; fail-closed crash only.
- glm-5.3 — CONFIRMED (reason given describes the unbounded `places` allocation): `places` is unbounded and the allocation runs before any fit check.

---

### 23. Crafted plan text can exhaust memory with an unbounded place count
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-core/src/plan/mod.rs:1250](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/plan/mod.rs#L1250)
**Preconditions:** Attacker supplies a crafted plan text with a huge `places` value; the user opens the plan.
**Scenario:** `Answers::from_text` parses `places` with no upper bound and later allocates `a.sticks = vec![vec![false; a.places]; rows]` before any validation. `places 1000000000` attempts ~1 GB and aborts on allocation failure; the later `fits` check has no upper bound and passes for a consistent huge value.
**Impact:** Memory exhaustion and crash/denial of service.
**Fix:** Clamp or validate `places` against `max_places(shape)` before allocating.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the allocation runs before the `fits` check; fail-closed DoS.
- glm-5.3 — CONFIRMED (reason given describes `hand_out`): with `places > 16` the `rebuilds` closure is vacuously true and the result is returned with `rebuilds: true` although no group was checked.

---

### 24. SLIP-39 share value and word indices left in unzeroized stack buffers in `Share::from_indices` / `Share::parse`
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [core/faraday-bip/src/slip39.rs:525](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/slip39.rs#L525) (also L575)
**Preconditions:** Physical access to the device or any memory-disclosure primitive; the user parses SLIP-39 shares.
**Scenario:** `Share::from_indices` decodes into a stack local `value` and copies it into `SecretBytes`, but the 40-byte buffer is never zeroized. `Share::parse` builds `indices` (the entire share as word indices) and passes it to `from_indices` without zeroizing it. Every other buffer in the file is explicitly zeroized.
**Impact:** Share value and its word-index encoding persist in stack memory after parsing.
**Fix:** Zeroize `value` and `acc` in `from_indices`, and `indices` in `Share::parse`, on all return paths.
**Reported by:** kimi-k3 (also reported independently as F23 by glm-5.3)
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: both locals hold share secret material; same issue as F23.
- glm-5.3 — CONFIRMED: a genuine deviation from the file's own rule.

---

### 25. Secret scalars left in stack locals across the MuSig2 signing path
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [core/faraday-bip/src/musig.rs:1050](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/musig.rs#L1050)
**Preconditions:** Physical access or a memory-disclosure primitive; the user performs a MuSig2 signing session.
**Scenario:** `SecNonce` is non-Clone and wiped on drop, but the signing functions copy the same secrets into plain locals never wiped: `deterministic_sign` has `seed = sk.secret_bytes()` and the `k` array; `nonce_gen` has `seed` and `k`; `sign()` has `k1`/`k2`, `d0 = sk.secret_bytes()` and `d`.
**Impact:** Private key and secret nonce material persists in stack memory after signing.
**Fix:** Zeroize the locals on every exit path, including early-error returns.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: all named locals are unwiped and are key/nonce/effective-scalar material.
- glm-5.3 — CONFIRMED: contradicts the module's own hygiene; no direct leak path in normal operation.

---

### 26. `read()` classifies a hex string that is also valid Base58 as Base58, not Hex
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [core/faraday-codec/src/encodings.rs:70](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-codec/src/encodings.rs#L70)
**Preconditions:** A caller uses `encodings::read()` to interpret user-supplied text as bytes and relies on the returned `encoding`/`bytes`.
**Scenario:** `read()` tries bech32, base58check, plain base58, then hex. `"deadbeef"` fails the first two but is valid plain Base58, so `base58::decode` succeeds and the hex branch is never reached. Any even-length hex string without a `0` digit is misclassified (~1.6% of random 32-byte hex strings). The module doc claims the order "cannot mistake a string for something else".
**Impact:** A caller expecting hex gets different bytes and a different encoding tag; wrong key/seed or a misparsed PSBT fragment.
**Fix:** Try `from_hex` before plain `base58::decode`; add a test that `read("deadbeef")` is Hex.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the behavior is exactly as described; impact is caller-dependent.
- glm-5.3 — CONFIRMED: the doc claim is wrong for the hex/Base58 pair; failure mode is deterministic misparse.

---

### 27. `xpriv_from_bytes` creates a temporary `SecretKey` for validation that is not erased
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [core/faraday-bip/src/xkey.rs:160](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/xkey.rs#L160)
**Preconditions:** The user imports an xprv/tprv as text; attacker has physical access or a memory dump.
**Scenario:** `xpriv_from_bytes` validates the scalar with `SecretKey::from_slice(&bytes[46..])` and discards the result. `secp256k1::SecretKey` is `Copy` and does not implement `Drop`, so the 32-byte private key is left on the stack. `decode_xpriv` zeroizes `bytes`, but the temporary is not erased, contradicting the module doc.
**Impact:** A copy of the imported private key can remain in stack memory.
**Fix:** Validate without a copying temporary, call `non_secure_erase`, or wrap in a zeroizing type.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the doc's erasure claim does not cover the `SecretKey` temporary.
- glm-5.3 — CONFIRMED: defense-in-depth gap; the same key is intentionally returned in the `Xpriv`.

---

### 28. Failed `mlock` is only reported once and secrets continue unpinned
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated medium
**File:** [core/faraday-crypto/src/pinned.rs:200](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-crypto/src/pinned.rs#L200)
**Preconditions:** `RLIMIT_MEMLOCK` is too small, or `mlock` fails for another reason.
**Scenario:** `raw::hold` calls `sys::lock`; on failure it records the failure in `PIN_FAILURE` and carries on with the secret in pageable memory. The shell may print one stderr line, but the secret can reach swap.
**Impact:** Secrets may survive in swap or be recoverable from disk, violating the air-gap and secret-lifetime guarantees; the warning may be missed.
**Fix:** Fail closed when `mlock` fails for a secret, or surface a prominent persistent warning with a way to abort.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the behavior is as described and explicitly documented as intentional; residual risk is real but disclosed.
- glm-5.3 — CONFIRMED (reason given describes the `Sealed::with` panic path): a panic in the closure leaves the plaintext unzeroized for `[u8;64]` seeds, which have no `Drop`.

---

### 29. `tapscript_quorum()` for a sortedmulti_a wallet hides that the internal key alone can spend
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated medium
**File:** [core/faraday-bip/src/policy.rs:556](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/policy.rs#L556)
**Preconditions:** As finding 10.
**Scenario:** As finding 10; this is the same defect reported separately with the emphasis on the hidden key path.
**Impact:** As finding 10.
**Fix:** As finding 10.
**Reported by:** glm-5.3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the sorted branch lacks the unsorted branch's leaf-key-count check; `spend_paths`/`template_text` mitigate.
- kimi-k3 — CONFIRMED: the asymmetry claim is correct; the quorum line states a false fact about who can spend.

---

### 30. `strip()` panics on crafted input via unchecked slice indexing
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-apk/src/sign.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-apk/src/sign.rs) (`strip`)
**Preconditions:** Crafted APK input reaching `strip`.
**Scenario:** `signed[start..block_start]` panics when `block_start > len`; `signed[cd_off..eocd_at]` panics when `cd_off > eocd_at`; `block_size + 8` can overflow `usize`. `cd_off` is bounded above only by the `.get()` probe, which permits `cd_off` up to `len + 16`.
**Impact:** Denial of service on crafted input.
**Fix:** Use checked arithmetic and `get()`-based slicing.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the function itself is vulnerable; the caller is not in the chunk.
- glm-5.3 — CONFIRMED: the function does exactly this on crafted input; DoS only.

---

### 31. `prevout_of` accepts prevout scripts without verifying `non_witness_utxo`'s txid
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [core/faraday-psbt/src/transaction.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-psbt/src/transaction.rs) (`prevout_of`)
**Preconditions:** Crafted PSBT.
**Scenario:** `prevout_of` takes the prevout script from `witness_utxo` or `non_witness_utxo.output[vout]` without checking the previous transaction's txid against `previous_output.txid`, while `add_previous` does verify. A substituted script changes the derived input pubkeys and the silent-payments shared secret.
**Impact:** The "did I get paid" check can be lied to; check-flow misinformation only.
**Fix:** Verify the txid in `prevout_of`, as `add_previous` does.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the inconsistency with `add_previous` is real.
- glm-5.3 — CONFIRMED: a crafted PSBT can substitute prevout scripts; no signing impact.

---

### 32. `SIGHASH_SINGLE` is only a Caution, so it signs with no override
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated high
**File:** [core/faraday-psbt/src/inspect.rs:985](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-psbt/src/inspect.rs#L985)
**Preconditions:** Malicious coordinator PSBT; the user approves a review showing only a caution.
**Scenario:** `inspect()` classifies `SIGHASH_SINGLE` (and `SINGLE|ANYONECANPAY`) as neither `is_none()` nor `NonStandard` nor default, so it lands in the Caution branch. `sign()` refuses only Blocked always and Danger without force, so a Caution signs with no override. The signature commits only to output i; the coordinator can replace every other output. For a legacy/p2sh input with `i >= outputs.len()`, the consensus one-hash bug makes the signature valid for any transaction carrying that input.
**Impact:** Theft of the change / redirection of everything except output i; in the legacy out-of-range case, theft of the entire input.
**Fix:** Classify SINGLE and SINGLE|ANYONECANPAY as Danger at minimum; classify the legacy one-hash case as Blocked. Display exactly which output is committed to.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the ladder ranks SINGLE as Caution; the coordinator can replace all outputs.
- glm-5.3 — CONFIRMED: the classification and the legacy out-of-range behavior both hold.

---

### 33. SeedQR words copied into a non-zeroizing `String` during boot import
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-core/src/boot_import/mod.rs:330](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/boot_import/mod.rs#L330)
**Preconditions:** A PNG on the boot stick contains a SeedQR and the boot import reads it.
**Scenario:** `import_codes` calls `crate::seedqr_words(&p)`, which returns the words as a `String`. The payload bytes are zeroized, but the returned `String` is only borrowed for `words.as_bytes().to_vec()` and dropped without zeroization.
**Impact:** Seed words remain in freed heap memory after the import.
**Fix:** Return/consume the words in a zeroizing type and wipe after building the item.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the words are also retained as an Item, so this is additional residue rather than the only copy.
- glm-5.3 — CONFIRMED (reason given describes vault import eviction): a same-named vault file silently deletes an existing Files entry.

---

### 34. Typed secret copied into a plain `String` when drawing Add a key's other forms
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-core/src/compact/screen.rs:520](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/compact/screen.rs#L520)
**Preconditions:** On a small panel, the user types a share/seed/part into Add a key's non-words form.
**Scenario:** `entry_form` does `let mut t = app.entry.typed.to_string();` and pushes the caret char, producing a plain `String` copy of the secret that is dropped without zeroization after `ui.wrap`.
**Impact:** The typed secret remains in freed heap memory, contrary to the `SecretText` discipline.
**Fix:** Draw from the `SecretText` directly, or use `Zeroizing<String>`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: matches the finding exactly; transient heap residue recreated per frame.
- glm-5.3 — CONFIRMED (reason given describes the boot-import SeedQR words): a wipe-hygiene break, not a practical remote exposure.

---

### 35. `Volume::rename` erases the old directory entries before writing the new ones
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-fat/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-fat/src/lib.rs) (`Volume::rename`)
**Preconditions:** A rename whose `write_entries` fails after the erase (full root directory, name-collision exhaustion, I/O error).
**Scenario:** `rename` does `erase_entries(&e)?; write_entries(to, e.cluster, e.size)` with no rollback. The file's directory entries are destroyed while its clusters stay allocated — leaked and unreferenced. `create()` has the equivalent rollback (`free_chain`); `rename()` does not.
**Impact:** The file is lost; the error text does not reveal it.
**Fix:** Roll back by rewriting the old entries, or free the chain on failure.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the error list is partly wrong (`check_name` runs before the erase) but the defect is real.
- glm-5.3 — CONFIRMED (reason given describes the note-title exposure): a note's first line becomes its visible title.

---

### 36. `finish_vault_writes` and `faraday_files::rename` read a stick file at its listed size, bypassing `MAX_READ`
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-files/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-files/src/lib.rs) (`finish_vault_writes`, `rename`)
**Preconditions:** A crafted stick with a hidden `.faraday-*.ofv.part` of huge size (up to 4 GiB on FAT).
**Scenario:** Both paths pass the file's own listed size as the read cap; `Volume::read`'s only check (`e.size > max`) is vacuous when `max` equals the listed size, so `vec![0u8; size]` allocates up to ~4 GiB. Allocation failure aborts the process.
**Impact:** Denial of service on the signer; the disk process dies.
**Fix:** Cap the read to `MAX_READ`, or read only the header and the length needed.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: both paths allocate the full listed size; DoS only.
- kimi-k3 — CONFIRMED: the abort needs no panic handler to be fatal.

---

### 37. `read_signature` panics on a certificate table whose `dwLength` is less than 8
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-sb/src/pe.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-sb/src/pe.rs) (`read_signature`)
**Preconditions:** A crafted signed image with `dwLength` in 0..7.
**Scenario:** `read_signature` does `&table[8..u32_at(table, 0)?.min(table.len())]`. `u16_at(table, 6)` guarantees `len >= 8`, so `dwLength` 0..7 makes the range invalid and the slice index panics. `check`'s `unwrap_or` catches `None`, not panics.
**Impact:** Reachable panic on a crafted image; fails closed.
**Fix:** Clamp the end to at least 8, or use `get()`.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the range is invalid for `dwLength` 0..7.
- glm-5.3 — CONFIRMED: the panic precedes the `None` → `Unreadable` path.

---

### 38. `sign()` panics when the existing certificate table starts inside the headers
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-sb/src/pe.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-sb/src/pe.rs) (`sign`)
**Preconditions:** A crafted image whose certificate-table offset lies inside the headers.
**Scenario:** `layout()` accepts a certificate-table offset inside the headers as long as `cert_at + cert_size <= pe.len()`. `sign()` then truncates to `cert_at` and indexes `cert_dir..cert_dir + 8`, which panics when `cert_at < cert_dir + 8`.
**Impact:** DoS of the signing tool on malformed input; no signature produced.
**Fix:** Require `cert_at >= cert_dir + 8` in `layout()`.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: `layout()` accepts the offset; `sign()` panics.
- glm-5.3 — CONFIRMED: larger bogus offsets fail with `Err`; only the in-header case panics.

---

### 39. `unix_of` accepts out-of-range hours, minutes and seconds in certificate times
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-sb/src/x509.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-sb/src/x509.rs) (`unix_of`)
**Preconditions:** A crafted certificate with an impossible time.
**Scenario:** `unix_of` checks month 1..=12, day 1..=31 and the trailing `Z`, but never bounds hours, minutes or seconds. `25:99:99` is accepted and folded in; February 31 is normalized rather than rejected.
**Impact:** Fail-open parsing wart; no caller in the shown code makes a validity decision from `not_before`.
**Fix:** Bound hours 0..=23, minutes/seconds 0..=59, and validate the day against the month.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the parser accepts the values.
- glm-5.3 — CONFIRMED: trust rests on the signature, so this is a wart rather than a bypass.

---

### 40. The PDF carrying the BitLocker recovery key is queued as a plain `Vec<u8>` and never wiped
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-starter/src/lib.rs:858](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-starter/src/lib.rs#L858)
**Preconditions:** Windows with BitLocker on; the user ticks Include the recovery key and prints the sheet.
**Scenario:** `print_notes()` builds the PDF containing the recovery key and pushes `StarterCommand::PrintNotes { pdf, with_key: true }`. `StarterCommand` derives `Clone` and `pdf` is not `Zeroizing`; the `RecoveryKey` itself is wiped, but the PDF copy in the queue is freed without zeroization if never drained.
**Impact:** The BitLocker recovery key can outlive the session in freed heap memory.
**Fix:** Wrap `pdf` in `Zeroizing<Vec<u8>>` when `with_key` is set, avoid cloning, and wipe undrained queue entries on drop.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED (reason given describes `create()` minimums): `check_cost()` uses the reader minimums; `CREATE_MIN_MEMORY_KIB`/`CREATE_MIN_PASSES` are never referenced.
- glm-5.3 — CONFIRMED: the documented wiping is shell-side only.

---

### 41. `create()` enforces only the reader minimums, not the declared creation minimums
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-vault/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-vault/src/lib.rs) (`create`)
**Preconditions:** A caller relying on `create()` alone.
**Scenario:** `create()` calls `check_cost()`, which uses `MIN_MEMORY_KIB` (8 MiB) and passes 1..=10. `CREATE_MIN_MEMORY_KIB` (64 MiB) and `CREATE_MIN_PASSES` (2) are defined but never referenced, so `create()` can write an 8 MiB / 1-pass vault.
**Impact:** A vault roughly an order of magnitude below the format's stated creation floor.
**Fix:** Enforce the creation minimums in `create()`.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED: the constants are unreferenced.
- glm-5.3 — CONFIRMED: an API-surface weakness; the real caller may enforce the floor.

---

### 42. In-use detection does not attribute LVM logical volumes or MD RAID members to their disk
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/shells/starter/src/linux/udisks.rs:167](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/shells/starter/src/linux/udisks.rs#L167)
**Preconditions:** Linux; a USB disk whose partition is an LVM PV with mounted LVs, or an MD RAID member with a mounted array.
**Scenario:** `blocks_of()` collects the whole disk, its partitions, and only blocks whose `CryptoBackingDevice` points at them. LVM LVs and MD arrays are reached through neither link, so filesystems mounted from `/dev/mapper/*` or `/dev/md*` are never seen by `in_use()`. The disk is offered as not in use and written.
**Impact:** Wrong-disk write with the in-use safeguard not firing, destroying data on a disk the computer is actively using.
**Fix:** Walk device-mapper children and MD slaves via `/sys`; failing certain attribution, treat a disk with `dm-*`/`md*` holders as in use.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — CONFIRMED (reason given describes the temp-dir permissions issue): `create_dir`/`fs::write` set no permissions, giving 0755/0644 under umask 022 in shared `/tmp`.
- glm-5.3 — CONFIRMED: identical to F158; the file holds the recovery key for the session.

---

## Likely findings (one checker confirmed, one partly)

### 43. Codex32 secret/share arrays are copied into `Codex32` without wiping the local copy
**Severity:** medium (glm-5.3: medium; kimi-k3: low) — reporter rated high
**File:** [core/faraday-bip/src/codex32.rs:489](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/codex32.rs#L489)
**Preconditions:** The device has parsed, split, recovered or derived a codex32 master seed or Shamir share, and an attacker can obtain a memory dump afterward.
**Scenario:** `from_seed` builds `let mut data = [0u8; MAX_DATA_LEN]`, fills it, then constructs `Codex32 { data, len }`. The local `data` is never wiped. The same pattern occurs in `parse`, `split` and `interpolate`. `Codex32` zeroizes on drop, the locals do not.
**Impact:** A memory dump after a codex32 operation can recover the master seed or a share.
**Fix:** Wrap the locals in `Zeroizing` or explicitly `zeroize()` them after construction.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the source observation is accurate, but the stated mechanism is wrong — `Codex32 { data, len }` moves the local, so "remains on the stack" is compiler-dependent.
- glm-5.3 — CONFIRMED: the locals are abandoned at scope end; only the `Codex32` value is wiped.

---

### 44. KDBX header accepts unbounded Argon2 passes/lanes
**Severity:** medium (kimi-k3: medium; deepseek-v4.1-flash-1017: low) — reporter rated medium
**File:** [core/faraday-backup/src/kdbx.rs:400](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-backup/src/kdbx.rs#L400) (also L548)
**Preconditions:** A crafted KDBX file reaching `verify`/`cost_of`, e.g. via USB or QR backup import.
**Scenario:** `read_kdf` parses `I` (passes) and `P` (lanes) and bounds only `memory_kib`. A file can state `passes = u32::MAX` with minimal memory; `verify` then runs that many passes over the allocated memory with no cancellation point. `oskb::read_header` applies the `DEVICE_PARAMS` bound; the KDBX path was missed.
**Impact:** Long CPU/memory denial of service on the signer; authentication still fails closed.
**Fix:** Reject `passes`/`lanes` outside the `DEVICE_PARAMS` bounds before allocating or running Argon2id.
**Reported by:** deepseek-v4.1-flash-1017 (also reported independently as F8 by glm-5.3)
**Checks:**
- kimi-k3 — CONFIRMED: the bound is missing and the KDF runs on attacker-chosen parameters before any authentication.
- deepseek-v4.1-flash-1017 — PARTLY: the missing bound is real, but the attacker precondition is not established by the shown code (the module is documented as a writer), and the "argon2 crate may panic" aside is speculative.

---

### 45. KDBX writer leaves ChaCha20 stream state (encryption key copy) unzeroized
**Severity:** medium (glm-5.3: medium; kimi-k3: low) — reporter rated medium
**File:** [core/faraday-backup/src/kdbx.rs:150](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-backup/src/kdbx.rs#L150)
**Preconditions:** The device writes a KDBX backup and an attacker can dump memory afterward.
**Scenario:** `write` creates `let mut stream = chacha20(&keys.encryption, iv);` and `document` creates another stream. The `Secret` wrappers are zeroized, but the `ChaCha20` state contains a copy of the key and is dropped without an explicit `zeroize()`.
**Impact:** The outer KDBX encryption key can remain in memory, allowing decryption of the backup without the passphrase.
**Fix:** Zeroize the cipher state, or use an API that zeroizes on drop.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the conclusion rests entirely on the external crate lacking drop-time wiping, which the finding admits it cannot establish.
- glm-5.3 — CONFIRMED: the key words are part of the ChaCha state; the crate does not zeroize on drop unless its feature is enabled.

---

### 46. Originless Tree key at index 0 is allowed for any key, not just the unspendable synthetic key
**Severity:** medium (glm-5.3: medium; kimi-k3: low) — reporter rated high
**File:** [core/faraday-bip/src/policy.rs:1258](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/core/faraday-bip/src/policy.rs#L1258)
**Preconditions:** Attacker supplies a `tr()` descriptor with an originless MultiXPub internal key, or with a Single internal key so the first leaf key becomes index 0.
**Scenario:** `check()` allows an originless key at index 0 for `Template::Tree` purely by position. With a Single internal key the filter removes it, so the first leaf key gets the exemption; with a MultiXPub internal key any originless xpub is accepted there. The device cannot attribute the key to a master.
**Impact:** A wallet with an attacker-controlled key the device cannot sign for, but the attacker can.
**Fix:** Only allow an originless Tree key at index 0 if it is the synthetic unspendable key; require an origin on all others.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the code facts hold, but the impact is partly wrong — for the MultiXPub-internal case `lift()` works and `spend_paths()` lists the key path.
- glm-5.3 — CONFIRMED: both stated consequences hold; medium because the descriptor text is still displayed.

---

### 47. SLIP-39 split randomness seed is copied and never zeroized
**Severity:** medium (kimi-k3: medium; glm-5.3: low) — reporter rated medium
**File:** [faraday/faraday-core/src/keygen/mod.rs:620](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/keygen/mod.rs#L620)
**Preconditions:** The user makes a SLIP-39 key and reaches the ENTER card's Continue, so `deal` runs with a fresh 32-byte draw.
**Scenario:** `keygen_act` obtains `draw = self.fresh(b"slip39 split")` (a plain `[u8;32]`) and passes it by value to `KeyGen::deal(&c, random: [u8;32])`. `deal` stretches `random` and hands it to `slip39_split`. Neither copy is zeroized; `KeyGen`'s Drop only wipes `frame`.
**Impact:** The split randomness deterministically produces the Shamir coefficients; an attacker who reads memory can recover the master secret from one share.
**Fix:** Make `fresh`/`deal` use `Zeroizing<[u8;32]>` and zeroize the `fill` outputs.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the core issue is verified, but the closure captures `random` by reference (not a copy), and "or without shares" is false — zero shares leave the secret information-theoretically hidden.
- glm-5.3 — CONFIRMED (reason given describes the key-card ASCII restriction): the passphrase fields accept only printable ASCII, so a non-ASCII BIP-39 passphrase cannot be typed on this restore path.

---

### 48. Multisig share merge counts duplicate key lines as distinct keys
**Severity:** medium (kimi-k3: medium; glm-5.3: low) — reporter rated medium
**File:** [faraday/faraday-core/src/restore.rs:120](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/restore.rs#L120)
**Preconditions:** Attacker supplies a malicious multisig share file or share set for an M-of-N wallet; the user restores from shares.
**Scenario:** `parts()` pushes every 8-hex key line. `merge()` deduplicates only across later shares, not within the first, and only checks `a.keys.len() >= a.n`. A crafted share set (`[A,A] + [B]` for a 2-of-3) makes `merge` build a `whole` config with duplicate keys.
**Impact:** Wrong wallet restore; funds sent to the restored wallet can be lost. The app reports success.
**Fix:** Deduplicate by fingerprint within each share and across all shares; require exactly N distinct keys and validate with `readable()`.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the merge-level claims are right, but the single-share scenario does not work (a file with `keys.len() == n` is not a `Share`), and "reports success" depends on an unshown parser.
- glm-5.3 — CONFIRMED (reason given describes AMOUNTS records): any opened vault's type-10 records are imported with no provenance check, enabling induced false signing refusals.

---

### 50. Wallet name is written unsanitized into line-based backup sheets, allowing newline injection
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated high
**File:** [faraday/faraday-core/src/wallet_backup.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-core/src/wallet_backup.rs) (`sheet_wallet`, `sheet_share`, `sheet_blank`)
**Preconditions:** A malicious wallet file with a newline in its name, or a user-supplied name containing a newline; the user prints the sheet.
**Scenario:** `sheet_wallet` writes `name: {wallet.name}\n` raw, while `config()` and `wallet_json()` route the name through `sanitize()`. A newline injects additional `field: value` lines ahead of the real `descriptor:` line.
**Impact:** The printed sheet — the user's independent check — can vouch for attacker-chosen values.
**Fix:** Sanitize `wallet.name` in all sheet writers, or escape newlines.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the injection is confirmed, but neither the name's sources nor a restore path that honors injected lines is in the shown code.
- glm-5.3 — CONFIRMED: the maintainers' own `sanitize()` convention proves the name can carry such characters.

---

### 51. Hidden `.faraday-*.ofv.part` files are read with no `MAX_READ` cap
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated medium
**File:** [faraday/faraday-files/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-files/src/lib.rs) (`finish_vault_writes`)
**Preconditions:** A stick with a hidden `.faraday-<name>.ofv.part` of huge size; the app reads any `.ofv` file.
**Scenario:** `finish_vault_writes` calls `place.read(n, *len)` with the file's own size as the cap, bypassing `MAX_READ`; `vec![0u8; size]` allocates up to ~4 GiB and allocation failure aborts.
**Impact:** Denial of service; possible loss of unsaved session state.
**Fix:** Cap the read to `MAX_READ`, or read only the header and the needed length.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — CONFIRMED: the attacker must give the file a real chain, which is craftable; DoS only.
- glm-5.3 — PARTLY: the code claims hold, but the grant helper must hand the partition out and the app-side handling of `Stick.boot` is not shown; "corrupting the boot disk" is overstated.

---

### 52. Partially decoded messages with trailing bytes are dropped without zeroizing their payloads
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-files/src/proto.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-files/src/proto.rs) (`Request::decode`, `Response::decode`)
**Preconditions:** A malformed frame with a `Write` or `Qr` payload and trailing bytes.
**Scenario:** `Request::decode` copies the bytes into a `Vec`, then `i.end()?` fails on trailing bytes; the `Request` is dropped without `wipe`. Same for `Response::decode` with `Qr`.
**Impact:** A secret copy remains in memory in the long-lived disk process or app.
**Fix:** Implement `Drop` for `Request`/`Response`, or zeroize on the error path.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the behavior is as described, but the honest encoder never emits trailing bytes, so the unwiped bytes are usually the peer's own data.
- glm-5.3 — CONFIRMED (reason given describes `Dir::wipe` symlink following): `wipe` follows symlinks and removes only the link, destroying an arbitrary host file.

---

### 53. A non-boot partition on the boot disk can be opened and written
**Severity:** low (kimi-k3: low; glm-5.3: low) — reporter rated low
**File:** [faraday/faraday-disk/src/lib.rs](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/faraday-disk/src/lib.rs) (`Disks::place`)
**Preconditions:** The boot disk has a second partition and the grant helper grants it.
**Scenario:** `Disks::found` marks sibling partitions `boot: true`, but `place` never refuses `f.boot`, so a granted sibling is listed, read and written. The FARADAYBOOT partition itself is refused three ways.
**Impact:** Corruption of data on the boot disk's sibling partition.
**Fix:** Refuse `f.boot` in `place`/`volume` unless explicitly a user stick.
**Reported by:** deepseek-v4.1-flash-1017
**Checks:**
- kimi-k3 — PARTLY: the impact is overstated; `Node` confines I/O to the granted partition, and the scenario hinges on the unshown grant helper.
- glm-5.3 — CONFIRMED (reason given describes the silently-renamed vault): a vault whose name is taken by a different vault is written as `name-2.ofv` with no notice.

---

### 54. Linux Starter treats `/mnt` as a desktop automount location, defeating the in-use safeguard
**Severity:** low (deepseek-v4.1-flash-1017: low; glm-5.3: low) — reporter rated medium
**File:** [faraday/shells/starter/src/linux/udisks.rs:70](https://github.com/bitcoinpasada/faraday/blob/baf4c9f34d535783207da797c96492766ae8b323/faraday/shells/starter/src/linux/udisks.rs#L70)
**Preconditions:** Linux; a USB disk mounted under `/mnt` (typical for fstab mounts). udisks2 itself only automounts under `/run/media/<user>` and `/media/<user>`.
**Scenario:** `in_use()` reports `InUse::Mounted` only for mount points outside `DESKTOP_MOUNTS`, which includes `/mnt/`. A disk mounted at `/mnt/backup` is reported as not in use and `desktop_mounted()` unmounts it automatically before the write.
**Impact:** The Starter overwrites the wrong disk with the in-use protection silently defeated — potentially the user's only other Faraday backup stick.
**Fix:** Remove `/mnt/` from `DESKTOP_MOUNTS`; treat any mount outside the udisks2 automount roots as in use.
**Reported by:** kimi-k3
**Checks:**
- deepseek-v4.1-flash-1017 — PARTLY: `list()` retains only present disks, so the stale version needs an unobserved swap; "nothing re-reads until a write" is not generally true.
- glm-5.3 — CONFIRMED: the cache is keyed on (serial, size) and reused while the key matches.

---

## Summary

- **What was examined:** Faraday's Rust and shell sources at `baf4c9f3`, by three AI models, each finding cross-checked by the other two.
- **What was found:** 47 findings in this file (21 medium, 26 low), mostly robustness and validation gaps. Each is a lead to verify, not a reproduced bug. A further 6 findings at critical or high are in `private.md`, sent as private reports.
- **Assessment:** the codebase is carefully written and documents its own limits. But the private findings mean the code should not yet be trusted with significant funds in the affected features until they are fixed.

