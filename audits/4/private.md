# Faraday: five critical/high findings (private report)

**Repository:** https://github.com/bitcoinpasada/faraday
**Commit audited:** `baf4c9f34d535783207da797c96492766ae8b323` (2026-10-24)
**Rechecked:** `2e43c665b00c7f9c0505ca95731b1aa8fd520d84` (main on 2026-10-25), by reading. All five are still present; line references below give both commits where they differ.
**How it was found:** an AI-assisted audit. Three models found the issues: DeepSeek V4.1 (deepseek-v4.1-flash-1017), Kimi K3 and GLM 5.3. Each finding was cross-checked by the two models that did not report it. Claude Opus 5.5 then verified every finding below by **reading the source**. **None was confirmed by running the code**; the scenarios are traced through the code paths cited. No tool other than reading the repository was used.
**Scope of this report:** only the five findings that held up on source review at critical or high severity under `SECURITY.md`. The full audit (42 findings confirmed by both checkers and 15 likely, most of them medium or low) can follow as a public submission under `docs/AUDIT-SUBMISSIONS.md` once you've seen these.

---

## 1. Critical: the carry file holds the other signers' FROST secret nonces in cleartext, which recovers their shares

**File:** `core/faraday-psbt/src/threshold.rs` (module docs lines 18–33; `CarrySection` ~L303; `to_bytes` L348–360; unchanged at main)

**What goes wrong:**
- The first signing location draws a secret nonce for every chosen signer that has not signed yet.
- It writes those nonces into the carry file (`OSKC`) next to the PSBT, as raw 64-byte `SecNonce` values (`out.extend_from_slice(&entry.secnonce.serialize())`), with no encryption.
- Each later signer's partial signature becomes part of the circulating PSBT.
- In FROST, a partial signature `z_i = d_i + e_i·ρ_i + λ_i·c·s_i` together with that signer's secret nonce `(d_i, e_i)` yields the secret share `s_i`.

**How to trigger:** in a 2-of-3:
1. Location A signs first and writes the carry file holding `secnonce_B`.
2. Anyone with a copy of that file computes `s_B` once B's partial signature appears in the PSBT. That includes A's own device, which derived `secnonce_B` itself, or anyone who intercepts the file (a USB stick, or the online coordinator if the file is relayed through it).
3. That party now holds two shares, the threshold.

**Impact:** one compromised location or one intercepted carry file, plus the PSBT, reaches the threshold alone. Under `SECURITY.md` this is a key extracted from Faraday's own output.

**Suggested fix:** never transport another participant's secret nonce. Each signer draws its own nonce, as in a two-round flow (commitments first, then signatures). If single-pass transport must stay, encrypt each nonce to its signer's public share (ephemeral ECDH) and authenticate the section. Even then, the first device knows the nonces it drew, so the two-round design is the real fix.

---

## 2. Critical: multisig change accepts any witness script that merely contains our key

**File:** `core/faraday-psbt/src/inspect.rs`: `multisig_change` (L1737–1758 at the audited commit; L1723–1747 at main), used at L1705 (L1691 at main), where it returns `OutputKind::Change`.

**What goes wrong:**
- With no wallet registered, an output that claims a loaded BIP-48 key is classified as verified `Change`, with no warning, when two things hold:
  - its scriptPubKey commits to the supplied `witness_script`;
  - our pubkey appears as a push in that script.
- The script is never parsed as a multisig, and its threshold is never checked. The function's own comment notes "the threshold and the cosigners are still the coordinator's word".

**How to trigger:** a malicious coordinator gives the change output a `witness_script` of `<our_pubkey> OP_DROP OP_TRUE`, or `multi(1, our_change_key, attacker_key)`, and pays the "change" to its P2WSH.

**Impact:**
- The output is shown as the user's change and left out of the amount sent to others.
- The user approves.
- The attacker then spends the "change". Under `SECURITY.md`: the device shows as approved something the user did not approve, and funds are lost.

**Suggested fix:** with no registered policy, treat such outputs as unverified (the existing `UnverifiedChange` caution). Or require that the script parse as `multi`/`sortedmulti` with a threshold of at least 2 where every other key is a known cosigner. A registered policy should be the only way to verify multisig change.

---

## 3. High: a `tr()` wallet with a non-NUMS internal key looks like a script-only multisig

**File:**
- `core/faraday-bip/src/policy.rs`: `parse_miniscript` (~L1095–1105) filters any plain internal key out of the wallet's keys;
- `key_path_unspendable()` (L520–534; L528 at main) checks for BIP-341's NUMS point.

**What goes wrong:**
- `key_path_unspendable()` exists, but nothing in the application calls it; only a test does (`core/faraday-psbt/tests/all/tapmulti.rs:172`, still the only caller at main).
- So `tr(<attacker_key>, multi_a(2, user_keys…))` registers.
- `tapscript_quorum()` reports 2-of-n, and the structured review matches a safe `tr(NUMS, multi_a(2, …))` wallet.
- The internal key appears only as hex in the template text.

**How to trigger:** a coordinator, or a shared wallet file, supplies such a descriptor for registration.

**Impact:** the attacker holds a key-path spend over a wallet the user believes needs two signatures. Under `SECURITY.md`: a policy shown as approved that the user did not approve, under the specific condition of an attacker-supplied policy.

**Suggested fix:** at registration and in review, refuse a plain internal key that is not NUMS, or show it prominently with `key_path_unspendable()` as a hard warning ("someone holding this key can spend without the multisig").

---

## 4. High: the boot copier and the upgrade source trust a partition by release string and size alone

**Files:**
- `faraday/faraday-boot/src/lib.rs`: `read_source` (L366 onward, unchanged at main), accepting a partition when `holds(&bytes, &release)` and the size fits;
- the audit's finding 49 reports the same pattern for the upgrade source.

**What goes wrong:** the source image is identified by containing the running kernel's release string and by its size. Its bytes are not checked against a hash of the running image or against a signature.

**How to trigger:** with physical access and the genuine boot stick removed (the device runs from memory), the attacker inserts a crafted partition that carries the running release string and the expected size. The copier reads it and writes it to the target stick.

**Impact:** a tampered image is written to a new Faraday stick (`SECURITY.md`, high: a tampered image under physical access).

**Suggested fix:** authenticate the source before copying. Compare it with a hash of the running image measured at boot, or verify the release signature the build already produces. Apply the same to the upgrade path.

---

## 5. High: the silent-payments wallet's scan key is never checked, so the shown address may not be the user's

**File:** `faraday/faraday-core/src/silent/mod.rs`:
- the receiver check (`silent_receiver`, ~L165–175 at the audited commit; `receiver`, L182–192 at main) compares only `w.spend` with the derived spend key, although its comment says "the wallet is the two points";
- the shown address (`silent_address`, ~L214–222; `address`, L231–239 at main) returns `w.address()` from the record for label 0, without deriving it.

**How to trigger:** a tampered silent-payments wallet record (QR, USB file or vault record) carrying the user's spend public key and an attacker's scan public key.

**Impact:**
- The device reports the user's key as loaded and shows an address built on the attacker's scan key.
- Senders pay outputs that only the attacker's scan key can find. The attacker sees every payment.
- The user can't detect or spend the coins without the attacker.

Under `SECURITY.md`: output that is wrong in a way that loses funds, under the condition of a tampered record.

**Suggested fix:** derive both keys from the loaded key, compare the scan key as well as the spend key, and derive the shown address instead of reading it from the record.

---

We're glad to answer questions or review fixes. The hash of this file can be posted on the audit issue when the public batch goes in.
