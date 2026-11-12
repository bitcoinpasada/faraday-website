# Faraday: one further finding (private follow-up to GHSA-7h4m-p8qx-pxrf and issue #2)

**Repository:** https://github.com/bitcoinpasada/faraday
**Commit audited:** `baf4c9f34d535783207da797c96492766ae8b323`; rechecked by reading at `2e43c665b00c7f9c0505ca95731b1aa8fd520d84` (main, 2026-10-25), still present.
**How it was found:** the same AI-assisted audit (DeepSeek V4.1 deepseek-v4.1-flash-1017 found it; Kimi K3 and GLM 5.3 cross-checked it). Claude Opus 5.5 confirmed it by reading the source. Not confirmed by running code.
**Why it is private:** the checkers split (low vs high). Under `SECURITY.md`, "secrets outlive the session" is high, so it is sent here rather than in the public audit issue.

## High (or lower, at your judgement): secret QR frames are not wiped when the QR view is dropped

**File:** `faraday/faraday-core/src/qr_view.rs`:
- `QrView.frames: Vec<faraday_codec::qr::QrMatrix>` (~L237);
- `impl Drop for QrView` (~L267–284);
- the doc comment ~L264–266.

**What goes wrong:**
- `Drop` zeroizes `source` (the PSBT, text, key or file bytes), `title` and `subtitle`.
- It leaves `frames` untouched. Those are the QR matrices, which encode the same secret, for example a seed or Lightning key shown as a QR from a secret file.
- The comment above it notes that faraday-codec's codes have "no way to wipe them".

**How to trigger:** show a secret file as a QR, then close the sheet. The frames' heap memory is freed without being overwritten, so the secret's encoding stays in RAM until that memory is reused.

**Impact:** seed or key material can survive in memory after the view is gone, against the goal that secrets do not outlive the session. Whether this is high depends on how long such freed memory can persist before reboot, which you know better than we do.

**Suggested fix:**
- Give `QrMatrix` a zeroizing drop, or expose a `wipe()` in faraday-codec.
- Zeroize `frames` (and any whole-payload copy) in `QrView::drop` when the source is secret.
