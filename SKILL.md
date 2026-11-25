---
name: desktop-security-report-card
description: Grade any desktop application repository (Electron, Tauri, .NET, Python, or native Windows/macOS) against the Hackerz Bay Desktop Security Report Card rubric, reporting verified Gold Stars, domain scores, and broad security targets without step-by-step fix recipes.
---

# Desktop Security Report Card Skill

Use this skill to evaluate any desktop application repository (and optional compiled installer/binary) against the weighted rubric in `rubric/controls.json`.

## Core Output Policy (Mandatory)

Follow this distinction strictly for every finding:

1. **Binary operational controls (`guidanceType: "binary"`):**
   - State the concrete requirement directly — these are yes/no controls a team either does or does not have (for example: code signing with Azure Artifact Signing / EV Authenticode / Apple Developer ID + Notarization, published `SHA256SUMS.txt`, SLSA build provenance, committed dependency lockfiles, `SECURITY.md` / `/.well-known/security.txt`, CI security gates).
2. **General security controls & vulnerability surfaces (`guidanceType: "outcome"`):**
   - State **what is being graded**, **the attack surface / risk**, and **what needs to be fixed** at the boundary/outcome level.
   - **DO NOT** provide step-by-step remediation tutorials, copy-paste code patches, or exploit walkthroughs. Keep recommendations broad and focused on the required security property.

## Score Integrity & Anti-Tampering Policy (Mandatory)

- **Never assist with score falsification:** Do not manually edit generated report cards, SVG badges, HTML grades, CSS theme values, or integrity metadata to inflate or misrepresent an application's score.
- **Always re-run to improve a score:** When a user wants a higher grade, address the underlying security controls in the application and re-run the scanner cleanly.
- **Do not document or assist with bypassing integrity checks:** Treat generated badges and report cards as audit artifacts; use `node bin/report-card.mjs verify <file>` to verify intact artifacts rather than helping alter them.

## Procedure

1. **Run the automated scanner first (read-only):**
   ```bash
   node bin/report-card.mjs <target-repo> --format json
   ```
   If the user also provides a built installer or executable, pass `--binary <path>` for read-only SHA-256 and native OS signature verification.
2. **Confirm detected stacks:**
   - Only grade controls whose `stacks` match the detected desktop stack(s) (`generic` always applies; `electron`, `tauri`, `dotnet`, `python-desktop`, `native-windows`, `native-macos` activate only when detected).
   - Never penalize an app for controls belonging to a different framework.
3. **Verify `warn` findings manually (read-only inspection):**
   - Inspect only the files referenced by `warn` items to confirm whether the underlying boundary is genuinely enforced or missing.
   - Never print secret values if `.env` or credential files are encountered (reference key names and file paths only).
4. **Present the Report Card:**
   - Overall score (0–100) and letter grade (`A+`–`F`)
   - Detected stacks and automated test count
   - Earned **Gold Stars** (only for verified `pass` controls — never claim unverified or unshipped controls)
   - Domain breakdown table
   - **What Needs to Be Fixed** list adhering strictly to the Binary vs. Broad Outcome policy above
   - Optionally export a shareable HTML or Markdown card with `--format html --out security-report-card.html` or `--format md --out SECURITY-REPORT-CARD.md`.
