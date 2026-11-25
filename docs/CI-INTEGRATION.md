# CI / Pipeline Integration Guide

The **Desktop Security Report Card** has zero npm dependencies and runs anywhere with **Node.js 20+**. Use it to:

- Grade pull requests automatically and publish a clean report card in CI job summaries.
- Verify compiled & signed Windows/macOS release installers (`--binary`) right after code signing.
- Enforce a minimum security score (`--min-score`) so regressions cannot silently ship.
- Issue **tamper-evident HTML report cards and SVG shield badges**, optionally cryptographically signed with an Ed25519 key in CI.

---

## 1. GitHub Actions (Recommended — Built-In Composite Action)

### A. Pull Request Security Report Card

Add `.github/workflows/security-report-card.yml` to any desktop repository:

```yaml
name: Desktop Security Report Card

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  report-card:
    name: Grade desktop security posture
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Run Desktop Security Report Card
        id: report-card
        uses: Hackerz-Bay/desktop-security-report-card@v1
        with:
          target: .
          app-name: ${{ github.event.repository.name }}
          out-dir: .security-report-card
          # Optional: fail the PR if the score drops below your floor
          # min-score: "75"
          write-summary: "true"

      - name: Upload Report Card & SVG Badge
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: desktop-security-report-card
          path: .security-report-card/
          retention-days: 30
```

### B. Release Pipeline Integration (With Live Signed Binary Verification)

On Windows or macOS release runners, run the grader **after** code signing and pass the freshly signed installer via `binary:`. This performs a live read-only OS Authenticode / `codesign` + RFC 3161 timestamp check alongside the repository scan:

```yaml
      - name: Grade signed release build
        uses: Hackerz-Bay/desktop-security-report-card@v1
        with:
          target: .
          app-name: My Desktop App
          binary: dist/MyApp-Setup.exe
          out-dir: ${{ runner.temp }}/security-report-card
          min-score: "80"
          # Optional: sign the badge digest with a CI-only Ed25519 private key
          # sign-key: ${{ secrets.REPORT_CARD_ED25519_PRIVATE_KEY }}
```

> **Tip for strict release output directories:** Always point `out-dir` to `${{ runner.temp }}/security-report-card` (outside your release artifact staging folder) if your release pipeline runs a strict manifest completeness check over its output directory.

### C. Issuing Cryptographically Certified Badges (Ed25519)

Because this tool is open source, the built-in chromatic and geometric badge seals catch casual/manual edits to generated HTML or SVG files, while **Ed25519 private-key signing** provides mathematical unforgeability for public badges:

1. Generate an Ed25519 key pair once (keep the private key in CI Secrets; publish the public key):
   ```bash
   openssl genpkey -algorithm ED25519 -out report-card-private.pem
   openssl pkey -in report-card-private.pem -pubout -out report-card-public.pem
   ```
2. Store `report-card-private.pem` as a GitHub Actions Secret (e.g., `REPORT_CARD_ED25519_PRIVATE_KEY`) and pass `sign-key: ${{ secrets.REPORT_CARD_ED25519_PRIVATE_KEY }}`.
3. Anyone can verify a published badge or HTML report card against your public key:
   ```bash
   npx github:Hackerz-Bay/desktop-security-report-card verify security-badge.svg \
     --public-key ./report-card-public.pem
   ```

---

## 2. Azure DevOps Pipelines

```yaml
steps:
  - task: NodeTool@0
    inputs:
      versionSpec: "20.x"

  - script: |
      npx --yes github:Hackerz-Bay/desktop-security-report-card . \
        --name "$(Build.Repository.Name)" \
        --format html \
        --out "$(Build.ArtifactStagingDirectory)/security-report-card.html" \
        --min-score 75
    displayName: "Generate Desktop Security Report Card"

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: "$(Build.ArtifactStagingDirectory)/security-report-card.html"
      ArtifactName: "security-report-card"
```

---

## 3. GitLab CI

```yaml
desktop-security-report-card:
  image: node:20-alpine
  stage: test
  script:
    - npx --yes github:Hackerz-Bay/desktop-security-report-card . --format html --out security-report-card.html
    - npx --yes github:Hackerz-Bay/desktop-security-report-card . --format svg --out security-badge.svg
    - npx --yes github:Hackerz-Bay/desktop-security-report-card . --min-score 75 --format text
  artifacts:
    when: always
    paths:
      - security-report-card.html
      - security-badge.svg
    expire_in: 30 days
```

---

## 4. Verifying Shared Report Cards & Badges

Whenever a vendor or team shares a generated `.html`, `.svg`, or `.json` report card, verify its integrity before trusting the displayed score:

```bash
# Check visual & structural seals (exits 0 if intact, 3 if tampered)
npx github:Hackerz-Bay/desktop-security-report-card verify security-report-card.html

# Machine-readable verification output for automated portals or registries
npx github:Hackerz-Bay/desktop-security-report-card verify security-badge.svg --format json
```

If someone manually altered the displayed score or grade, the verifier exits with status code `3`, flags `TAMPERING DETECTED`, and prints the original score recovered from the embedded badge and palette seals.

---

## 5. Exit Codes Reference

| Exit Code | Meaning |
| --- | --- |
| `0` | Scan completed (and met `--min-score` if specified) or `verify` passed |
| `1` | Usage error, missing file, or invalid option |
| `2` | Scan succeeded, but overall score is below `--min-score` |
| `3` | `verify` detected score tampering, seal corruption, or invalid signature |
