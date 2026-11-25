# Desktop Security Report Card

A zero-dependency, stack-aware **Desktop Security Report Card** rubric, CLI scanner, and shareable HTML/Markdown/JSON grader built by [Hackerz Bay](https://hackerzbay.com/security).

Run it against **any desktop application** — **Electron, Tauri, .NET (WPF/WinUI/MAUI), Python desktop (PyInstaller/Nuitka/PyQt/PySide), or native Windows/macOS** — to get an honest 0–100 score, letter grade (`A+`–`F`), earned **Gold Stars**, and a clear summary of what needs to be fixed.

---

## Grading Philosophy: *What Needs to Be Fixed*, Not Step-by-Step Recipes

This rubric deliberately separates controls into two categories:

1. **Binary Operational Requirements (`binary`)** — Concrete yes/no supply-chain controls you either have or you do not (for example: trusted code signing such as Azure Artifact Signing / EV Authenticode / Apple Notarization, published `SHA256SUMS.txt` checksums, SLSA build provenance attestations, pinned dependency lockfiles, `SECURITY.md` / `security.txt`, and CI security gates).
2. **Broad Security Outcomes (`outcome`)** — Architectural isolation, privilege boundaries, local networking, and vulnerability/attack-vector checks. Rather than handing out fragile, stack-specific step-by-step fix recipes, the report card states:
   - **What is graded** (the security property being verified)
   - **Risk surface** (what attack vector opens when absent)
   - **What needs to be fixed** (the target security boundary your engineering team must enforce)

This keeps the report card stack-agnostic, safe to share publicly, and focused on verifiable engineering outcomes.

---

## Quick Start

Requires **Node.js 20+** (zero npm dependencies).

```bash
# Run directly against a local desktop repository
npx github:Hackerz-Bay/desktop-security-report-card ./path/to/your-app

# Generate a self-contained dark-mode HTML Report Card (includes embedded shield badge)
npx github:Hackerz-Bay/desktop-security-report-card ./path/to/your-app \
  --name "My Desktop App" \
  --format html \
  --out security-report-card.html

# Export a standalone verifiable SVG shield badge for your README or website
npx github:Hackerz-Bay/desktop-security-report-card ./path/to/your-app \
  --name "My Desktop App" \
  --format svg \
  --out security-badge.svg

# Verify a shared HTML, SVG, or JSON report card for tampering (exits code 3 if altered)
npx github:Hackerz-Bay/desktop-security-report-card verify security-report-card.html

# Optional: cryptographically sign and verify with Ed25519 keys for CI-certified badges
npx github:Hackerz-Bay/desktop-security-report-card ./path/to/your-app \
  --format svg --sign-key ./ci-private.pem --out certified-badge.svg
npx github:Hackerz-Bay/desktop-security-report-card verify certified-badge.svg --public-key ./ci-public.pem

# Inspect a compiled Windows or macOS installer alongside the repository
npx github:Hackerz-Bay/desktop-security-report-card ./path/to/your-app \
  --binary ./dist/MyApp-Setup.exe \
  --format md \
  --out SECURITY-REPORT-CARD.md

# Enforce a minimum score in CI (exits with code 2 if below threshold)
npx github:Hackerz-Bay/desktop-security-report-card . --min-score 80
```

Or clone and run locally:

```bash
git clone https://github.com/Hackerz-Bay/desktop-security-report-card.git
cd desktop-security-report-card
node bin/report-card.mjs /path/to/your-app --format html --out report.html
```

---

## Automatic Stack Detection

Framework-specific controls activate **only** when that stack is detected so apps are never penalized for controls that do not apply to them:

| Stack | Auto-Detected Signals | Stack-Specific Checks |
| --- | --- | --- |
| `generic` | Always active | Code signing, checksums, SLSA provenance, lockfiles/CVE scans, disclosure policy, URL/shell execution boundaries, least-privilege ACLs, secret storage, loopback networking, TLS validation, auto-updates, automated tests, CI security gates |
| `electron` | `electron`, `electron-builder`, `@electron-forge/cli`, `@electron/fuses` | Renderer process isolation (`IS-01`), Web Security & CSP (`IS-02`), Compile-Time Binary Fuses (`IS-03`), Installer hygiene (`PR-02`) |
| `tauri` | `tauri.conf.json`, `@tauri-apps/*`, `src-tauri/Cargo.toml` | Tauri Capability Scoping & CSP (`IS-04`) |
| `dotnet` | `.csproj`, `.sln`, `.fsproj` | Windows installer/service hygiene (`PR-02`) + generic desktop controls |
| `python-desktop` | PyInstaller, Nuitka, PyQt/PySide, wxPython, `.spec` | Windows installer/service hygiene (`PR-02`) + generic desktop controls |
| `native-windows` | `.nsi`, `.nsh`, `.wxs`, `.iss`, `.vcxproj`, `.exe`/`.msi` | Windows installer/service hygiene (`PR-02`) + live Authenticode verification with `--binary` |
| `native-macos` | `Info.plist`, `.entitlements`, `.xcodeproj`, `.dmg`/`.app` | Hardened Runtime & Minimal Entitlements (`PR-03`) + live `codesign` verification with `--binary` |

---

## Six Weighted Domains

1. **Binary Identity & Supply Chain (25%)** — Trusted code signing + timestamping, published SHA-256 checksums, SLSA build provenance, pinned dependencies + CVE scanning, disclosure policy.
2. **Runtime Isolation & Sandboxing (20%)** — Stack-appropriate renderer/webview isolation, CSP, binary hardening fuses, URL & command execution boundaries.
3. **Privileges, Installers & OS Boundaries (15%)** — Locked service/install directory ACLs, safe installer lifecycle, macOS Hardened Runtime.
4. **Secrets, Data & Local Networking (15%)** — OS-protected secret storage, loopback-only local servers, strict TLS certificate validation.
5. **Auto-Update Integrity (10%)** — HTTPS + cryptographic signature/digest checks, channel isolation & anti-downgrade controls.
6. **Verification & Automated Testing (15%)** — Automated test coverage and continuous CI SAST/secret/CVE gates.

---

## CI / Pipeline Integration

Drop the built-in GitHub Action directly into your PR or release workflow:

```yaml
- uses: Hackerz-Bay/desktop-security-report-card@v1
  with:
    target: .
    app-name: ${{ github.event.repository.name }}
    # binary: dist/MyApp-Setup.exe   # Optional: live OS Authenticode / codesign check
    # min-score: "80"                # Optional: fail CI below threshold
    write-summary: "true"
```

See **[docs/CI-INTEGRATION.md](./docs/CI-INTEGRATION.md)** for full copy-paste examples covering:
- **GitHub Actions** (PR Job Summary, HTML/SVG artifact upload, signed release binary verification)
- **Ed25519 certified badge signing** (`--sign-key` / `verify --public-key`)
- **Azure DevOps Pipelines** and **GitLab CI**
- **Exit codes & automated badge verification**

---

## Use With AI Coding Agents (`SKILL.md`)

This repository includes a portable [`SKILL.md`](./SKILL.md) so teams using **Antigravity, Claude Code, Cursor, or Codex** can run a guided Desktop Security Report Card audit directly inside their workspace using the exact same rubric and broad-outcome policy.

---

## CLI Options

| Flag | Description |
| --- | --- |
| `[target-dir]` | Path to the desktop app repository to scan (default: `.`) |
| `--name <label>` | Display name printed on the report card |
| `--binary <path>` | Optional compiled installer/executable (`.exe`, `.msi`, `.dmg`, `.app`) for read-only SHA-256 and native OS signature inspection |
| `--format <fmt>` | `text` (default), `md`, `html`, `svg`, or `json` |
| `--out <file>` | Write report output to a file instead of stdout |
| `--min-score <0-100>` | Exit with status code `2` if overall score falls below threshold |
| `--sign-key <priv.pem>` | Sign the canonical report digest with an Ed25519 private key (PEM) |
| `verify <file>` | Verify a generated `.html`, `.svg`, or `.json` artifact for score tampering (exit `3` on tampering); accepts `--public-key <pub.pem>` |

---

## Running Tests

```bash
npm test
```

## License

MIT — see [LICENSE](./LICENSE).
