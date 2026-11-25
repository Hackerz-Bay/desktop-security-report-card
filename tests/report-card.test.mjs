import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { loadRubric, runSecurityReportCard, scoreToGrade } from '../src/scanner.mjs';
import { renderText } from '../src/renderers/text.mjs';
import { renderMarkdown } from '../src/renderers/markdown.mjs';
import { renderHtml } from '../src/renderers/html.mjs';
import { renderSvgBadge } from '../src/renderers/svg.mjs';
import {
  buildChromaticPalette,
  buildShieldMatrix,
  decodeChromaticPalette,
  decodeShieldMatrix,
} from '../src/seal.mjs';
import { verifyReportArtifact } from '../src/verifier.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'report-card.mjs');

function makeFixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsrc-fixture-'));
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return dir;
}

test('rubric enforces broad-outcome policy without step-by-step fix recipes', () => {
  const rubric = loadRubric();
  assert.ok(Array.isArray(rubric.controls) && rubric.controls.length >= 15);
  assert.equal(
    rubric.domains.reduce((s, d) => s + d.weight, 0),
    100,
    'Domain weights must sum to 100'
  );

  for (const control of rubric.controls) {
    assert.ok(
      control.guidanceType === 'binary' || control.guidanceType === 'outcome',
      `Control ${control.id} must declare guidanceType binary or outcome`
    );
    assert.ok(control.gradedProperty.length > 20, `${control.id} needs gradedProperty`);
    assert.ok(control.attackSurface.length > 20, `${control.id} needs attackSurface`);
    assert.ok(control.whatToFix.length > 20, `${control.id} needs whatToFix`);

    if (control.guidanceType === 'outcome') {
      assert.doesNotMatch(
        control.whatToFix,
        /(```|step\s*1|npm install|pip install|apt-get|icacls\s+|chmod\s+)/i,
        `Outcome control ${control.id} must not give step-by-step fix recipes`
      );
    }
  }
});

test('hardened Electron fixture detects electron+native-windows and scores A/A+', () => {
  const dir = makeFixture({
    'package.json': JSON.stringify({
      name: 'hardened-electron-app',
      dependencies: { 'electron-updater': '^6.0.0' },
      devDependencies: {
        electron: '^42.0.0',
        'electron-builder': '^26.0.0',
        '@electron/fuses': '^1.8.0',
      },
    }),
    'package-lock.json': '{"lockfileVersion": 3}',
    'SECURITY.md': '# Security Policy\nEmail security@example.com\n',
    'src/main.js': `
      const { BrowserWindow, safeStorage } = require('electron');
      const win = new BrowserWindow({
        webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true }
      });
      win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      // Content-Security-Policy: default-src 'self'; script-src 'self'
      const localUrl = 'http://127.0.0.1:5004';
    `,
    'scripts/apply-fuses.js': `
      const { flipFuses, FuseV1Options } = require('@electron/fuses');
      module.exports = async () => flipFuses;
    `,
    'build/installer.nsh': `
      !macro customInstall
        nsExec::ExecToLog 'icacls "C:\\ProgramData\\App\\services" /inheritance:r /grant *S-1-5-18:(OI)(CI)F'
      !macroend
      !macro customUnInstall
      !macroend
    `,
    '.github/workflows/release.yml': `
      permissions:
        attestations: write
        id-token: write
      jobs:
        release:
          steps:
            - uses: azure/artifact-signing-action@v2
              with:
                timestamp-rfc3161: http://timestamp.acs.microsoft.com
            - uses: actions/attest-build-provenance@v2
            - run: echo "SHA256SUMS.txt" && echo "monotonic channel check"
            - uses: github/codeql-action/analyze@v3
            - run: osv-scanner --lockfile=package-lock.json
    `,
    'tests/a.test.js': 'test("1",()=>{}); test("2",()=>{}); test("3",()=>{}); test("4",()=>{}); test("5",()=>{});',
    'tests/b.test.js': 'test("6",()=>{}); test("7",()=>{});',
    'tests/c.test.js': 'test("8",()=>{});',
    'tests/d.test.js': 'test("9",()=>{});',
    'tests/e.test.js': 'test("10",()=>{});',
  });

  try {
    const report = runSecurityReportCard(dir, { appName: 'Hardened Demo' });
    assert.ok(report.detectedStacks.includes('electron'));
    assert.ok(report.detectedStacks.includes('native-windows'));
    assert.ok(!report.detectedStacks.includes('tauri'));
    assert.equal(
      report.controls.find((c) => c.id === 'IS-04').status,
      'not-applicable',
      'Tauri control must be N/A on Electron app'
    );
    assert.ok(report.overallScore >= 90, `Expected >= 90, got ${report.overallScore}`);
    assert.ok(['A', 'A+'].includes(report.grade));
    assert.ok(report.goldStars.length >= 6);
    assert.equal(report.testStats.testFiles, 5);
    assert.equal(report.testStats.estimatedTests, 10);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('vulnerable Electron fixture flags isolation, webSecurity, ACL, 0.0.0.0, and TLS bypass', () => {
  const dir = makeFixture({
    'package.json': JSON.stringify({
      name: 'vuln-electron',
      devDependencies: { electron: '^28.0.0' },
    }),
    'src/main.js': `
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      const win = new BrowserWindow({
        webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false }
      });
      server.listen(8080, '0.0.0.0');
      child_process.exec('calc.exe ' + userInput);
    `,
    'build/installer.nsh': `
      nsExec::ExecToLog 'icacls "C:\\ProgramData\\MyApp" /grant *S-1-5-32-545:(OI)(CI)M /T'
    `,
  });

  try {
    const report = runSecurityReportCard(dir);
    const byId = Object.fromEntries(report.controls.map((c) => [c.id, c]));
    assert.equal(byId['IS-01'].status, 'fail');
    assert.equal(byId['IS-02'].status, 'fail');
    assert.equal(byId['IS-03'].status, 'fail');
    assert.equal(byId['PR-01'].status, 'fail');
    assert.equal(byId['SD-02'].status, 'fail');
    assert.equal(byId['SD-03'].status, 'fail');
    assert.equal(byId['SC-01'].status, 'fail');
    assert.equal(byId['VT-01'].status, 'fail');
    assert.ok(report.overallScore < 50, `Expected < 50, got ${report.overallScore}`);
    assert.equal(report.grade, 'F');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Tauri and .NET fixtures activate only their respective stack checks', () => {
  const tauriDir = makeFixture({
    'src-tauri/tauri.conf.json': JSON.stringify({
      app: { security: { csp: null } },
      tauri: { allowlist: { shell: { all: true } } },
    }),
  });
  const dotnetDir = makeFixture({
    'MyApp.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><UseWPF>true</UseWPF></PropertyGroup></Project>',
    'Tests/AppTests.cs': '[Fact] public void One() {} [Theory] public void Two() {}',
  });

  try {
    const tauriReport = runSecurityReportCard(tauriDir);
    assert.ok(tauriReport.detectedStacks.includes('tauri'));
    assert.equal(tauriReport.controls.find((c) => c.id === 'IS-04').status, 'fail');
    assert.equal(tauriReport.controls.find((c) => c.id === 'IS-01').status, 'not-applicable');

    const dotnetReport = runSecurityReportCard(dotnetDir);
    assert.ok(dotnetReport.detectedStacks.includes('dotnet'));
    assert.equal(dotnetReport.controls.find((c) => c.id === 'IS-01').status, 'not-applicable');
    assert.equal(dotnetReport.controls.find((c) => c.id === 'IS-04').status, 'not-applicable');
    assert.equal(dotnetReport.testStats.testFiles, 1);
    assert.equal(dotnetReport.testStats.estimatedTests, 2);
  } finally {
    fs.rmSync(tauriDir, { recursive: true, force: true });
    fs.rmSync(dotnetDir, { recursive: true, force: true });
  }
});

test('renderers produce valid Text, Markdown, and XSS-safe HTML outputs', () => {
  const dir = makeFixture({ 'README.md': '# Demo' });
  try {
    const report = runSecurityReportCard(dir, { appName: '<script>alert(1)</script> App' });
    const text = renderText(report);
    const md = renderMarkdown(report);
    const html = renderHtml(report);

    assert.match(text, /DESKTOP SECURITY REPORT CARD/);
    assert.match(text, /WHAT NEEDS TO BE FIXED/);
    assert.match(md, /^# Desktop Security Report Card/m);
    assert.match(md, /## Domain Breakdown/);
    assert.match(html, /^<!doctype html>/i);
    assert.ok(!html.includes('<script>alert(1)</script>'), 'HTML output must escape untrusted appName');
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI supports --format html --out and enforces --min-score exit code 2', () => {
  const dir = makeFixture({ 'README.md': '# Empty app' });
  const outHtml = path.join(dir, 'out', 'card.html');
  try {
    execFileSync(
      process.execPath,
      [CLI_PATH, dir, '--name', 'CLI Test', '--format', 'html', '--out', outHtml],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    );
    assert.ok(fs.existsSync(outHtml));
    const html = fs.readFileSync(outHtml, 'utf8');
    assert.ok(html.includes('CLI Test'));

    let exitCode = 0;
    try {
      execFileSync(process.execPath, [CLI_PATH, dir, '--min-score', '99'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      exitCode = err.status;
    }
    assert.equal(exitCode, 2, 'CLI should exit with code 2 when score < --min-score');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scoreToGrade maps boundaries cleanly', () => {
  assert.equal(scoreToGrade(96), 'A+');
  assert.equal(scoreToGrade(90), 'A');
  assert.equal(scoreToGrade(85), 'A-');
  assert.equal(scoreToGrade(75), 'B');
  assert.equal(scoreToGrade(60), 'C');
  assert.equal(scoreToGrade(50), 'D');
  assert.equal(scoreToGrade(49), 'F');
});

test('chromatic palette and geometric shield matrix round-trip exact scores', () => {
  const dir = makeFixture({ 'README.md': '# Demo' });
  try {
    const report = runSecurityReportCard(dir, { appName: 'Seal Roundtrip' });
    const palette = buildChromaticPalette(report);
    const decodedPal = decodeChromaticPalette(palette);
    assert.equal(decodedPal.valid, true);
    assert.equal(decodedPal.overallScore, report.overallScore);
    for (const d of report.domainScores) {
      assert.equal(decodedPal.domainScores[d.id], d.score);
    }

    const matrix = buildShieldMatrix(report);
    const decodedMatrix = decodeShieldMatrix(matrix);
    assert.equal(decodedMatrix.valid, true);
    assert.equal(decodedMatrix.overallScore, report.overallScore);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('verify detects manual HTML score tampering and recovers the real score', () => {
  const dir = makeFixture({ 'README.md': '# Weak app' });
  const htmlPath = path.join(dir, 'report.html');
  const tamperedPath = path.join(dir, 'tampered.html');
  try {
    const report = runSecurityReportCard(dir, { appName: 'Tamper Demo' });
    const realScore = report.overallScore;
    const realGrade = report.grade;
    const html = renderHtml(report);
    fs.writeFileSync(htmlPath, html, 'utf8');

    const okResult = verifyReportArtifact(htmlPath);
    assert.equal(okResult.intact, true);
    assert.equal(okResult.recoveredScore, realScore);

    // Simulate someone editing the displayed score and grade in HTML to fake an A+ (99/100)
    const tampered = html
      .replaceAll(`${realScore} / 100`, '99 / 100')
      .replaceAll(`${realScore}/100`, '99/100')
      .replaceAll(`class="grade-letter">${realGrade}<`, 'class="grade-letter">A+<')
      .replaceAll(`data-role="grade">${realGrade}<`, 'data-role="grade">A+<');
    fs.writeFileSync(tamperedPath, tampered, 'utf8');

    const badResult = verifyReportArtifact(tamperedPath);
    assert.equal(badResult.intact, false);
    assert.equal(badResult.displayedScore, 99);
    assert.equal(badResult.recoveredScore, realScore);
    assert.equal(badResult.recoveredGrade, realGrade);
    assert.ok(
      badResult.discrepancies.some((d) => d.includes('TAMPERING DETECTED')),
      'Verifier must explicitly flag tampering and cite the real score'
    );

    // Verify CLI exits with code 3 on tampered file
    let exitCode = 0;
    try {
      execFileSync(process.execPath, [CLI_PATH, 'verify', tamperedPath], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      exitCode = err.status;
    }
    assert.equal(exitCode, 3, 'verify CLI must exit 3 when tampering is detected');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('verify catches SVG badge tampering and validates Ed25519 signatures', () => {
  const dir = makeFixture({ 'README.md': '# Signed app' });
  const svgPath = path.join(dir, 'badge.svg');
  const tamperedSvgPath = path.join(dir, 'badge-tampered.svg');
  const privPath = path.join(dir, 'priv.pem');
  const pubPath = path.join(dir, 'pub.pem');

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), 'utf8');
  fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');

  try {
    execFileSync(
      process.execPath,
      [CLI_PATH, dir, '--name', 'Signed Demo', '--format', 'svg', '--sign-key', privPath, '--out', svgPath],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    );

    const verified = verifyReportArtifact(svgPath, {
      publicKeyPem: fs.readFileSync(pubPath, 'utf8'),
    });
    assert.equal(verified.intact, true);
    assert.equal(verified.signatureVerified, true);

    const svgText = fs.readFileSync(svgPath, 'utf8');
    const tamperedSvg = svgText.replaceAll(`${verified.displayedScore}/100`, '98/100');
    fs.writeFileSync(tamperedSvgPath, tamperedSvg, 'utf8');

    const badSvg = verifyReportArtifact(tamperedSvgPath, {
      publicKeyPem: fs.readFileSync(pubPath, 'utf8'),
    });
    assert.equal(badSvg.intact, false);
    assert.equal(badSvg.recoveredScore, verified.displayedScore);
    assert.ok(renderSvgBadge(runSecurityReportCard(dir)).includes('data-dsrc-digest='));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('GitHub Action runner writes all 4 artifacts, step summary, outputs, and enforces min-score', () => {
  const dir = makeFixture({ 'README.md': '# Action Test App' });
  const outDir = path.join(dir, 'action-out');
  const summaryPath = path.join(dir, 'step-summary.md');
  const ghOutPath = path.join(dir, 'gh-output.txt');
  const actionRunner = path.resolve(__dirname, '..', 'scripts', 'run-action.mjs');

  try {
    execFileSync(process.execPath, [actionRunner], {
      env: {
        ...process.env,
        DSRC_TARGET: dir,
        DSRC_APP_NAME: 'Action Demo',
        DSRC_OUT_DIR: outDir,
        DSRC_WRITE_SUMMARY: 'true',
        GITHUB_STEP_SUMMARY: summaryPath,
        GITHUB_OUTPUT: ghOutPath,
      },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    assert.ok(fs.existsSync(path.join(outDir, 'security-report-card.html')));
    assert.ok(fs.existsSync(path.join(outDir, 'security-report-card.md')));
    assert.ok(fs.existsSync(path.join(outDir, 'security-report-card.json')));
    assert.ok(fs.existsSync(path.join(outDir, 'security-badge.svg')));
    assert.match(fs.readFileSync(summaryPath, 'utf8'), /Desktop Security Report Card — Action Demo/);
    const ghOut = fs.readFileSync(ghOutPath, 'utf8');
    assert.match(ghOut, /^score=\d+/m);
    assert.match(ghOut, /^grade=[A-F][+-]?/m);

    // Confirm min-score threshold failure exits 2
    let code = 0;
    try {
      execFileSync(process.execPath, [actionRunner], {
        env: {
          ...process.env,
          DSRC_TARGET: dir,
          DSRC_OUT_DIR: outDir,
          DSRC_MIN_SCORE: '99',
        },
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      code = err.status;
    }
    assert.equal(code, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
