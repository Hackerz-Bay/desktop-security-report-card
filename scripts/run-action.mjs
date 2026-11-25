#!/usr/bin/env node
/**
 * Cross-platform entrypoint for the Desktop Security Report Card GitHub Action.
 * Runs identically on Linux, Windows, and macOS runners with zero dependencies.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'report-card.mjs');

const target = process.env.DSRC_TARGET || '.';
const appName = (process.env.DSRC_APP_NAME || '').trim();
const binary = (process.env.DSRC_BINARY || '').trim();
const outDir = path.resolve(process.env.DSRC_OUT_DIR || '.security-report-card');
const minScoreRaw = (process.env.DSRC_MIN_SCORE || '').trim();
const signKeyPem = process.env.DSRC_SIGN_KEY || '';
const writeSummary = (process.env.DSRC_WRITE_SUMMARY || 'true').toLowerCase() !== 'false';

fs.mkdirSync(outDir, { recursive: true });

let tempKeyDir = null;
let tempKeyPath = null;
if (signKeyPem.trim()) {
  tempKeyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsrc-key-'));
  tempKeyPath = path.join(tempKeyDir, 'sign.pem');
  fs.writeFileSync(tempKeyPath, signKeyPem, { encoding: 'utf8', mode: 0o600 });
}

function buildBaseArgs(format, outFile) {
  const args = [CLI_PATH, target, '--format', format, '--out', outFile];
  if (appName) args.push('--name', appName);
  if (binary) args.push('--binary', binary);
  if (tempKeyPath && (format === 'html' || format === 'svg' || format === 'json')) {
    args.push('--sign-key', tempKeyPath);
  }
  return args;
}

const jsonPath = path.join(outDir, 'security-report-card.json');
const mdPath = path.join(outDir, 'security-report-card.md');
const htmlPath = path.join(outDir, 'security-report-card.html');
const svgPath = path.join(outDir, 'security-badge.svg');

try {
  execFileSync(process.execPath, buildBaseArgs('json', jsonPath), { stdio: 'inherit' });
  execFileSync(process.execPath, buildBaseArgs('md', mdPath), { stdio: 'inherit' });
  execFileSync(process.execPath, buildBaseArgs('html', htmlPath), { stdio: 'inherit' });
  execFileSync(process.execPath, buildBaseArgs('svg', svgPath), { stdio: 'inherit' });

  // Self-verify generated HTML & SVG artifacts immediately so CI confirms integrity.
  execFileSync(process.execPath, [CLI_PATH, 'verify', htmlPath], { stdio: 'inherit' });
  execFileSync(process.execPath, [CLI_PATH, 'verify', svgPath], { stdio: 'inherit' });

  const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

  if (writeSummary && process.env.GITHUB_STEP_SUMMARY) {
    const mdContent = fs.readFileSync(mdPath, 'utf8');
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${mdContent}\n`, 'utf8');
  }

  if (process.env.GITHUB_OUTPUT) {
    const outputs = [
      `score=${report.overallScore}`,
      `grade=${report.grade}`,
      `gold_stars=${report.goldStars.length}`,
      `html_path=${htmlPath}`,
      `svg_path=${svgPath}`,
      `markdown_path=${mdPath}`,
      `json_path=${jsonPath}`,
    ].join('\n');
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${outputs}\n`, 'utf8');
  }

  if (minScoreRaw) {
    const threshold = Number(minScoreRaw);
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
      throw new Error(`Invalid min-score '${minScoreRaw}'; expected a number between 0 and 100.`);
    }
    if (report.overallScore < threshold) {
      console.error(
        `Desktop Security Report Card score ${report.overallScore}/100 (${report.grade}) is below required min-score ${threshold}.`
      );
      process.exitCode = 2;
    }
  }
} finally {
  if (tempKeyDir) {
    fs.rmSync(tempKeyDir, { recursive: true, force: true });
  }
}
