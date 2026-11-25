#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runSecurityReportCard } from '../src/scanner.mjs';
import { renderText } from '../src/renderers/text.mjs';
import { renderMarkdown } from '../src/renderers/markdown.mjs';
import { renderHtml } from '../src/renderers/html.mjs';
import { renderSvgBadge } from '../src/renderers/svg.mjs';
import { buildChromaticPalette, canonicalReportDigest, signReportDigest } from '../src/seal.mjs';
import { verifyReportArtifact } from '../src/verifier.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'package.json'), 'utf8'));

function printHelp() {
  console.log(`
Desktop Security Report Card v${pkg.version}

Usage:
  desktop-security-report-card [target-dir] [options]
  desktop-security-report-card verify <report.html|badge.svg|report.json> [--public-key <pub.pem>]

Options:
  --name <label>         Override application name on the report card
  --binary <path>        Inspect a compiled installer/executable (.exe, .msi, .dmg, .app)
  --format <fmt>         Output format: text | md | html | svg | json (default: text)
  --out <file>           Write output to a file instead of stdout
  --min-score <0-100>    Exit with code 2 if overall score is below threshold
  --sign-key <priv.pem>  Sign the report digest with an Ed25519 private key (PEM)
  --public-key <pub.pem> Verify Ed25519 signature when using 'verify'
  -v, --version          Show version
  -h, --help             Show this help message
`);
}

function parseArgs(argv) {
  const opts = {
    command: 'scan',
    target: '.',
    appName: null,
    binaryPath: null,
    format: 'text',
    outPath: null,
    minScore: null,
    signKeyPath: null,
    publicKeyPath: null,
    help: false,
    version: false,
  };

  let i = 0;
  if (argv[0] === 'verify') {
    opts.command = 'verify';
    i = 1;
  }

  let positionalSet = false;
  for (; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      opts.help = true;
    } else if (arg === '-v' || arg === '--version') {
      opts.version = true;
    } else if (arg === '--name') {
      opts.appName = argv[++i];
    } else if (arg === '--binary') {
      opts.binaryPath = argv[++i];
    } else if (arg === '--format') {
      opts.format = String(argv[++i] || '').toLowerCase();
    } else if (arg === '--out') {
      opts.outPath = argv[++i];
    } else if (arg === '--sign-key') {
      opts.signKeyPath = argv[++i];
    } else if (arg === '--public-key') {
      opts.publicKeyPath = argv[++i];
    } else if (arg === '--min-score') {
      const n = Number(argv[++i]);
      if (!Number.isFinite(n) || n < 0 || n > 100) {
        throw new Error('--min-score must be a number between 0 and 100');
      }
      opts.minScore = n;
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!positionalSet) {
      opts.target = arg;
      positionalSet = true;
    } else {
      throw new Error(`Unexpected positional argument: ${arg}`);
    }
  }

  if (opts.command === 'verify' && !positionalSet && !opts.help && !opts.version) {
    throw new Error('verify requires a path to a generated .html, .svg, or .json report card');
  }
  return opts;
}

function formatReport(report, format, { signature = null } = {}) {
  switch (format) {
    case 'text':
      return renderText(report);
    case 'md':
    case 'markdown':
      return renderMarkdown(report);
    case 'html':
      return renderHtml(report, { signature });
    case 'svg':
      return renderSvgBadge(report, { signature });
    case 'json': {
      const enriched = {
        ...report,
        integrity: {
          digest: canonicalReportDigest(report),
          palette: buildChromaticPalette(report),
          ...(signature ? { signature } : {}),
        },
      };
      return JSON.stringify(enriched, null, 2) + '\n';
    }
    default:
      throw new Error(`Unsupported format '${format}'. Use text, md, html, svg, or json.`);
  }
}

try {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    process.exit(0);
  }
  if (opts.version) {
    console.log(pkg.version);
    process.exit(0);
  }

  if (opts.command === 'verify') {
    const publicKeyPem = opts.publicKeyPath
      ? fs.readFileSync(path.resolve(opts.publicKeyPath), 'utf8')
      : null;
    const result = verifyReportArtifact(opts.target, { publicKeyPem });

    if (opts.format === 'json') {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else if (result.intact) {
      console.log(`VERIFIED: ${result.file}`);
      console.log(`  Displayed score : ${result.displayedScore}/100 (${result.displayedGrade})`);
      if (result.recoveredScore !== null) {
        console.log(`  Embedded seal   : ${result.recoveredScore}/100 (${result.recoveredGrade})`);
      }
      if (result.signatureVerified === true) {
        console.log('  Ed25519 sig     : VALID');
      }
    } else {
      console.error(`TAMPERING OR INTEGRITY FAILURE: ${result.file}`);
      if (result.displayedScore !== null) {
        console.error(`  Displayed score : ${result.displayedScore}/100 (${result.displayedGrade || '?'})`);
      }
      if (result.recoveredScore !== null) {
        console.error(`  Real score      : ${result.recoveredScore}/100 (${result.recoveredGrade})`);
      }
      if (result.recoveredDomains) {
        console.error(`  Real domains    : ${JSON.stringify(result.recoveredDomains)}`);
      }
      for (const issue of result.discrepancies) {
        console.error(`  - ${issue}`);
      }
    }

    process.exit(result.intact ? 0 : 3);
  }

  const report = runSecurityReportCard(opts.target, {
    appName: opts.appName,
    binaryPath: opts.binaryPath,
  });

  let signature = null;
  if (opts.signKeyPath) {
    const privateKeyPem = fs.readFileSync(path.resolve(opts.signKeyPath), 'utf8');
    signature = signReportDigest(canonicalReportDigest(report), privateKeyPem);
  }

  const output = formatReport(report, opts.format, { signature });

  if (opts.outPath) {
    const absOut = path.resolve(opts.outPath);
    fs.mkdirSync(path.dirname(absOut), { recursive: true });
    fs.writeFileSync(absOut, output, 'utf8');
    console.error(
      `Wrote ${opts.format} report card for ${report.appName} (Grade ${report.grade}, ${report.overallScore}/100) to ${absOut}`
    );
  } else {
    process.stdout.write(output);
  }

  if (opts.minScore !== null && report.overallScore < opts.minScore) {
    console.error(
      `Score ${report.overallScore}/100 is below --min-score threshold ${opts.minScore}.`
    );
    process.exit(2);
  }
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
