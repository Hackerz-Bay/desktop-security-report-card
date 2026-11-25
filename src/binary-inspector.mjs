import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return {
    sha256: hash.digest('hex'),
    sizeBytes: data.length,
  };
}

/**
 * Read-only inspection of a compiled desktop installer or executable.
 * Never executes the target binary.
 */
export function inspectBinary(binaryPath) {
  const absPath = path.resolve(binaryPath);
  if (!fs.existsSync(absPath)) {
    throw new Error(`Binary path does not exist: ${absPath}`);
  }

  const stat = fs.statSync(absPath);
  const ext = path.extname(absPath).toLowerCase();
  const base = {
    path: absPath,
    filename: path.basename(absPath),
    extension: ext,
    sha256: stat.isFile() ? sha256File(absPath).sha256 : null,
    sizeBytes: stat.isFile() ? stat.size : null,
    signatureStatus: 'unverified',
    signerSubject: null,
    timestamped: false,
    details: '',
  };

  if (process.platform === 'win32' && ['.exe', '.msi', '.msix', '.dll'].includes(ext)) {
    try {
      const psScript = [
        '$sig = Get-AuthenticodeSignature -LiteralPath $env:DSRC_BINARY_PATH',
        '[pscustomobject]@{',
        '  Status = [string]$sig.Status',
        '  Subject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null }',
        '  HasTimestamp = [bool]($null -ne $sig.TimeStamperCertificate)',
        '  StatusMessage = [string]$sig.StatusMessage',
        '} | ConvertTo-Json -Compress',
      ].join('; ');

      const out = execFileSync(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', psScript],
        {
          env: { ...process.env, DSRC_BINARY_PATH: absPath },
          encoding: 'utf8',
          timeout: 15000,
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      ).trim();

      const parsed = JSON.parse(out);
      const status = String(parsed.Status || '');
      if (status === 'Valid') {
        base.signatureStatus = 'valid';
      } else if (status === 'NotSigned') {
        base.signatureStatus = 'unsigned';
      } else {
        base.signatureStatus = 'invalid';
      }
      base.signerSubject = parsed.Subject || null;
      base.timestamped = Boolean(parsed.HasTimestamp);
      base.details = parsed.StatusMessage || status;
    } catch (err) {
      base.signatureStatus = 'error';
      base.details = `Authenticode inspection failed: ${err.message}`;
    }
    return base;
  }

  if (process.platform === 'darwin' && ['.app', '.dmg', '.pkg'].includes(ext)) {
    try {
      execFileSync('codesign', ['--verify', '--deep', '--strict', absPath], {
        encoding: 'utf8',
        timeout: 15000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      base.signatureStatus = 'valid';
      base.timestamped = true;
      base.details = 'codesign --verify --deep --strict succeeded';
    } catch {
      base.signatureStatus = 'invalid';
      base.details = 'codesign verification failed or binary is unsigned';
    }
    return base;
  }

  base.signatureStatus = 'skipped-platform';
  base.details = `OS-native signature check for ${ext || 'binary'} is only supported on its native OS (${process.platform} host).`;
  return base;
}
