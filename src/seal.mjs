import crypto from 'node:crypto';

const SEAL_VERSION = 1;
const SEAL_SALT = 'dsrc-v1-integrity';

// Six cohesive dark-slate/cyan/navy base high-nibbles for subtle palette encoding.
// Each channel's low nibble (0..15) varies by at most 15/255 (~5.8%), keeping the
// visual palette harmonious while carrying 72 bits (9 bytes) of exact score state.
const BASE_HIGH_NIBBLES = [
  [0x0, 0x1, 0x2],
  [0x1, 0x2, 0x3],
  [0x0, 0x2, 0x4],
  [0x1, 0x3, 0x5],
  [0x2, 0x3, 0x4],
  [0x0, 0x3, 0x4],
];

function clampByte(n, max = 100) {
  return Math.max(0, Math.min(max, Math.round(Number(n) || 0)));
}

function checksumByte(bytes) {
  const hash = crypto
    .createHash('sha256')
    .update(Buffer.from(bytes))
    .update(SEAL_SALT)
    .digest();
  return hash[0];
}

function toHex2(n) {
  return (n & 0xff).toString(16).padStart(2, '0');
}

/**
 * Derive six subtle accent hex colors that encode the exact overall score,
 * all six domain scores, and an 8-bit integrity tag.
 */
export function buildChromaticPalette(report) {
  const domainOrder = [
    'supply-chain',
    'isolation',
    'privileges',
    'secrets-network',
    'auto-update',
    'verification',
  ];
  const domainMap = new Map(report.domainScores.map((d) => [d.id, d.score]));

  const payload = [
    SEAL_VERSION,
    clampByte(report.overallScore, 100),
    ...domainOrder.map((id) => clampByte(domainMap.get(id) ?? 0, 100)),
  ];
  const tag = checksumByte(payload);
  const fullBytes = [...payload, tag]; // 9 bytes = 18 nibbles

  const nibbles = [];
  for (const byte of fullBytes) {
    nibbles.push((byte >> 4) & 0x0f, byte & 0x0f);
  }

  const colors = BASE_HIGH_NIBBLES.map(([hr, hg, hb], idx) => {
    const r = (hr << 4) | nibbles[idx * 3];
    const g = (hg << 4) | nibbles[idx * 3 + 1];
    const b = (hb << 4) | nibbles[idx * 3 + 2];
    return `#${toHex2(r)}${toHex2(g)}${toHex2(b)}`;
  });

  return colors;
}

/**
 * Recover the encoded overall score and six domain scores from the six palette hex colors.
 */
export function decodeChromaticPalette(colors) {
  if (!Array.isArray(colors) || colors.length !== 6) {
    return { valid: false, reason: 'Expected 6 chromatic palette colors' };
  }

  const nibbles = [];
  for (let i = 0; i < 6; i += 1) {
    const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(String(colors[i] || '').trim());
    if (!match) {
      return { valid: false, reason: `Malformed palette color at index ${i}` };
    }
    const r = parseInt(match[1], 16);
    const g = parseInt(match[2], 16);
    const b = parseInt(match[3], 16);
    const [hr, hg, hb] = BASE_HIGH_NIBBLES[i];
    if ((r >> 4) !== hr || (g >> 4) !== hg || (b >> 4) !== hb) {
      return { valid: false, reason: `Palette high-nibble altered at stop ${i}` };
    }
    nibbles.push(r & 0x0f, g & 0x0f, b & 0x0f);
  }

  const bytes = [];
  for (let i = 0; i < 18; i += 2) {
    bytes.push((nibbles[i] << 4) | nibbles[i + 1]);
  }

  const payload = bytes.slice(0, 8);
  const tag = bytes[8];
  if (payload[0] !== SEAL_VERSION) {
    return { valid: false, reason: `Unsupported seal version ${payload[0]}` };
  }
  if (checksumByte(payload) !== tag) {
    return { valid: false, reason: 'Chromatic palette checksum mismatch' };
  }

  const domainOrder = [
    'supply-chain',
    'isolation',
    'privileges',
    'secrets-network',
    'auto-update',
    'verification',
  ];
  const domainScores = {};
  for (let i = 0; i < domainOrder.length; i += 1) {
    domainScores[domainOrder[i]] = payload[2 + i];
  }

  return {
    valid: true,
    overallScore: payload[1],
    domainScores,
  };
}

/**
 * Build a 24-bit geometric matrix (4 rows x 6 cols) for the SVG shield emblem.
 * Layout: 7 bits overallScore | 5 bits passedCount | 5 bits failedCount | 7 bits digest.
 */
export function buildShieldMatrix(report) {
  const applicable = report.controls.filter((c) => c.status !== 'not-applicable');
  const passed = Math.min(31, applicable.filter((c) => c.status === 'pass').length);
  const failed = Math.min(31, applicable.filter((c) => c.status === 'fail').length);
  const score = clampByte(report.overallScore, 100);

  const core17 = (score << 10) | (passed << 5) | failed;
  const digest =
    crypto
      .createHash('sha256')
      .update(`matrix:${score}:${passed}:${failed}:${SEAL_SALT}`)
      .digest()[0] & 0x7f;

  const bits24 = ((core17 << 7) | digest) >>> 0;
  const cells = [];
  for (let i = 23; i >= 0; i -= 1) {
    cells.push((bits24 >>> i) & 1);
  }
  return cells;
}

/**
 * Decode the 24-bit geometric shield matrix back into score + pass/fail counts.
 */
export function decodeShieldMatrix(cells) {
  if (!Array.isArray(cells) || cells.length !== 24) {
    return { valid: false, reason: 'Expected 24 shield matrix cells' };
  }
  let bits24 = 0;
  for (const bit of cells) {
    bits24 = ((bits24 << 1) | (bit ? 1 : 0)) >>> 0;
  }
  const digest = bits24 & 0x7f;
  const core17 = bits24 >>> 7;
  const failed = core17 & 0x1f;
  const passed = (core17 >>> 5) & 0x1f;
  const score = (core17 >>> 10) & 0x7f;

  const expectedDigest =
    crypto
      .createHash('sha256')
      .update(`matrix:${score}:${passed}:${failed}:${SEAL_SALT}`)
      .digest()[0] & 0x7f;

  if (score > 100 || digest !== expectedDigest) {
    return { valid: false, reason: 'Shield geometric matrix checksum mismatch' };
  }
  return {
    valid: true,
    overallScore: score,
    passedCount: passed,
    failedCount: failed,
  };
}

/**
 * Canonical signing payload used for optional Ed25519 cryptographic certification.
 */
export function canonicalReportDigest(report) {
  const canonical = {
    rubricVersion: report.rubricVersion,
    appName: report.appName,
    overallScore: report.overallScore,
    grade: report.grade,
    detectedStacks: [...report.detectedStacks].sort(),
    domainScores: report.domainScores.map((d) => ({
      id: d.id,
      score: d.score,
      passed: d.passed,
      warned: d.warned,
      failed: d.failed,
    })),
    goldStars: report.goldStars.map((s) => s.controlId).sort(),
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

export function signReportDigest(digestHex, privateKeyPem) {
  const signature = crypto.sign(null, Buffer.from(digestHex, 'utf8'), privateKeyPem);
  return signature.toString('base64url');
}

export function verifyReportDigestSignature(digestHex, signatureBase64Url, publicKeyPem) {
  try {
    return crypto.verify(
      null,
      Buffer.from(digestHex, 'utf8'),
      publicKeyPem,
      Buffer.from(signatureBase64Url, 'base64url')
    );
  } catch {
    return false;
  }
}
