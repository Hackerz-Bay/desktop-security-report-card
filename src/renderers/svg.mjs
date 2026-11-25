import { buildChromaticPalette, buildShieldMatrix, canonicalReportDigest } from '../seal.mjs';

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function accentForScore(score) {
  if (score >= 85) return '#34d399';
  if (score >= 70) return '#fbbf24';
  return '#f87171';
}

/**
 * Render a standalone or inline SVG Desktop Security Report Card shield badge.
 */
export function renderSvgBadge(report, { signature = null } = {}) {
  const palette = buildChromaticPalette(report);
  const matrix = buildShieldMatrix(report);
  const accent = accentForScore(report.overallScore);
  const digest = canonicalReportDigest(report);

  const dots = [];
  for (let row = 0; row < 4; row += 1) {
    for (let col = 0; col < 6; col += 1) {
      const bit = matrix[row * 6 + col];
      const cx = 24 + col * 8;
      const cy = 22 + row * 8;
      const opacity = bit ? '0.62' : '0.18';
      dots.push(`<circle cx="${cx}" cy="${cy}" r="2.1" fill="${accent}" fill-opacity="${opacity}"/>`);
    }
  }

  const starText = `${report.goldStars.length} Gold Star${report.goldStars.length === 1 ? '' : 's'}`;
  const sigAttr = signature ? ` data-sig="${esc(signature)}"` : '';

  return `<svg xmlns="http://www.w3.org/2000/svg" width="380" height="92" viewBox="0 0 380 92" role="img" aria-label="Desktop Security Report Card: ${esc(
    report.appName
  )} Grade ${esc(report.grade)} (${report.overallScore}/100)" data-dsrc-digest="${esc(digest)}"${sigAttr}>
  <defs>
    <linearGradient id="dsrc-bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${palette[0]}"/>
      <stop offset="50%" stop-color="${palette[1]}"/>
      <stop offset="100%" stop-color="${palette[2]}"/>
    </linearGradient>
    <linearGradient id="dsrc-rim" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="${palette[3]}"/>
      <stop offset="50%" stop-color="${palette[4]}"/>
      <stop offset="100%" stop-color="${palette[5]}"/>
    </linearGradient>
  </defs>
  <rect x="1.5" y="1.5" width="377" height="89" rx="14" fill="url(#dsrc-bg)" stroke="url(#dsrc-rim)" stroke-width="2"/>
  <g id="dsrc-emblem">
    <path d="M44 10 L74 18 V44 C74 62 61 74 44 82 C27 74 14 62 14 44 V18 Z" fill="rgba(7,11,20,0.55)" stroke="${accent}" stroke-width="1.5"/>
    ${dots.join('\n    ')}
  </g>
  <text x="92" y="28" fill="#38bdf8" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="10" font-weight="700" letter-spacing="1.4">DESKTOP SECURITY REPORT CARD</text>
  <text x="92" y="51" fill="#f8fafc" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="17" font-weight="700">${esc(
    report.appName.slice(0, 24)
  )}</text>
  <text x="92" y="72" fill="#94a3b8" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="12">${esc(
    starText
  )} · Rubric v${esc(report.rubricVersion)}</text>
  <g id="dsrc-score-box">
    <rect x="304" y="14" width="62" height="64" rx="12" fill="rgba(7,11,20,0.72)" stroke="${accent}" stroke-width="1.75"/>
    <text x="335" y="48" text-anchor="middle" fill="${accent}" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="24" font-weight="800" data-role="grade">${esc(
    report.grade
  )}</text>
    <text x="335" y="67" text-anchor="middle" fill="#cbd5e1" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="11" font-weight="600" data-role="score">${report.overallScore}/100</text>
  </g>
</svg>
`;
}
