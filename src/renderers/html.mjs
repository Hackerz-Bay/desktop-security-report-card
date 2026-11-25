import { buildChromaticPalette } from '../seal.mjs';
import { renderSvgBadge } from './svg.mjs';

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function gradeColor(score) {
  if (score >= 85) return '#34d399';
  if (score >= 70) return '#fbbf24';
  return '#f87171';
}

function statusPillClass(status) {
  if (status === 'pass') return 'pill-pass';
  if (status === 'warn') return 'pill-warn';
  return 'pill-fail';
}

export function renderHtml(report, { signature = null } = {}) {
  const accent = gradeColor(report.overallScore);
  const tones = buildChromaticPalette(report);
  const badgeSvg = renderSvgBadge(report, { signature });

  const goldStarsHtml =
    report.goldStars.length > 0
      ? report.goldStars
          .map(
            (s) =>
              `<div class="star-chip"><span class="star-icon" aria-hidden="true">&#9733;</span><span>${esc(
                s.label
              )}</span><code>${esc(s.controlId)}</code></div>`
          )
          .join('')
      : '<p class="muted">No Gold Stars earned yet. Complete verified supply-chain, isolation, ACL, or testing controls to unlock Gold Stars.</p>';

  const domainsHtml = report.domainScores
    .map(
      (d) => `
      <div class="domain-card">
        <div class="domain-head">
          <div>
            <h3>${esc(d.name)}</h3>
            <p class="muted small">${esc(d.description)}</p>
          </div>
          <div class="domain-grade" style="color:${gradeColor(d.score)}">${esc(d.grade)} <span>${d.score}%</span></div>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width:${d.score}%;background:${gradeColor(
          d.score
        )}"></div></div>
        <div class="domain-meta">
          <span>${d.passed} pass</span>
          <span>${d.warned} warn</span>
          <span>${d.failed} fail</span>
          <span>Weight ${d.weight}%</span>
        </div>
      </div>`
    )
    .join('');

  const actionItemsHtml =
    report.actionItems.length === 0
      ? '<div class="empty-state">Every applicable control passed automated evaluation.</div>'
      : report.actionItems
          .map((item) => {
            const kindLabel =
              item.guidanceType === 'binary' ? 'Binary Requirement' : 'Broad Security Outcome';
            return `
            <article class="finding-card finding-${esc(item.status)}">
              <div class="finding-head">
                <div class="finding-title">
                  <span class="pill ${statusPillClass(item.status)}">${esc(
                    item.status.toUpperCase()
                  )}</span>
                  <code>${esc(item.controlId)}</code>
                  <h3>${esc(item.title)}</h3>
                </div>
                <span class="kind-tag">${esc(kindLabel)}</span>
              </div>
              <dl class="finding-grid">
                <div><dt>What Is Graded</dt><dd>${esc(item.gradedProperty)}</dd></div>
                <div><dt>Risk Surface</dt><dd>${esc(item.attackSurface)}</dd></div>
                <div><dt>What Needs to Be Fixed</dt><dd class="fix-target">${esc(
                  item.whatToFix
                )}</dd></div>
                <div><dt>Observed Evidence</dt><dd>${esc(item.evidence.join(' | '))}</dd></div>
              </dl>
            </article>`;
          })
          .join('');

  const watchlistHtml = report.aiEraWatchlist
    .map(
      (w) => `
      <details class="watch-item">
        <summary>
          <span class="watch-title">${esc(w.title)}</span>
          <span class="watch-tip">Inspect red flag</span>
        </summary>
        <p><strong>Red flag:</strong> ${esc(w.redFlag)}</p>
        <p class="muted"><strong>Why it matters in the AI era:</strong> ${esc(w.whyItMatters)}</p>
      </details>`
    )
    .join('');

  const controlsTableRows = report.controls
    .filter((c) => c.status !== 'not-applicable')
    .map(
      (c) => `
      <tr>
        <td><code>${esc(c.id)}</code></td>
        <td><strong>${esc(c.title)}</strong><div class="muted small">${esc(c.gradedProperty)}</div></td>
        <td><span class="kind-tag">${esc(
          c.guidanceType === 'binary' ? 'Binary' : 'Outcome'
        )}</span></td>
        <td><span class="pill ${statusPillClass(c.status)}">${esc(c.status.toUpperCase())}</span></td>
        <td class="small">${esc(c.evidence.join('; '))}</td>
      </tr>`
    )
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Desktop Security Report Card — ${esc(report.appName)}</title>
  <style>
    :root {
      --bg: #070b14;
      --surface: #0f172a;
      --surface-2: #131f38;
      --surface-tone-0: ${tones[0]};
      --surface-tone-1: ${tones[1]};
      --surface-tone-2: ${tones[2]};
      --surface-tone-3: ${tones[3]};
      --surface-tone-4: ${tones[4]};
      --surface-tone-5: ${tones[5]};
      --border: #24324d;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --gold: #f59e0b;
      --pass: #34d399;
      --warn: #fbbf24;
      --fail: #f87171;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: radial-gradient(circle at top right, var(--surface-tone-2) 0%, var(--bg) 55%);
      color: var(--text);
      line-height: 1.55;
    }
    .container { max-width: 1120px; margin: 0 auto; padding: 32px 20px 64px; }
    .hero {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 24px;
      align-items: center;
      background: linear-gradient(135deg, var(--surface-tone-0), var(--surface-tone-1));
      border: 1px solid var(--surface-tone-4);
      border-radius: 18px;
      padding: 28px;
      margin-bottom: 28px;
    }
    .badge-wrap { margin-top: 16px; }
    .badge-wrap svg { max-width: 100%; height: auto; display: block; }
    .eyebrow {
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 12px;
      color: #38bdf8;
      font-weight: 700;
      margin: 0 0 6px;
    }
    h1 { margin: 0 0 8px; font-size: 30px; line-height: 1.15; }
    h2 { margin: 32px 0 12px; font-size: 20px; }
    h3 { margin: 0; font-size: 16px; }
    .muted { color: var(--muted); }
    .small { font-size: 13px; }
    .grade-orb {
      width: 136px;
      height: 136px;
      border-radius: 50%;
      border: 4px solid ${accent};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: rgba(7,11,20,0.7);
      box-shadow: 0 0 32px rgba(52,211,153,0.16);
    }
    .grade-letter { font-size: 46px; font-weight: 800; color: ${accent}; line-height: 1; }
    .grade-score { font-size: 14px; color: var(--muted); margin-top: 4px; }
    .meta-strip { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
    .meta-pill {
      background: rgba(148,163,184,0.1);
      border: 1px solid var(--border);
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
    }
    .stars-wrap { display: flex; flex-wrap: wrap; gap: 10px; }
    .star-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(245,158,11,0.12);
      border: 1px solid rgba(245,158,11,0.45);
      color: #fde68a;
      padding: 8px 12px;
      border-radius: 12px;
      font-size: 13px;
      font-weight: 600;
    }
    .star-icon { color: var(--gold); font-size: 15px; }
    .domains-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
      gap: 16px;
    }
    .domain-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
    }
    .domain-head { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }
    .domain-grade { font-size: 22px; font-weight: 800; white-space: nowrap; }
    .domain-grade span { font-size: 13px; font-weight: 600; color: var(--muted); }
    .bar-track { height: 8px; background: #1e293b; border-radius: 999px; overflow: hidden; margin: 12px 0 10px; }
    .bar-fill { height: 100%; border-radius: 999px; }
    .domain-meta { display: flex; justify-content: space-between; font-size: 12px; color: var(--muted); }
    .policy-banner {
      background: rgba(56,189,248,0.08);
      border: 1px solid rgba(56,189,248,0.3);
      border-radius: 12px;
      padding: 14px 16px;
      font-size: 13px;
      margin-bottom: 16px;
    }
    .finding-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 4px solid var(--warn);
      border-radius: 12px;
      padding: 18px;
      margin-bottom: 14px;
    }
    .finding-fail { border-left-color: var(--fail); }
    .finding-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
    .finding-title { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .finding-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin: 0; }
    .finding-grid dt { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 700; margin-bottom: 4px; }
    .finding-grid dd { margin: 0; font-size: 13px; }
    .fix-target { color: #f8fafc; font-weight: 500; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }
    .pill-pass { background: rgba(52,211,153,0.16); color: var(--pass); }
    .pill-warn { background: rgba(251,191,36,0.16); color: var(--warn); }
    .pill-fail { background: rgba(248,113,113,0.16); color: var(--fail); }
    .kind-tag { font-size: 11px; padding: 3px 8px; border-radius: 6px; background: rgba(148,163,184,0.12); color: var(--muted); }
    .watch-item {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 10px;
    }
    .watch-item summary { cursor: pointer; display: flex; justify-content: space-between; align-items: center; font-weight: 600; }
    .watch-tip { font-size: 12px; color: #38bdf8; }
    table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); background: var(--surface-2); }
    code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; background: rgba(148,163,184,0.12); padding: 2px 6px; border-radius: 4px; }
    .empty-state { background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.35); border-radius: 12px; padding: 18px; color: var(--pass); }
    footer { margin-top: 40px; font-size: 12px; color: var(--muted); text-align: center; }
    @media (max-width: 720px) { .hero { grid-template-columns: 1fr; } .grade-orb { margin: 0 auto; } }
  </style>
</head>
<body>
  <main class="container">
    <section class="hero">
      <div>
        <p class="eyebrow">Desktop Security Report Card &middot; Rubric v${esc(report.rubricVersion)}</p>
        <h1>${esc(report.appName)}</h1>
        <p class="muted">${esc(report.philosophy.summary)}</p>
        <div class="meta-strip">
          <span class="meta-pill">Stacks: ${esc(report.detectedStacks.join(', '))}</span>
          <span class="meta-pill">Files scanned: ${report.filesScanned}</span>
          <span class="meta-pill">Auto tests: ${report.testStats.testFiles} files (~${report.testStats.estimatedTests} cases)</span>
          <span class="meta-pill">Generated: ${esc(report.generatedAt)}</span>
        </div>
        <div class="badge-wrap">${badgeSvg}</div>
      </div>
      <div class="grade-orb" aria-label="Overall security grade ${esc(report.grade)} (${report.overallScore} out of 100)">
        <div class="grade-letter">${esc(report.grade)}</div>
        <div class="grade-score">${report.overallScore} / 100</div>
      </div>
    </section>

    <section>
      <h2>Gold Stars Earned (${report.goldStars.length})</h2>
      <div class="stars-wrap">${goldStarsHtml}</div>
    </section>

    <section>
      <h2>Domain Breakdown</h2>
      <div class="domains-grid">${domainsHtml}</div>
    </section>

    <section>
      <h2>What Needs to Be Fixed</h2>
      <div class="policy-banner">
        <strong>Broad-outcome grading policy:</strong> Concrete binary requirements (such as code signing certificates, published checksums, and build provenance) are stated directly. General architectural controls and vulnerability surfaces specify <em>what is graded</em> and <em>what needs to be fixed</em> rather than prescriptive step-by-step fix recipes.
      </div>
      ${actionItemsHtml}
    </section>

    <section>
      <h2>AI-Era Desktop Safety Watchlist</h2>
      <p class="muted small">What users should look for before installing any desktop application in an era where convincing malware and AI-generated apps are easy to build:</p>
      ${watchlistHtml}
    </section>

    <section>
      <h2>Complete Control Matrix</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Control &amp; Graded Property</th><th>Type</th><th>Status</th><th>Evidence</th></tr>
        </thead>
        <tbody>${controlsTableRows}</tbody>
      </table>
    </section>

    <footer>
      Generated by <strong>@hackerzbay/desktop-security-report-card</strong> &middot; Static signals complement runtime testing and human security review.
    </footer>
  </main>
</body>
</html>
`;
}
