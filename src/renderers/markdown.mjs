function statusBadge(status) {
  switch (status) {
    case 'pass':
      return 'PASS';
    case 'warn':
      return 'WARN';
    case 'fail':
      return 'FAIL';
    default:
      return 'N/A';
  }
}

function escapeCell(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function renderMarkdown(report) {
  const lines = [];
  lines.push(`# Desktop Security Report Card — ${report.appName}`);
  lines.push('');
  lines.push(
    `**Overall Grade:** \`${report.grade}\` (**${report.overallScore}/100**) · **Rubric:** \`v${report.rubricVersion}\` · **Generated:** \`${report.generatedAt}\``
  );
  lines.push('');
  lines.push(`- **Detected Stacks:** ${report.detectedStacks.map((s) => `\`${s}\``).join(', ')}`);
  lines.push(`- **Files Scanned:** ${report.filesScanned}${report.truncated ? ' (capped)' : ''}`);
  lines.push(
    `- **Automated Tests Detected:** ${report.testStats.testFiles} test files (~${report.testStats.estimatedTests} test cases)`
  );
  if (report.binaryInfo) {
    lines.push(
      `- **Binary Inspected:** \`${report.binaryInfo.filename}\` — signature: \`${report.binaryInfo.signatureStatus}\`, timestamped: \`${report.binaryInfo.timestamped}\`${
        report.binaryInfo.sha256 ? `, SHA-256: \`${report.binaryInfo.sha256}\`` : ''
      }`
    );
  }
  lines.push('');

  if (report.goldStars.length > 0) {
    lines.push(`## Gold Stars Earned (${report.goldStars.length})`);
    lines.push('');
    for (const star of report.goldStars) {
      lines.push(`- **${star.label}** (\`${star.controlId}\`)`);
    }
    lines.push('');
  }

  lines.push('## Domain Breakdown');
  lines.push('');
  lines.push('| Domain | Score | Grade | Pass | Warn | Fail |');
  lines.push('| --- | ---: | :---: | ---: | ---: | ---: |');
  for (const d of report.domainScores) {
    lines.push(
      `| ${escapeCell(d.name)} | ${d.score}% | **${d.grade}** | ${d.passed} | ${d.warned} | ${d.failed} |`
    );
  }
  lines.push('');

  lines.push('## What Needs to Be Fixed');
  lines.push('');
  lines.push(
    '> **Grading policy:** Binary supply-chain controls state the exact requirement (you either do it or you do not). General security boundaries and attack-vector findings state **what is graded** and **what needs to be fixed** — never step-by-step fix recipes.'
  );
  lines.push('');

  if (report.actionItems.length === 0) {
    lines.push('All applicable automated controls passed.');
  } else {
    for (const item of report.actionItems) {
      const kind = item.guidanceType === 'binary' ? 'Binary Requirement' : 'Security Outcome';
      lines.push(`### [${item.status.toUpperCase()}] ${item.controlId} — ${item.title} (${kind})`);
      lines.push('');
      lines.push(`- **What is graded:** ${item.gradedProperty}`);
      lines.push(`- **Risk surface:** ${item.attackSurface}`);
      lines.push(`- **What needs to be fixed:** ${item.whatToFix}`);
      lines.push(`- **Observed evidence:** ${item.evidence.join(' | ')}`);
      lines.push('');
    }
  }

  lines.push('## All Applicable Controls');
  lines.push('');
  lines.push('| ID | Control | Type | Status | Evidence |');
  lines.push('| --- | --- | --- | :---: | --- |');
  for (const c of report.controls) {
    if (c.status === 'not-applicable') continue;
    lines.push(
      `| \`${c.id}\` | ${escapeCell(c.title)} | \`${c.guidanceType}\` | **${statusBadge(c.status)}** | ${escapeCell(
        c.evidence.join('; ')
      )} |`
    );
  }
  lines.push('');
  return lines.join('\n');
}
