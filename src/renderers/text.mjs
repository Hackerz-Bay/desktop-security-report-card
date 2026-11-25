function padRight(str, width) {
  return String(str).padEnd(width, ' ');
}

function statusTag(status) {
  switch (status) {
    case 'pass':
      return '[PASS]';
    case 'warn':
      return '[WARN]';
    case 'fail':
      return '[FAIL]';
    default:
      return '[N/A ]';
  }
}

function bar(score, width = 20) {
  const filled = Math.round((score / 100) * width);
  return '[' + '#'.repeat(filled) + '-'.repeat(Math.max(0, width - filled)) + ']';
}

export function renderText(report) {
  const lines = [];
  lines.push('========================================================================');
  lines.push(`  DESKTOP SECURITY REPORT CARD — ${report.appName}`);
  lines.push('========================================================================');
  lines.push(`  Overall Grade : ${report.grade} (${report.overallScore}/100)`);
  lines.push(`  Stacks        : ${report.detectedStacks.join(', ')}`);
  lines.push(`  Files Scanned : ${report.filesScanned}${report.truncated ? ' (capped)' : ''}`);
  lines.push(
    `  Auto Tests    : ${report.testStats.testFiles} test file(s) (~${report.testStats.estimatedTests} test cases)`
  );
  if (report.binaryInfo) {
    lines.push(
      `  Binary Check  : ${report.binaryInfo.filename} -> ${report.binaryInfo.signatureStatus} (timestamped: ${report.binaryInfo.timestamped})`
    );
  }
  lines.push(`  Rubric        : v${report.rubricVersion} (${report.generatedAt})`);
  lines.push('');

  if (report.goldStars.length > 0) {
    lines.push(`GOLD STARS EARNED (${report.goldStars.length}):`);
    for (const star of report.goldStars) {
      lines.push(`  * [${star.controlId}] ${star.label}`);
    }
    lines.push('');
  }

  lines.push('DOMAIN SCORES:');
  for (const d of report.domainScores) {
    const summary = `${d.passed}/${d.total} pass`;
    lines.push(
      `  ${padRight(d.name, 40)} ${bar(d.score)} ${String(d.score).padStart(3)}% (${padRight(d.grade, 2)})  ${summary}`
    );
  }
  lines.push('');

  lines.push('CONTROLS EVALUATED:');
  for (const c of report.controls) {
    if (c.status === 'not-applicable') continue;
    lines.push(`  ${statusTag(c.status)} ${padRight(c.id, 6)} ${c.title} (${c.guidanceType})`);
    for (const ev of c.evidence) {
      lines.push(`         Evidence: ${ev}`);
    }
  }
  lines.push('');

  if (report.actionItems.length > 0) {
    lines.push('WHAT NEEDS TO BE FIXED (broad grading targets, not step-by-step recipes):');
    for (const item of report.actionItems) {
      const kind = item.guidanceType === 'binary' ? 'Binary Requirement' : 'Security Outcome';
      lines.push(`  - [${item.status.toUpperCase()}] ${item.controlId} ${item.title} (${kind})`);
      lines.push(`    What is graded : ${item.gradedProperty}`);
      lines.push(`    Risk surface   : ${item.attackSurface}`);
      lines.push(`    What to fix    : ${item.whatToFix}`);
    }
  } else {
    lines.push('No failing or warning controls detected across applicable checks.');
  }

  lines.push('');
  lines.push('Note: Static analysis verifies observable repository/binary signals. Combine with');
  lines.push('runtime verification and periodic human review before claiming full assurance.');
  return lines.join('\n') + '\n';
}
