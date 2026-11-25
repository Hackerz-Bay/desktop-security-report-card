import fs from 'node:fs';
import path from 'node:path';
import {
  canonicalReportDigest,
  decodeChromaticPalette,
  decodeShieldMatrix,
  verifyReportDigestSignature,
} from './seal.mjs';
import { scoreToGrade } from './scanner.mjs';

function extractSvgPalette(content) {
  const stopRegex = /<stop\s+offset="(?:0|50|100)%"\s+stop-color="(#[0-9a-f]{6})"/gi;
  const colors = [];
  let m;
  while ((m = stopRegex.exec(content)) !== null && colors.length < 6) {
    colors.push(m[1]);
  }
  return colors;
}

function extractCssPalette(content) {
  const colors = [];
  for (let i = 0; i < 6; i += 1) {
    const re = new RegExp(`--surface-tone-${i}\\s*:\\s*(#[0-9a-f]{6})`, 'i');
    const m = re.exec(content);
    if (m) colors.push(m[1]);
  }
  return colors;
}

function extractShieldMatrix(content) {
  const emblemMatch = /<g\s+id="dsrc-emblem">([\s\S]*?)<\/g>/i.exec(content);
  if (!emblemMatch) return [];
  const circleRegex = /<circle\b[^>]*fill-opacity="([0-9.]+)"/gi;
  const bits = [];
  let m;
  while ((m = circleRegex.exec(emblemMatch[1])) !== null && bits.length < 24) {
    bits.push(parseFloat(m[1]) >= 0.4 ? 1 : 0);
  }
  return bits;
}

function extractDisplayedScores(content, kind) {
  const displayed = [];

  // SVG badge score/grade
  const svgScoreMatch = /data-role="score"[^>]*>\s*(\d{1,3})\s*\/\s*100\s*</i.exec(content);
  const svgGradeMatch = /data-role="grade"[^>]*>\s*([A-F][+-]?)\s*</i.exec(content);
  if (svgScoreMatch) {
    displayed.push({
      location: 'svg-badge',
      score: parseInt(svgScoreMatch[1], 10),
      grade: svgGradeMatch ? svgGradeMatch[1] : null,
    });
  }

  const ariaMatch = /aria-label="[^"]*Grade\s+([A-F][+-]?)\s+\((\d{1,3})\/100\)"/i.exec(content);
  if (ariaMatch) {
    displayed.push({
      location: 'svg-aria-label',
      score: parseInt(ariaMatch[2], 10),
      grade: ariaMatch[1],
    });
  }

  if (kind === 'html') {
    const orbScoreMatch = /class="grade-score"[^>]*>\s*(\d{1,3})\s*\/\s*100\s*</i.exec(content);
    const orbGradeMatch = /class="grade-letter"[^>]*>\s*([A-F][+-]?)\s*</i.exec(content);
    if (orbScoreMatch) {
      displayed.push({
        location: 'html-hero',
        score: parseInt(orbScoreMatch[1], 10),
        grade: orbGradeMatch ? orbGradeMatch[1] : null,
      });
    }
  }

  return displayed;
}

/**
 * Verify a generated HTML, SVG, or JSON Desktop Security Report Card for score tampering
 * and optional Ed25519 cryptographic signature validity.
 */
export function verifyReportArtifact(filePath, { publicKeyPem = null } = {}) {
  const absPath = path.resolve(filePath);
  const raw = fs.readFileSync(absPath, 'utf8');
  const ext = path.extname(absPath).toLowerCase();

  if (ext === '.json') {
    const parsed = JSON.parse(raw);
    const computedDigest = canonicalReportDigest(parsed);
    const discrepancies = [];
    const expectedGrade = scoreToGrade(parsed.overallScore);
    if (parsed.grade !== expectedGrade) {
      discrepancies.push(
        `Grade '${parsed.grade}' does not match score ${parsed.overallScore} (expected '${expectedGrade}').`
      );
    }
    if (parsed.integrity?.digest && parsed.integrity.digest !== computedDigest) {
      discrepancies.push('Embedded JSON integrity digest does not match current report payload.');
    }
    if (parsed.integrity?.palette) {
      const pal = decodeChromaticPalette(parsed.integrity.palette);
      if (!pal.valid) {
        discrepancies.push(`Chromatic seal invalid: ${pal.reason}`);
      } else if (pal.overallScore !== parsed.overallScore) {
        discrepancies.push(
          `Displayed score (${parsed.overallScore}) contradicts chromatic seal score (${pal.overallScore}).`
        );
      }
    }

    let signatureVerified = null;
    if (publicKeyPem) {
      const sig = parsed.integrity?.signature;
      signatureVerified = Boolean(sig && verifyReportDigestSignature(computedDigest, sig, publicKeyPem));
      if (!signatureVerified) {
        discrepancies.push('Ed25519 signature missing or invalid for supplied public key.');
      }
    }

    return {
      file: absPath,
      format: 'json',
      intact: discrepancies.length === 0,
      displayedScore: parsed.overallScore,
      displayedGrade: parsed.grade,
      recoveredScore: parsed.integrity?.palette
        ? decodeChromaticPalette(parsed.integrity.palette).overallScore ?? null
        : null,
      recoveredGrade: null,
      signatureVerified,
      discrepancies,
    };
  }

  const kind = ext === '.svg' || raw.trimStart().startsWith('<svg') ? 'svg' : 'html';
  const displayedList = extractDisplayedScores(raw, kind);
  const svgPalette = extractSvgPalette(raw);
  const cssPalette = kind === 'html' ? extractCssPalette(raw) : [];
  const matrixBits = extractShieldMatrix(raw);

  const svgPalDecoded = decodeChromaticPalette(svgPalette);
  const cssPalDecoded = cssPalette.length === 6 ? decodeChromaticPalette(cssPalette) : null;
  const matrixDecoded = decodeShieldMatrix(matrixBits);

  const discrepancies = [];
  const recoveredCandidates = [];

  if (svgPalDecoded.valid) {
    recoveredCandidates.push({ source: 'svg-chromatic-seal', score: svgPalDecoded.overallScore });
  } else {
    discrepancies.push(`SVG chromatic seal invalid or altered (${svgPalDecoded.reason}).`);
  }

  if (cssPalDecoded) {
    if (cssPalDecoded.valid) {
      recoveredCandidates.push({ source: 'css-chromatic-seal', score: cssPalDecoded.overallScore });
    } else {
      discrepancies.push(`HTML palette seal invalid or altered (${cssPalDecoded.reason}).`);
    }
  }

  if (matrixDecoded.valid) {
    recoveredCandidates.push({ source: 'svg-shield-matrix', score: matrixDecoded.overallScore });
  } else {
    discrepancies.push(`SVG shield geometric seal invalid or altered (${matrixDecoded.reason}).`);
  }

  // Cross-check independent seals against each other
  const uniqueRecovered = [...new Set(recoveredCandidates.map((c) => c.score))];
  if (uniqueRecovered.length > 1) {
    discrepancies.push(
      `Independent visual seals disagree: ${recoveredCandidates
        .map((c) => `${c.source}=${c.score}`)
        .join(', ')}.`
    );
  }

  const recoveredScore = uniqueRecovered.length >= 1 ? uniqueRecovered[0] : null;
  const recoveredGrade = recoveredScore !== null ? scoreToGrade(recoveredScore) : null;

  if (displayedList.length === 0) {
    discrepancies.push('Could not extract displayed score from artifact.');
  }

  for (const disp of displayedList) {
    const expectedDisplayedGrade = scoreToGrade(disp.score);
    if (disp.grade && disp.grade !== expectedDisplayedGrade) {
      discrepancies.push(
        `Displayed grade '${disp.grade}' in ${disp.location} does not match displayed score ${disp.score} (expected '${expectedDisplayedGrade}').`
      );
    }
    if (recoveredScore !== null && disp.score !== recoveredScore) {
      discrepancies.push(
        `TAMPERING DETECTED in ${disp.location}: displayed score is ${disp.score} (${
          disp.grade || expectedDisplayedGrade
        }), but the embedded visual seal records the real score as ${recoveredScore} (${recoveredGrade}).`
      );
    }
  }

  let signatureVerified = null;
  if (publicKeyPem) {
    const digestMatch = /data-dsrc-digest="([0-9a-f]{64})"/i.exec(raw);
    const sigMatch = /data-sig="([A-Za-z0-9_-]+)"/i.exec(raw);
    if (!digestMatch || !sigMatch) {
      signatureVerified = false;
      discrepancies.push('No Ed25519 cryptographic signature found in artifact.');
    } else {
      signatureVerified = verifyReportDigestSignature(digestMatch[1], sigMatch[1], publicKeyPem);
      if (!signatureVerified) {
        discrepancies.push('Ed25519 signature verification failed for supplied public key.');
      }
    }
  }

  return {
    file: absPath,
    format: kind,
    intact: discrepancies.length === 0,
    displayedScore: displayedList[0]?.score ?? null,
    displayedGrade: displayedList[0]?.grade ?? null,
    recoveredScore,
    recoveredGrade,
    recoveredDomains: svgPalDecoded.valid
      ? svgPalDecoded.domainScores
      : cssPalDecoded?.valid
      ? cssPalDecoded.domainScores
      : null,
    signatureVerified,
    discrepancies,
  };
}
