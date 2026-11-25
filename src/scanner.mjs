import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { countAutomatedTests, walkProject } from './file-walker.mjs';
import { detectStacks } from './detect-stack.mjs';
import { inspectBinary } from './binary-inspector.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RUBRIC_PATH = path.resolve(__dirname, '..', 'rubric', 'controls.json');

export function loadRubric() {
  return JSON.parse(fs.readFileSync(RUBRIC_PATH, 'utf8'));
}

function nonTestFiles(project, predicate = () => true) {
  return project.files.filter((f) => !f.isTest && predicate(f));
}

function findMatches(project, files, regex, { limit = 5 } = {}) {
  const hits = [];
  for (const file of files) {
    const text = project.readText(file);
    if (!text) continue;
    if (regex.test(text)) {
      hits.push(file.rel);
      if (hits.length >= limit) break;
    }
  }
  return hits;
}

function isControlApplicable(control, stacks) {
  return control.stacks.some((s) => stacks.includes(s));
}

function evaluateControl(control, ctx) {
  const { project, stacks, binaryInfo, testStats } = ctx;
  const workflows = project.files.filter(
    (f) => f.rel.startsWith('.github/workflows/') && /\.(yml|yaml)$/.test(f.ext)
  );
  const allNonTest = nonTestFiles(project);
  const codeFiles = nonTestFiles(project, (f) =>
    ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.cs', '.rs', '.go', '.swift', '.ps1'].includes(f.ext)
  );
  const electronJsFiles = nonTestFiles(project, (f) =>
    ['.js', '.mjs', '.cjs', '.ts'].includes(f.ext)
  );
  const installerFiles = nonTestFiles(project, (f) =>
    ['.nsi', '.nsh', '.wxs', '.iss', '.ps1'].includes(f.ext) ||
    /electron-builder\.(yml|yaml|json)$/i.test(f.name) ||
    f.name === 'package.json'
  );

  switch (control.id) {
    case 'SC-01': {
      if (binaryInfo) {
        if (binaryInfo.signatureStatus === 'valid' && binaryInfo.timestamped) {
          return {
            status: 'pass',
            evidence: [
              `Verified trusted signature on ${binaryInfo.filename} with RFC 3161 timestamp`,
              binaryInfo.signerSubject ? `Signer: ${binaryInfo.signerSubject}` : null,
            ].filter(Boolean),
          };
        }
        if (binaryInfo.signatureStatus === 'valid' && !binaryInfo.timestamped) {
          return {
            status: 'warn',
            evidence: [`${binaryInfo.filename} is signed, but no trusted timestamp certificate was detected.`],
          };
        }
        if (binaryInfo.signatureStatus === 'unsigned' || binaryInfo.signatureStatus === 'invalid') {
          return {
            status: 'fail',
            evidence: [`${binaryInfo.filename}: ${binaryInfo.signatureStatus} (${binaryInfo.details})`],
          };
        }
      }

      const signingHits = findMatches(
        project,
        [...workflows, ...installerFiles],
        /(artifact-signing-action|TrustedSigning|azureSign|signtool|codesign|notarytool|appleId|certificateFile|signAndEditExecutable|publisherName|signtoolOptions)/i
      );
      const timestampHits = findMatches(
        project,
        [...workflows, ...installerFiles],
        /(timestamp-rfc3161|TimeStampServer|timestamp\.acs\.microsoft\.com|rfc3161|\/tr\s+https?:\/\/|--timestamp)/i
      );
      if (signingHits.length > 0 && timestampHits.length > 0) {
        return {
          status: 'pass',
          evidence: [
            `Code-signing pipeline configured in ${signingHits.join(', ')}`,
            `Trusted timestamping configured in ${timestampHits.join(', ')}`,
          ],
        };
      }
      if (signingHits.length > 0) {
        return {
          status: 'warn',
          evidence: [
            `Code-signing references found (${signingHits.join(', ')}), but trusted timestamping was not confirmed.`,
          ],
        };
      }
      return {
        status: 'fail',
        evidence: ['No code-signing configuration or verified binary signature detected.'],
      };
    }

    case 'SC-02': {
      const checksumHits = findMatches(
        project,
        [...workflows, ...allNonTest],
        /(SHA256SUMS\.txt|sha256sum|Get-FileHash\b.*SHA256|checksums\.txt|checksums_url)/i
      );
      if (checksumHits.length > 0) {
        return {
          status: 'pass',
          evidence: [`SHA-256 checksum generation/publishing detected in ${checksumHits.join(', ')}`],
        };
      }
      return {
        status: 'fail',
        evidence: ['No published SHA-256 checksum generation (e.g., SHA256SUMS.txt) detected.'],
      };
    }

    case 'SC-03': {
      const provenanceHits = findMatches(
        project,
        workflows,
        /(actions\/attest-build-provenance|slsa-github-generator|cosign\s+attest|attestations:\s*write)/i
      );
      if (provenanceHits.length > 0) {
        return {
          status: 'pass',
          evidence: [`SLSA / build provenance attestation configured in ${provenanceHits.join(', ')}`],
        };
      }
      return {
        status: 'fail',
        evidence: ['No SLSA build provenance attestation workflow detected.'],
      };
    }

    case 'SC-04': {
      const lockfiles = project.files.filter((f) =>
        [
          'package-lock.json',
          'pnpm-lock.yaml',
          'yarn.lock',
          'uv.lock',
          'poetry.lock',
          'Cargo.lock',
          'packages.lock.json',
          'Pipfile.lock',
        ].includes(f.name)
      );
      const vulnScanHits = findMatches(
        project,
        [...workflows, ...project.files.filter((f) => f.rel.startsWith('.github/'))],
        /(osv-scanner|npm\s+audit|pip-audit|cargo-audit|dependabot|snyk|trivy|dotnet\s+list\s+.*--vulnerable)/i
      );
      if (lockfiles.length > 0 && vulnScanHits.length > 0) {
        return {
          status: 'pass',
          evidence: [
            `Committed lockfile(s): ${lockfiles.slice(0, 4).map((f) => f.rel).join(', ')}`,
            `Automated dependency vulnerability scanning in ${vulnScanHits.join(', ')}`,
          ],
        };
      }
      if (lockfiles.length > 0) {
        return {
          status: 'warn',
          evidence: [
            `Committed lockfile(s) found (${lockfiles.slice(0, 3).map((f) => f.rel).join(', ')}), but no CI dependency CVE scanner detected.`,
          ],
        };
      }
      return {
        status: 'fail',
        evidence: ['No committed dependency lockfiles or CI vulnerability scanners detected.'],
      };
    }

    case 'SC-05': {
      const policyFiles = project.files.filter((f) =>
        /(^|\/)(SECURITY\.md|\.github\/SECURITY\.md|.*\.well-known\/security\.txt)$/i.test(f.rel)
      );
      if (policyFiles.length > 0) {
        return {
          status: 'pass',
          evidence: [`Vulnerability disclosure file(s): ${policyFiles.map((f) => f.rel).join(', ')}`],
        };
      }
      return {
        status: 'fail',
        evidence: ['Neither SECURITY.md nor .well-known/security.txt was found.'],
      };
    }

    case 'IS-01': {
      const badIsolation = findMatches(
        project,
        electronJsFiles,
        /(contextIsolation\s*:\s*false|nodeIntegration\s*:\s*true|enableRemoteModule\s*:\s*true)/
      );
      const goodIsolation = findMatches(
        project,
        electronJsFiles,
        /contextIsolation\s*:\s*true/
      );
      const goodNoNode = findMatches(
        project,
        electronJsFiles,
        /nodeIntegration\s*:\s*false/
      );
      const sandboxOff = findMatches(project, electronJsFiles, /sandbox\s*:\s*false/);

      if (badIsolation.length > 0) {
        return {
          status: 'fail',
          evidence: [`Unsafe renderer isolation settings detected in ${badIsolation.join(', ')}`],
        };
      }
      if (goodIsolation.length > 0 && goodNoNode.length > 0 && sandboxOff.length === 0) {
        return {
          status: 'pass',
          evidence: [`Renderer isolation enforced in ${goodIsolation.join(', ')}`],
        };
      }
      if (goodIsolation.length > 0 && sandboxOff.length > 0) {
        return {
          status: 'warn',
          evidence: [
            `Context isolation found (${goodIsolation.join(', ')}), but sandbox is explicitly disabled in ${sandboxOff.join(', ')}.`,
          ],
        };
      }
      return {
        status: 'warn',
        evidence: ['Electron detected, but explicit BrowserWindow webPreferences isolation settings were not confirmed.'],
      };
    }

    case 'IS-02': {
      const webSecOff = findMatches(project, electronJsFiles, /webSecurity\s*:\s*false/);
      const cspHits = findMatches(
        project,
        nonTestFiles(project, (f) => ['.js', '.mjs', '.cjs', '.ts', '.html', '.htm'].includes(f.ext)),
        /Content-Security-Policy/i
      );
      const unsafeEvalCsp = findMatches(
        project,
        nonTestFiles(project, (f) => ['.js', '.mjs', '.cjs', '.ts', '.html', '.htm'].includes(f.ext)),
        /Content-Security-Policy[^\n]{0,300}'unsafe-eval'/i
      );

      if (webSecOff.length > 0) {
        return {
          status: 'fail',
          evidence: [`webSecurity is disabled in ${webSecOff.join(', ')}`],
        };
      }
      if (cspHits.length > 0 && unsafeEvalCsp.length === 0) {
        return {
          status: 'pass',
          evidence: [`Web security intact and Content-Security-Policy enforced in ${cspHits.join(', ')}`],
        };
      }
      if (cspHits.length > 0 && unsafeEvalCsp.length > 0) {
        return {
          status: 'warn',
          evidence: [`CSP is present (${cspHits.join(', ')}), but includes permissive script directives.`],
        };
      }
      return {
        status: 'fail',
        evidence: ['No Content-Security-Policy enforcement detected for Electron windows.'],
      };
    }

    case 'IS-03': {
      const fuseHits = findMatches(
        project,
        nonTestFiles(project, (f) => ['.js', '.mjs', '.cjs', '.ts', '.json', '.yml', '.yaml'].includes(f.ext)),
        /(@electron\/fuses|flipFuses|FuseV1Options)/
      );
      if (fuseHits.length > 0) {
        return {
          status: 'pass',
          evidence: [`Electron fuses configured in ${fuseHits.join(', ')}`],
        };
      }
      return {
        status: 'fail',
        evidence: ['No @electron/fuses binary hardening configuration detected.'],
      };
    }

    case 'IS-04': {
      const tauriConf = project.files.filter((f) => f.name === 'tauri.conf.json');
      if (tauriConf.length === 0) {
        return {
          status: 'warn',
          evidence: ['Tauri detected, but tauri.conf.json was not found to inspect CSP/capabilities.'],
        };
      }
      const confText = project.readText(tauriConf[0]);
      const nullCsp = /"csp"\s*:\s*null/.test(confText);
      const wildcardShell = /"shell"\s*:\s*\{[^}]*"all"\s*:\s*true/s.test(confText);
      if (nullCsp || wildcardShell) {
        return {
          status: 'fail',
          evidence: [
            nullCsp ? `${tauriConf[0].rel} sets security.csp to null` : null,
            wildcardShell ? `${tauriConf[0].rel} grants unrestricted shell permissions` : null,
          ].filter(Boolean),
        };
      }
      return {
        status: 'pass',
        evidence: [`${tauriConf[0].rel} enforces non-null CSP and avoids wildcard shell grants.`],
      };
    }

    case 'IS-05': {
      const shellInjectionRisk = findMatches(
        project,
        codeFiles,
        /(execSync|child_process\.exec\s*\(|subprocess\.(?:run|Popen|call)\([^)]*shell\s*=\s*True|os\.system\s*\()/
      );
      const navGuards = findMatches(
        project,
        codeFiles,
        /(setWindowOpenHandler|will-navigate|allowedProtocols|https?:|ValidateUri|UriSchemeHttps)/i
      );
      if (shellInjectionRisk.length > 0 && navGuards.length === 0) {
        return {
          status: 'fail',
          evidence: [
            `Shell-interpreted process execution patterns found in ${shellInjectionRisk.join(', ')} without clear navigation/URL boundary guards.`,
          ],
        };
      }
      if (shellInjectionRisk.length > 0) {
        return {
          status: 'warn',
          evidence: [
            `Navigation/URL boundary checks found (${navGuards.join(', ')}), but shell-interpreted command execution patterns appear in ${shellInjectionRisk.join(', ')} and warrant review.`,
          ],
        };
      }
      if (navGuards.length > 0) {
        return {
          status: 'pass',
          evidence: [`URL/navigation boundary enforcement detected in ${navGuards.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['No obvious shell-injection patterns found, but explicit external-URL/navigation boundary guards were not detected.'],
      };
    }

    case 'PR-01': {
      const worldWritableGrant = findMatches(
        project,
        installerFiles,
        /(icacls\s+[^\n]*(?:ProgramData|Program Files)[^\n]*(?:Users|Everyone|\*S-1-5-32-545|\*S-1-1-0):[^\n]*\([A-Z()]*[MFW]|chmod\s+(?:-R\s+)?0?777)/i
      );
      const lockedAcl = findMatches(
        project,
        installerFiles,
        /(icacls\s+[^\n]*\/inheritance:r[^\n]*\*S-1-5-18|icacls\s+[^\n]*\/remove(?::g)?\s+\*S-1-5-32-545|chmod\s+0?[67]00)/i
      );

      if (worldWritableGrant.length > 0 && lockedAcl.length === 0) {
        return {
          status: 'fail',
          evidence: [
            `Broad standard-user/world write permission grant detected in ${worldWritableGrant.join(', ')} without explicit ACL lockdown on privileged subdirectories.`,
          ],
        };
      }
      if (lockedAcl.length > 0) {
        return {
          status: 'pass',
          evidence: [`Explicit least-privilege directory ACL hardening detected in ${lockedAcl.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['No broad world-writable grants detected; verify privileged service/install directories enforce administrative-only write ACLs.'],
      };
    }

    case 'PR-02': {
      const badInstallerPatterns = findMatches(
        project,
        installerFiles,
        /(netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off|AllowAll|binPath=\s*[^"'\s][^\n]*\s)/i
      );
      const uninstallHygiene = findMatches(
        project,
        installerFiles,
        /(customUnInstall|uninstall|sc\.exe\s+delete|Remove-Service|deleteAppDataOnUninstall|nsis)/i
      );
      if (badInstallerPatterns.length > 0) {
        return {
          status: 'fail',
          evidence: [`Risky installer/service pattern detected in ${badInstallerPatterns.join(', ')}`],
        };
      }
      if (uninstallHygiene.length > 0) {
        return {
          status: 'pass',
          evidence: [`Installer lifecycle & service hygiene hooks detected in ${uninstallHygiene.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['Packaging configuration detected, but service/uninstaller boundary hygiene could not be fully verified statically.'],
      };
    }

    case 'PR-03': {
      const entitlements = project.files.filter((f) => f.ext === '.entitlements');
      const riskyEntitlements = findMatches(
        project,
        entitlements,
        /(disable-library-validation|allow-unsigned-executable-memory|disable-executable-page-protection)/
      );
      const hardenedRuntime = findMatches(
        project,
        [...allNonTest, ...workflows],
        /(hardenedRuntime\s*:\s*true|--options\s+runtime|ENABLE_HARDENED_RUNTIME\s*=\s*YES)/
      );
      if (riskyEntitlements.length > 0) {
        return {
          status: 'fail',
          evidence: [`Relaxed macOS runtime entitlements found in ${riskyEntitlements.join(', ')}`],
        };
      }
      if (hardenedRuntime.length > 0) {
        return {
          status: 'pass',
          evidence: [`macOS Hardened Runtime enabled in ${hardenedRuntime.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['macOS artifacts detected, but Hardened Runtime enforcement was not confirmed.'],
      };
    }

    case 'SD-01': {
      const hardcodedSecretHits = findMatches(
        project,
        codeFiles,
        /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,})/
      );
      const osKeychainHits = findMatches(
        project,
        codeFiles,
        /(safeStorage|ProtectedData\.Protect|DPAPI|keytar|keyring|SecItemAdd|CredentialManager)/
      );
      if (hardcodedSecretHits.length > 0) {
        return {
          status: 'fail',
          evidence: [`High-confidence credential pattern found in ${hardcodedSecretHits.join(', ')}`],
        };
      }
      if (osKeychainHits.length > 0) {
        return {
          status: 'pass',
          evidence: [`OS-protected secret storage usage detected in ${osKeychainHits.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['No hardcoded private keys/tokens detected; confirm any locally persisted credentials use OS-protected storage.'],
      };
    }

    case 'SD-02': {
      const wildcardBind = findMatches(
        project,
        codeFiles,
        /(\.listen\s*\([^)]*['"]0\.0\.0\.0['"]|host\s*=\s*['"]0\.0\.0\.0['"]|http:\/\/\*:|Access-Control-Allow-Origin['":\s]+\*)/
      );
      const loopbackBind = findMatches(
        project,
        codeFiles,
        /(127\.0\.0\.1|localhost|::1|IPAddress\.Loopback)/
      );
      if (wildcardBind.length > 0) {
        return {
          status: 'fail',
          evidence: [`Wildcard bind (0.0.0.0) or wildcard CORS detected in ${wildcardBind.join(', ')}`],
        };
      }
      if (loopbackBind.length > 0) {
        return {
          status: 'pass',
          evidence: [`Loopback-scoped local networking detected in ${loopbackBind.join(', ')}`],
        };
      }
      return {
        status: 'pass',
        evidence: ['No wildcard local server bindings or wildcard CORS headers detected.'],
      };
    }

    case 'SD-03': {
      const tlsDisabled = findMatches(
        project,
        codeFiles,
        /(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|ServerCertificateCustomValidationCallback\s*=\s*[^;]*=>\s*true)/
      );
      if (tlsDisabled.length > 0) {
        return {
          status: 'fail',
          evidence: [`TLS certificate validation bypass detected in ${tlsDisabled.join(', ')}`],
        };
      }
      return {
        status: 'pass',
        evidence: ['No TLS certificate validation bypasses detected in application source.'],
      };
    }

    case 'AU-01': {
      const updaterHits = findMatches(
        project,
        [...codeFiles, ...installerFiles],
        /(electron-updater|autoUpdater|tauri-plugin-updater|Sparkle|Velopack|Squirrel|verifyUpdateCodeSignature|publisherName)/
      );
      const insecureUpdater = findMatches(
        project,
        [...codeFiles, ...installerFiles],
        /(verifyUpdateCodeSignature\s*:\s*false|allowDowngrade\s*:\s*true|http:\/\/[^\s'"]+(?:latest\.yml|updates|releases))/i
      );
      if (insecureUpdater.length > 0) {
        return {
          status: 'fail',
          evidence: [`Weakened auto-update verification or plaintext update URL detected in ${insecureUpdater.join(', ')}`],
        };
      }
      if (updaterHits.length > 0) {
        return {
          status: 'pass',
          evidence: [`Signed/verified auto-update mechanism detected in ${updaterHits.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['No auto-update framework detected; if updates are delivered out-of-band, verify signature and digest enforcement.'],
      };
    }

    case 'AU-02': {
      const downgradeGuard = findMatches(
        project,
        [...allNonTest, ...workflows],
        /(monotonic|downgrade|allowDowngrade\s*:\s*false|channel|prerelease|Resolve-UpdateFeedDecision|Resolve-LatestPointerDecision)/i
      );
      if (downgradeGuard.length > 0) {
        return {
          status: 'pass',
          evidence: [`Release channel separation / anti-downgrade controls detected in ${downgradeGuard.join(', ')}`],
        };
      }
      return {
        status: 'warn',
        evidence: ['No explicit monotonic version or channel-separation guards detected in repository automation.'],
      };
    }

    case 'VT-01': {
      if (testStats.testFiles >= 5 || testStats.estimatedTests >= 25) {
        return {
          status: 'pass',
          evidence: [
            `Detected ${testStats.testFiles} test file(s) (~${testStats.estimatedTests} automated test case(s)).`,
          ],
        };
      }
      if (testStats.testFiles > 0) {
        return {
          status: 'warn',
          evidence: [
            `Detected ${testStats.testFiles} test file(s) (~${testStats.estimatedTests} test case(s)); coverage appears limited.`,
          ],
        };
      }
      return {
        status: 'fail',
        evidence: ['No automated test files detected in repository.'],
      };
    }

    case 'VT-02': {
      const ciSecHits = findMatches(
        project,
        workflows,
        /(github\/codeql-action|semgrep|gitleaks|trufflehog|osv-scanner|bandit|safety|cargo-audit|security-scan)/i
      );
      if (ciSecHits.length > 0) {
        return {
          status: 'pass',
          evidence: [`Automated CI security scanning detected in ${ciSecHits.join(', ')}`],
        };
      }
      return {
        status: 'fail',
        evidence: ['No automated SAST, secret-scanning, or security workflow gates detected in .github/workflows/.'],
      };
    }

    default:
      return { status: 'warn', evidence: ['Manual verification required.'] };
  }
}

export function scoreToGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 85) return 'A-';
  if (score >= 80) return 'B+';
  if (score >= 75) return 'B';
  if (score >= 70) return 'B-';
  if (score >= 65) return 'C+';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

export function runSecurityReportCard(targetDir, { appName = null, binaryPath = null } = {}) {
  const rubric = loadRubric();
  const project = walkProject(targetDir);
  const stackInfo = detectStacks(project, { binaryPath });
  const testStats = countAutomatedTests(project);
  const binaryInfo = binaryPath ? inspectBinary(binaryPath) : null;

  const ctx = {
    project,
    stacks: stackInfo.stacks,
    binaryInfo,
    testStats,
  };

  const results = rubric.controls.map((control) => {
    if (!isControlApplicable(control, stackInfo.stacks)) {
      return {
        ...control,
        status: 'not-applicable',
        scoreRatio: null,
        evidence: [`Not applicable (requires stack: ${control.stacks.join(', ')})`],
      };
    }
    const evaluated = evaluateControl(control, ctx);
    const scoreRatio =
      evaluated.status === 'pass' ? 1 : evaluated.status === 'warn' ? 0.5 : 0;
    return {
      ...control,
      status: evaluated.status,
      scoreRatio,
      evidence: evaluated.evidence,
    };
  });

  const domainScores = rubric.domains.map((domain) => {
    const domainControls = results.filter(
      (r) => r.domain === domain.id && r.status !== 'not-applicable'
    );
    const maxWeight = domainControls.reduce((sum, c) => sum + c.weight, 0);
    const earnedWeight = domainControls.reduce(
      (sum, c) => sum + c.weight * (c.scoreRatio ?? 0),
      0
    );
    const pct = maxWeight > 0 ? Math.round((earnedWeight / maxWeight) * 100) : 100;
    return {
      ...domain,
      score: pct,
      grade: scoreToGrade(pct),
      passed: domainControls.filter((c) => c.status === 'pass').length,
      warned: domainControls.filter((c) => c.status === 'warn').length,
      failed: domainControls.filter((c) => c.status === 'fail').length,
      total: domainControls.length,
    };
  });

  const activeDomains = domainScores.filter((d) => d.total > 0);
  const totalDomainWeight = activeDomains.reduce((sum, d) => sum + d.weight, 0);
  const overallScore =
    totalDomainWeight > 0
      ? Math.round(
          activeDomains.reduce((sum, d) => sum + d.score * d.weight, 0) / totalDomainWeight
        )
      : 0;

  const goldStars = results
    .filter((r) => r.goldStar && r.status === 'pass')
    .map((r) => ({
      controlId: r.id,
      label: r.goldStarLabel || r.title,
      domain: r.domain,
    }));

  const actionItems = results
    .filter((r) => r.status === 'fail' || r.status === 'warn')
    .sort((a, b) => {
      if (a.status !== b.status) return a.status === 'fail' ? -1 : 1;
      return b.weight - a.weight;
    })
    .map((r) => ({
      controlId: r.id,
      title: r.title,
      domain: r.domain,
      status: r.status,
      guidanceType: r.guidanceType,
      gradedProperty: r.gradedProperty,
      attackSurface: r.attackSurface,
      whatToFix: r.whatToFix,
      evidence: r.evidence,
    }));

  return {
    rubricVersion: rubric.version,
    generatedAt: new Date().toISOString(),
    appName: appName || path.basename(project.rootDir),
    targetDir: project.rootDir,
    filesScanned: project.files.length,
    truncated: project.truncated,
    detectedStacks: stackInfo.stacks,
    stackEvidence: stackInfo.evidence,
    testStats,
    binaryInfo,
    overallScore,
    grade: scoreToGrade(overallScore),
    goldStars,
    domainScores,
    controls: results,
    actionItems,
    aiEraWatchlist: rubric.aiEraWatchlist,
    philosophy: rubric.philosophy,
  };
}
