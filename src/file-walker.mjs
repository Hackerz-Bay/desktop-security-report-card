import fs from 'node:fs';
import path from 'node:path';

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'out',
  'target',
  'bin',
  'obj',
  '.venv',
  'venv',
  '__pycache__',
  '.mypy_cache',
  '.pytest_cache',
  '.ruff_cache',
  '.next',
  '.nuxt',
  'coverage',
  '.cache',
  'vendor',
  'packages-cache',
  'Pods',
]);

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.json', '.yml', '.yaml', '.toml', '.xml', '.plist', '.entitlements',
  '.py', '.cs', '.csproj', '.fsproj', '.vbproj', '.sln', '.props', '.targets',
  '.rs', '.go', '.c', '.cc', '.cpp', '.h', '.hpp', '.swift', '.m', '.mm',
  '.ps1', '.psm1', '.psd1', '.sh', '.bash', '.bat', '.cmd',
  '.nsi', '.nsh', '.wxs', '.iss', '.md', '.txt', '.html', '.htm', '.ini', '.cfg', '.conf',
]);

const TEST_FILE_PATTERNS = [
  /(^|\/)(__tests__|tests?|spec|specs)\//i,
  /\.(test|spec)\.[a-z0-9]+$/i,
  /(^|\/)test_[^/]+\.py$/i,
  /(^|\/)[^/]+_test\.(go|rs|py|cs)$/i,
  /(^|\/)test-[^/]+\.(ps1|sh)$/i,
  /(^|\/)[^/]+Tests?\.cs$/,
];

const MAX_FILE_BYTES = 512 * 1024;
const MAX_TOTAL_FILES = 12000;

export function toPosix(p) {
  return p.split(path.sep).join('/');
}

export function isTestFile(relPosix) {
  return TEST_FILE_PATTERNS.some((re) => re.test(relPosix));
}

export function isTextReadable(relPosix) {
  const base = path.posix.basename(relPosix).toLowerCase();
  if (
    base === 'dockerfile' ||
    base === 'makefile' ||
    base === 'security' ||
    base === 'security.txt' ||
    base === 'sha256sums' ||
    base === 'sha256sums.txt' ||
    base.startsWith('.env')
  ) {
    return true;
  }
  return TEXT_EXTENSIONS.has(path.posix.extname(relPosix).toLowerCase());
}

/**
 * Walk a target directory safely without following symlinks or executing code.
 */
export function walkProject(rootDir, { maxFiles = MAX_TOTAL_FILES } = {}) {
  const absRoot = path.resolve(rootDir);
  const files = [];
  const truncated = { hitLimit: false };

  function visit(currentDir) {
    if (files.length >= maxFiles) {
      truncated.hitLimit = true;
      return;
    }

    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (files.length >= maxFiles) {
        truncated.hitLimit = true;
        return;
      }
      if (entry.isSymbolicLink()) continue;

      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        visit(fullPath);
      } else if (entry.isFile()) {
        const rel = toPosix(path.relative(absRoot, fullPath));
        files.push({
          rel,
          abs: fullPath,
          name: entry.name,
          ext: path.posix.extname(rel).toLowerCase(),
          isTest: isTestFile(rel),
        });
      }
    }
  }

  visit(absRoot);

  const cache = new Map();
  function readText(fileObj) {
    if (cache.has(fileObj.rel)) return cache.get(fileObj.rel);
    if (!isTextReadable(fileObj.rel)) {
      cache.set(fileObj.rel, '');
      return '';
    }
    try {
      const stat = fs.statSync(fileObj.abs);
      if (stat.size > MAX_FILE_BYTES) {
        cache.set(fileObj.rel, '');
        return '';
      }
      const content = fs.readFileSync(fileObj.abs, 'utf8');
      cache.set(fileObj.rel, content);
      return content;
    } catch {
      cache.set(fileObj.rel, '');
      return '';
    }
  }

  return {
    rootDir: absRoot,
    files,
    truncated: truncated.hitLimit,
    readText,
  };
}

/**
 * Estimate automated test counts across common desktop ecosystems without executing code.
 */
export function countAutomatedTests(project) {
  let testFiles = 0;
  let estimatedTests = 0;

  for (const file of project.files) {
    if (!file.isTest) continue;
    testFiles += 1;
    const text = project.readText(file);
    if (!text) continue;

    if (/\.(js|mjs|cjs|jsx|ts|tsx)$/.test(file.ext)) {
      const matches = text.match(/\b(?:it|test)\s*\(/g);
      estimatedTests += matches ? matches.length : 0;
    } else if (file.ext === '.py') {
      const matches = text.match(/^\s*(?:async\s+)?def\s+test_[A-Za-z0-9_]+\s*\(/gm);
      estimatedTests += matches ? matches.length : 0;
    } else if (file.ext === '.cs') {
      const matches = text.match(/\[\s*(?:Fact|Theory|Test|TestMethod)\b/g);
      estimatedTests += matches ? matches.length : 0;
    } else if (file.ext === '.rs') {
      const matches = text.match(/#\[\s*(?:tokio::)?test\b/g);
      estimatedTests += matches ? matches.length : 0;
    } else if (file.ext === '.ps1') {
      const matches = text.match(/\b(?:It|Invoke-NewGroup|Assert-Equal|Assert-Throws)\b/g);
      estimatedTests += matches ? Math.max(1, Math.min(matches.length, 50)) : 1;
    } else if (file.ext === '.sh') {
      const matches = text.match(/^\s*(?:test_[A-Za-z0-9_]+\s*\(\)|check\s+)/gm);
      estimatedTests += matches ? matches.length : 1;
    }
  }

  return { testFiles, estimatedTests };
}
