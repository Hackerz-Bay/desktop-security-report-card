import path from 'node:path';

function safeParseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Inspect repository files and optional binary path to detect active desktop stacks.
 */
export function detectStacks(project, { binaryPath = null } = {}) {
  const detected = new Set(['generic']);
  const evidence = [];

  const packageJsonFiles = project.files.filter(
    (f) => f.name === 'package.json' && f.rel.split('/').length <= 3
  );

  for (const pkgFile of packageJsonFiles) {
    const pkg = safeParseJson(project.readText(pkgFile));
    if (!pkg) continue;
    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {}),
    };
    const depNames = Object.keys(allDeps);
    if (
      depNames.some((d) =>
        ['electron', 'electron-builder', '@electron-forge/cli', '@electron/fuses'].includes(d)
      )
    ) {
      detected.add('electron');
      evidence.push(`Electron detected via ${pkgFile.rel}`);
    }
    if (depNames.some((d) => d === '@tauri-apps/api' || d === '@tauri-apps/cli')) {
      detected.add('tauri');
      evidence.push(`Tauri detected via ${pkgFile.rel}`);
    }
  }

  if (
    project.files.some((f) => f.name === 'tauri.conf.json' || f.rel.endsWith('src-tauri/Cargo.toml'))
  ) {
    detected.add('tauri');
    evidence.push('Tauri detected via tauri.conf.json / src-tauri');
  }

  if (
    project.files.some((f) => f.ext === '.csproj' || f.ext === '.sln' || f.ext === '.fsproj')
  ) {
    detected.add('dotnet');
    evidence.push('.NET desktop project detected via .csproj / .sln');
  }

  const pyManifests = project.files.filter(
    (f) =>
      f.name === 'pyproject.toml' ||
      f.name === 'setup.py' ||
      /^requirements.*\.txt$/i.test(f.name) ||
      f.ext === '.spec'
  );
  for (const pyFile of pyManifests) {
    const text = project.readText(pyFile);
    if (
      /\b(pyinstaller|nuitka|cx[_-]freeze|pyqt[56]|pyside[26]|wxpython|customtkinter|pywebview|flet)\b/i.test(
        text
      ) ||
      (pyFile.ext === '.spec' && /PYZ\(|EXE\(/.test(text))
    ) {
      detected.add('python-desktop');
      evidence.push(`Python desktop packaging detected via ${pyFile.rel}`);
      break;
    }
  }

  if (
    project.files.some((f) =>
      ['.nsi', '.nsh', '.wxs', '.iss', '.vcxproj', '.msixmanifest'].includes(f.ext)
    ) ||
    project.files.some((f) => /electron-builder\.(yml|yaml|json)$/i.test(f.name))
  ) {
    detected.add('native-windows');
    evidence.push('Windows installer/packaging configuration detected');
  }

  if (
    project.files.some(
      (f) =>
        f.ext === '.entitlements' ||
        f.name === 'Info.plist' ||
        f.rel.includes('.xcodeproj/')
    )
  ) {
    detected.add('native-macos');
    evidence.push('macOS bundle/entitlements configuration detected');
  }

  if (binaryPath) {
    const ext = path.extname(binaryPath).toLowerCase();
    if (['.exe', '.msi', '.msix', '.dll'].includes(ext)) {
      detected.add('native-windows');
      evidence.push(`Windows binary supplied: ${path.basename(binaryPath)}`);
    } else if (['.app', '.dmg', '.pkg'].includes(ext)) {
      detected.add('native-macos');
      evidence.push(`macOS binary supplied: ${path.basename(binaryPath)}`);
    }
  }

  return {
    stacks: [...detected],
    evidence: [...new Set(evidence)],
  };
}
