'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { checkPlatformPackage, packageFor, resolveBinary, versionBelow } = require('../bin/premier.js');
const launcherManifest = require('../package.json');

const glibc = { getReport: () => ({ header: { glibcVersionRuntime: '2.39' } }) };
const musl = { getReport: () => ({ header: {} }) };

test('selects every published platform package', () => {
  assert.equal(packageFor('darwin', 'arm64'), '@premierstudio/premier-darwin-arm64');
  assert.equal(packageFor('darwin', 'x64'), '@premierstudio/premier-darwin-x64');
  assert.equal(packageFor('linux', 'arm64', glibc), '@premierstudio/premier-linux-arm64-gnu');
  assert.equal(packageFor('linux', 'x64', glibc), '@premierstudio/premier-linux-x64-gnu');
});

test('rejects unsupported operating systems and architectures', () => {
  assert.throws(() => packageFor('win32', 'x64'), /does not publish/);
  assert.throws(() => packageFor('darwin', 'riscv64'), /does not publish/);
});

test('rejects musl rather than installing a glibc binary', () => {
  assert.throws(() => packageFor('linux', 'x64', musl), /glibc only/);
});

test('an unsupported platform is told what is published and how to build from source', () => {
  for (const attempt of [
    () => packageFor('linux', 'x64', musl),
    () => packageFor('win32', 'x64'),
    () => packageFor('freebsd', 'x64'),
  ]) {
    assert.throws(attempt, /Build it from source instead.*CONTRIBUTING\.md/s);
  }
  assert.throws(() => packageFor('linux', 'x64', musl), /musl.*Alpine/s);
  assert.throws(() => packageFor('win32', 'x64'), /WSL 2/);
  assert.throws(() => packageFor('freebsd', 'x64'), /Published: darwin-arm64, darwin-x64, linux-arm64, linux-x64/);
});

test('refuses a platform package of another version', () => {
  const name = '@premierstudio/premier-linux-x64-gnu';
  assert.doesNotThrow(() => checkPlatformPackage(name, { version: launcherManifest.version }, launcherManifest, glibc));
  assert.throws(
    () => checkPlatformPackage(name, { version: '0.0.1' }, launcherManifest, glibc),
    new RegExp(`${name} is version 0\\.0\\.1, but this launcher .* is ${launcherManifest.version.replaceAll('.', '\\.')}`),
  );
});

test('refuses a binary that needs a newer glibc than the system has', () => {
  const name = '@premierstudio/premier-linux-x64-gnu';
  const manifest = { version: launcherManifest.version, premier: { glibc: '2.39' } };
  const old = { getReport: () => ({ header: { glibcVersionRuntime: '2.9' } }) };
  assert.doesNotThrow(() => checkPlatformPackage(name, manifest, launcherManifest, glibc));
  assert.throws(
    () => checkPlatformPackage(name, manifest, launcherManifest, old),
    /needs glibc 2\.39 or later; this system has glibc 2\.9.*Build it from source/s,
  );
  // No declared requirement, or not a glibc system (macOS): nothing to compare.
  assert.doesNotThrow(() => checkPlatformPackage(name, { version: launcherManifest.version }, launcherManifest, old));
  assert.doesNotThrow(() => checkPlatformPackage(name, manifest, launcherManifest, musl));
});

test('compares dotted versions numerically', () => {
  assert.equal(versionBelow('2.9', '2.39'), true);
  assert.equal(versionBelow('2.39', '2.39'), false);
  assert.equal(versionBelow('2.40', '2.39'), false);
  assert.equal(versionBelow('2.39', '2.39.1'), true);
  assert.equal(versionBelow('3', '2.39'), false);
});

test('resolveBinary checks the manifest it resolved and names a missing package', () => {
  const work = mkdtempSync(join(tmpdir(), 'premier-launcher-'));
  try {
    const write = (version) => {
      mkdirSync(join(work, 'bin'), { recursive: true });
      writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'platform', version }));
      return { resolve: () => join(work, 'package.json'), report: glibc };
    };
    assert.equal(resolveBinary('linux', 'x64', write(launcherManifest.version)), join(work, 'bin', 'premier'));
    assert.throws(() => resolveBinary('linux', 'x64', write('9.9.9')), /is version 9\.9\.9/);
    const missing = { resolve: () => { throw new Error('Cannot find module'); }, report: glibc };
    assert.throws(() => resolveBinary('darwin', 'arm64', missing), /optional package .* is missing.*Cannot find module/s);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test('the launcher exits 1 with the reason when a stale platform package is installed', () => {
  const work = mkdtempSync(join(tmpdir(), 'premier-launcher-'));
  try {
    // A consumer tree: the launcher, and a platform package of another version.
    const launcher = join(work, 'node_modules', '@premierstudio', 'premier');
    mkdirSync(join(launcher, 'bin'), { recursive: true });
    writeFileSync(join(launcher, 'package.json'), JSON.stringify(launcherManifest));
    writeFileSync(join(launcher, 'bin', 'premier.js'), require('node:fs').readFileSync(require.resolve('../bin/premier.js')));
    let name;
    try {
      name = packageFor(process.platform, process.arch);
    } catch {
      return; // This host has no platform package to be stale.
    }
    const platform = join(work, 'node_modules', ...name.split('/'));
    mkdirSync(join(platform, 'bin'), { recursive: true });
    writeFileSync(join(platform, 'package.json'), JSON.stringify({ name, version: '0.0.1' }));
    writeFileSync(join(platform, 'bin', 'premier'), '#!/bin/sh\necho ran-anyway\n', { mode: 0o755 });
    const result = spawnSync(process.execPath, [join(launcher, 'bin', 'premier.js'), '--version'], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^premier: .* is version 0\.0\.1, but this launcher/);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test('the launcher package ships only the launcher, its README and the licence', () => {
  assert.deepEqual(launcherManifest.files, ['bin', 'README.md', 'LICENSE']);
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    assert.equal(launcherManifest.scripts?.[hook], undefined, `${hook} script`);
  }
  const versions = new Set(Object.values(launcherManifest.optionalDependencies));
  assert.deepEqual([...versions], [launcherManifest.version], 'platform packages are pinned to the launcher version');
});
