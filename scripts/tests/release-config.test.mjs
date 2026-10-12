// Checks on the release configuration that can be made without running the
// workflows: pins, the order of the release build, and the version gate.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

const root = resolve(import.meta.dirname, '..', '..');
const read = (path) => readFileSync(join(root, path), 'utf8');
const workflows = readdirSync(join(root, '.github', 'workflows')).map((name) => `.github/workflows/${name}`);
const release = read('.github/workflows/release.yml');
const ci = read('.github/workflows/ci.yml');

test('every action is pinned by commit SHA with its version beside it', () => {
  for (const path of workflows) {
    for (const [, reference] of read(path).matchAll(/^\s*(?:- )?uses:\s*(\S+.*)$/gm)) {
      if (reference.startsWith('./')) continue; // a workflow of this repository
      assert.match(reference, /^[\w.-]+\/[\w./-]+@[0-9a-f]{40} # \S+/, `${path}: ${reference}`);
    }
  }
});

test('workflows install the toolchain rust-toolchain.toml pins', () => {
  const channel = read('rust-toolchain.toml').match(/^channel = "(\d+\.\d+\.\d+)"$/m)?.[1];
  assert.ok(channel, 'rust-toolchain.toml pins an exact version');
  for (const path of workflows) {
    const text = read(path);
    const installs = [...text.matchAll(/dtolnay\/rust-toolchain@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+toolchain: (\S+)/g)];
    assert.equal(installs.length, text.split('dtolnay/rust-toolchain@').length - 1, `${path}: every toolchain step names a version`);
    for (const [, version] of installs) assert.equal(version, channel, path);
  }
});

test('no checkout leaves credentials behind and npm is pinned exactly', () => {
  for (const path of workflows) {
    const text = read(path);
    const checkouts = text.split('actions/checkout@').length - 1;
    assert.equal(text.split('persist-credentials: false').length - 1, checkouts, `${path}: every checkout sets persist-credentials: false`);
  }
  assert.match(release, /npm install --global npm@\d+\.\d+\.\d+\n/);
});

test('the release builds the viewer, asserts it, and only then builds Rust with the viewer required', () => {
  const build = release.slice(release.indexOf('\n  build:'), release.indexOf('\n  publish:'));
  const order = ['npm run build', 'apps/viewer/dist/index.html', 'cargo test', "PREMIER_REQUIRE_VIEWER: '1'", 'cargo build --release', 'package-release.sh'];
  const positions = order.map((needle) => build.indexOf(needle));
  assert.ok(positions.every((position) => position !== -1), `missing step: ${order[positions.indexOf(-1)]}`);
  assert.deepEqual([...positions].sort((a, b) => a - b), positions, 'steps are in this order');
  assert.match(build, /--binary "target\/\$\{\{ matrix\.target \}\}\/release\/premier"/, 'the checked binary is the packaged one');
  assert.match(read('scripts/package-release.sh'), /PREMIER_REQUIRE_VIEWER=1 cargo build --release/);
  assert.match(read('crates/premier-cli/build.rs'), /PREMIER_REQUIRE_VIEWER/);
});

test('the release runs the CI suite first, and CI covers macOS', () => {
  assert.match(ci, /^ {2}workflow_call:$/m);
  assert.match(release, /\n {2}ci:\n(?:.*\n)*? {4}uses: \.\/\.github\/workflows\/ci\.yml/);
  assert.match(release, /\n {2}build:\n {4}needs: \[ci\]/);
  assert.match(ci, /runs-on: macos-\d+/);
});

test('the GitHub release stays a draft until npm has published, and prereleases are marked', () => {
  const publish = release.slice(release.indexOf('\n  publish:'));
  const draft = publish.indexOf('draft: true');
  const npm = publish.indexOf('npm publish');
  const promote = publish.indexOf('gh release edit');
  assert.ok(draft !== -1 && draft < npm && npm < promote, 'draft, then npm, then promote');
  assert.doesNotMatch(publish, /make_latest: true/);
  assert.match(publish, /prerelease: \$\{\{ contains\(github\.ref_name, '-'\) \}\}/);
  assert.match(publish, /dist_tag=next/);
  assert.match(publish, /npm publish "\.\/\$source" --access public --provenance --tag "\$dist_tag"/);
});

test('SBOMs and the installer are inside the signed manifest and the attestation', () => {
  assert.match(release, /sha256sum -- \.\/\*\.tar\.gz \.\/\*\.spdx\.json \.\/premier-install\.sh \| sort -k2 > SHA256SUMS/);
  const attest = release.slice(release.indexOf('attest-build-provenance@'), release.indexOf('softprops/'));
  for (const subject of ['release-assets/*.tar.gz', 'release-assets/*.spdx.json', 'release-assets/premier-install.sh']) {
    assert.ok(attest.includes(subject), `attestation covers ${subject}`);
  }
});

test('the privileged publish job installs no dependency tree', () => {
  const publish = release.slice(release.indexOf('\n  publish:'));
  assert.doesNotMatch(publish, /npm ci|npm install(?! --global npm@)/);
  assert.match(publish, /verify-staged-npm\.mjs/);
});

test('macOS signing runs only when its secrets exist', () => {
  assert.match(release, /if: runner\.os == 'macOS' && env\.APPLE_SIGNING_IDENTITY != ''\n(?:.*\n)*?\s+run: \.\/scripts\/macos-sign-notarize\.sh/);
  assert.match(release, /APPLE_SIGNING_IDENTITY: \$\{\{ secrets\.APPLE_SIGNING_IDENTITY \}\}/);
});

test('the version gate passes on the repository and names every mismatch', () => {
  const script = join(root, 'scripts', 'check-release-versions.mjs');
  const current = spawnSync(process.execPath, [script], { encoding: 'utf8' });
  assert.equal(current.status, 0, current.stderr);

  const wrong = spawnSync(process.execPath, [script, 'v9.9.9'], { encoding: 'utf8' });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /Cargo\.toml \[workspace\.package\] version is \d+\.\d+\.\d+, expected 9\.9\.9/);
  assert.match(wrong.stderr, /launcher optionalDependencies @premierstudio\/premier-linux-x64-gnu is /);
  assert.match(wrong.stderr, /Cargo\.lock premier-cli is /);

  const garbage = spawnSync(process.execPath, [script, 'v1.2.3garbage'], { encoding: 'utf8' });
  assert.equal(garbage.status, 1);
  assert.match(garbage.stderr, /is not a release version/);

  // One stale pin in an otherwise consistent tree is found and named.
  const work = mkdtempSync(join(tmpdir(), 'premier-versions-'));
  try {
    for (const path of ['Cargo.toml', 'Cargo.lock', 'package.json', 'packages/premier-cli/package.json', 'sdk/js/package.json']) {
      mkdirSync(join(work, path, '..'), { recursive: true });
      cpSync(join(root, path), join(work, path));
    }
    for (const directory of readdirSync(join(root, 'npm', 'platforms'))) {
      mkdirSync(join(work, 'npm', 'platforms', directory), { recursive: true });
      cpSync(join(root, 'npm', 'platforms', directory, 'package.json'), join(work, 'npm', 'platforms', directory, 'package.json'));
    }
    const launcher = join(work, 'packages', 'premier-cli', 'package.json');
    const manifest = JSON.parse(readFileSync(launcher, 'utf8'));
    manifest.optionalDependencies['@premierstudio/premier-darwin-x64'] = '0.0.1';
    writeFileSync(launcher, JSON.stringify(manifest));
    const stale = spawnSync(process.execPath, [script, '--root', work], { encoding: 'utf8' });
    assert.equal(stale.status, 1);
    assert.equal(stale.stderr.trim().split('\n').length, 2, stale.stderr);
    assert.match(stale.stderr, /launcher optionalDependencies @premierstudio\/premier-darwin-x64 is 0\.0\.1/);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
