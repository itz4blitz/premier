// scripts/stage-npm-packages.sh and scripts/verify-staged-npm.mjs against
// release archives built here. The "binaries" are files with the right
// executable header for each target; nothing is published or installed.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

const root = resolve(import.meta.dirname, '..', '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const TARGETS = {
  'aarch64-apple-darwin': 'darwin-arm64',
  'x86_64-apple-darwin': 'darwin-x64',
  'aarch64-unknown-linux-gnu': 'linux-arm64-gnu',
  'x86_64-unknown-linux-gnu': 'linux-x64-gnu',
};

function header(target) {
  if (target.includes('linux')) {
    const head = Buffer.alloc(20);
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(head);
    head.writeUInt16LE(2, 16);
    head.writeUInt16LE(target.startsWith('x86_64') ? 62 : 183, 18);
    return head;
  }
  const head = Buffer.alloc(20);
  head.writeUInt32LE(0xfeedfacf, 0);
  head.writeUInt32LE(target.startsWith('x86_64') ? 0x01000007 : 0x0100000c, 4);
  return head;
}

/** A release tree: archives in `assets`, and a copy of the packages to stage into. */
function fixture(t, overrides = {}) {
  const work = mkdtempSync(join(tmpdir(), 'premier-staging-'));
  t.after(() => rmSync(work, { recursive: true, force: true }));
  const assets = join(work, 'assets');
  mkdirSync(assets);
  cpSync(join(root, 'npm'), join(work, 'npm'), { recursive: true });
  cpSync(join(root, 'packages', 'premier-cli'), join(work, 'packages', 'premier-cli'), { recursive: true });
  for (const target of Object.keys(TARGETS)) {
    const settings = { viewer: 'embedded', glibc: '2.34', binaryFor: target, size: 4096, ...overrides[target] };
    const name = `premier-${version}-${target}`;
    mkdirSync(join(work, 'build', name, 'bin'), { recursive: true });
    writeFileSync(join(work, 'build', name, 'bin', 'premier'), Buffer.concat([header(settings.binaryFor), Buffer.alloc(settings.size)]));
    chmodSync(join(work, 'build', name, 'bin', 'premier'), 0o755);
    const metadata = ['NAME=premier', `VERSION=${version}`, `TARGET=${target}`, `VIEWER=${settings.viewer}`, 'SIGNATURE=none'];
    if (target.includes('linux') && settings.glibc) metadata.push(`GLIBC_MIN=${settings.glibc}`);
    writeFileSync(join(work, 'build', name, 'RELEASE-METADATA'), `${metadata.join('\n')}\n`);
    const packed = spawnSync('tar', ['-czf', join(assets, `${name}.tar.gz`), '-C', join(work, 'build'), name]);
    assert.equal(packed.status, 0, String(packed.stderr));
  }
  return { work, assets };
}

const stage = ({ work, assets }) =>
  spawnSync(join(root, 'scripts', 'stage-npm-packages.sh'), ['--version', version, '--assets', assets, '--root', work], { encoding: 'utf8' });
const verify = ({ work }, ...extra) =>
  spawnSync(process.execPath, [join(root, 'scripts', 'verify-staged-npm.mjs'), '--version', version, '--root', work, ...extra], { encoding: 'utf8' });

test('staging copies each binary, records glibc for Linux, and verification accepts it', (t) => {
  const tree = fixture(t);
  const staged = stage(tree);
  assert.equal(staged.status, 0, staged.stderr);
  for (const [target, directory] of Object.entries(TARGETS)) {
    const manifest = JSON.parse(readFileSync(join(tree.work, 'npm', 'platforms', directory, 'package.json'), 'utf8'));
    assert.deepEqual(manifest.premier, target.includes('linux') ? { glibc: '2.34' } : undefined, directory);
    assert.equal(manifest.version, version);
    assert.equal(
      readFileSync(join(tree.work, 'npm', 'platforms', directory, 'THIRD_PARTY_NOTICES.md'), 'utf8'),
      readFileSync(join(root, 'THIRD_PARTY_NOTICES.md'), 'utf8'),
      `${directory} carries the third-party notices`
    );
  }
  assert.equal(
    readFileSync(join(tree.work, 'packages', 'premier-cli', 'THIRD_PARTY_NOTICES.md'), 'utf8'),
    readFileSync(join(root, 'THIRD_PARTY_NOTICES.md'), 'utf8')
  );
  // The stand-in binaries cannot run, so the host run is the one step skipped.
  const verified = verify(tree, '--min-bytes', '1024', '--skip-host-run');
  assert.equal(verified.status, 0, verified.stderr);
  assert.match(verified.stdout, /linux-x64-gnu: \d+ bytes, x86_64-unknown-linux, glibc 2\.34/);

  // Without that flag the host's package is executed, and these do not run.
  const executed = verify(tree, '--min-bytes', '1024', '--skip-pack');
  assert.equal(executed.status, 1);
  assert.match(executed.stderr, /does not run on this host|no staged package matches this host/);
});

test('staging refuses an archive whose metadata or binary is not what it should be', (t) => {
  const placeholder = stage(fixture(t, { 'x86_64-apple-darwin': { viewer: 'unverified' } }));
  assert.equal(placeholder.status, 1);
  assert.match(placeholder.stderr, /without a verified embedded viewer \(VIEWER=unverified\)/);

  const swapped = stage(fixture(t, { 'aarch64-unknown-linux-gnu': { binaryFor: 'x86_64-unknown-linux-gnu' } }));
  assert.equal(swapped.status, 1);
  assert.match(swapped.stderr, /does not contain a aarch64-unknown-linux-gnu executable/);

  const noGlibc = stage(fixture(t, { 'x86_64-unknown-linux-gnu': { glibc: '' } }));
  assert.equal(noGlibc.status, 1);
  assert.match(noGlibc.stderr, /does not record the glibc its binary requires/);

  const tree = fixture(t);
  rmSync(join(tree.assets, `premier-${version}-aarch64-apple-darwin.tar.gz`));
  const missing = stage(tree);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /missing release archive/);
});

test('verification names every problem with what was staged', (t) => {
  const tree = fixture(t);
  assert.equal(stage(tree).status, 0);
  const platforms = join(tree.work, 'npm', 'platforms');
  // An empty binary, a binary of another architecture, a stale version, an
  // extra file that would be published, and a missing glibc record.
  writeFileSync(join(platforms, 'darwin-arm64', 'bin', 'premier'), '');
  cpSync(join(platforms, 'linux-x64-gnu', 'bin', 'premier'), join(platforms, 'darwin-x64', 'bin', 'premier'));
  const edit = (directory, change) => {
    const path = join(platforms, directory, 'package.json');
    const manifest = JSON.parse(readFileSync(path, 'utf8'));
    change(manifest);
    writeFileSync(path, JSON.stringify(manifest));
  };
  edit('linux-arm64-gnu', (manifest) => { manifest.version = '0.0.1'; });
  edit('linux-x64-gnu', (manifest) => { delete manifest.premier; manifest.files.push('extra.txt'); });
  writeFileSync(join(platforms, 'linux-x64-gnu', 'extra.txt'), 'not for publication');

  // A package staged without the third-party notices.
  rmSync(join(platforms, 'darwin-arm64', 'THIRD_PARTY_NOTICES.md'));
  rmSync(join(tree.work, 'packages', 'premier-cli', 'THIRD_PARTY_NOTICES.md'));

  const result = verify(tree, '--min-bytes', '1024', '--skip-host-run');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /darwin-arm64: would publish \[LICENSE, README\.md, bin\/premier, package\.json\], expected \[LICENSE, README\.md, THIRD_PARTY_NOTICES\.md, bin\/premier, package\.json\]/);
  assert.match(result.stderr, /launcher: would publish \[LICENSE, README\.md, bin\/premier\.js, package\.json\]/);
  assert.match(result.stderr, /darwin-arm64: bin\/premier is only 0 bytes/);
  assert.match(result.stderr, /darwin-x64: bin\/premier is a x86_64-unknown-linux executable, expected x86_64-apple-darwin/);
  assert.match(result.stderr, /linux-arm64-gnu: version is 0\.0\.1/);
  assert.match(result.stderr, /linux-x64-gnu: does not record the glibc/);
  assert.match(result.stderr, /linux-x64-gnu: would publish \[.*extra\.txt.*\]/);
});
