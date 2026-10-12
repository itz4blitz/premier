'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PLATFORM_PACKAGES } = require('../bin/premier.js');

const platformPackage = PLATFORM_PACKAGES[`${process.platform}-${process.arch}`];
const skip = platformPackage ? false : `no platform package for ${process.platform}-${process.arch}`;

// Stand-in for the native binary. Modes:
//   exit N  -> exit with code N
//   trap    -> report SIGTERM/SIGINT to a marker file, then exit 7
//   wait    -> install no handlers, so a forwarded signal terminates it
const FAKE_BINARY = `#!${process.execPath}
const fs = require('node:fs');
const [mode, value] = process.argv.slice(2);
if (mode === 'exit') process.exit(Number(value));
if (mode === 'trap') {
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.on(signal, () => {
      fs.writeFileSync(process.env.FAKE_MARKER, signal);
      process.exit(7);
    });
  }
}
setInterval(() => {}, 1000);
fs.writeFileSync(process.env.FAKE_READY, String(process.pid));
`;

// Lay out node_modules the way npm does, so the copied launcher resolves the
// fake binary through its normal optional-dependency lookup.
function installFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'premier-launcher-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const scope = path.join(root, 'node_modules', '@premierstudio');
  const launcherDir = path.join(scope, 'premier', 'bin');
  const nativeDir = path.join(scope, platformPackage.split('/')[1]);
  fs.mkdirSync(launcherDir, { recursive: true });
  fs.mkdirSync(path.join(nativeDir, 'bin'), { recursive: true });
  fs.copyFileSync(path.join(__dirname, '..', 'bin', 'premier.js'), path.join(launcherDir, 'premier.js'));
  // The launcher refuses a platform package of another version than its own.
  const manifest = path.join(__dirname, '..', 'package.json');
  const { version } = JSON.parse(fs.readFileSync(manifest, 'utf8'));
  fs.copyFileSync(manifest, path.join(scope, 'premier', 'package.json'));
  fs.writeFileSync(path.join(nativeDir, 'package.json'), JSON.stringify({ name: platformPackage, version }));
  fs.writeFileSync(path.join(nativeDir, 'bin', 'premier'), FAKE_BINARY, { mode: 0o755 });
  return {
    launcher: path.join(launcherDir, 'premier.js'),
    ready: path.join(root, 'ready'),
    marker: path.join(root, 'marker'),
  };
}

function launch(fixture, args) {
  const child = spawn(process.execPath, [fixture.launcher, ...args], {
    stdio: ['ignore', 'ignore', 'inherit'],
    env: { ...process.env, FAKE_READY: fixture.ready, FAKE_MARKER: fixture.marker },
  });
  const exited = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });
  return { child, exited };
}

async function waitFor(check, what) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function nativePid(t, fixture) {
  await waitFor(() => fs.existsSync(fixture.ready), 'the fake binary to start');
  const pid = Number(fs.readFileSync(fixture.ready, 'utf8'));
  // Never leave the fake binary behind, even when the launcher orphans it.
  t.after(() => {
    if (isAlive(pid)) process.kill(pid, 'SIGKILL');
  });
  return pid;
}

test('exits with the native binary exit code', { skip }, async (t) => {
  const fixture = installFixture(t);
  assert.deepEqual(await launch(fixture, ['exit', '3']).exited, { code: 3, signal: null });
  assert.deepEqual(await launch(fixture, ['exit', '0']).exited, { code: 0, signal: null });
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`forwards ${signal} to the native binary and exits with its code`, { skip }, async (t) => {
    const fixture = installFixture(t);
    const { child, exited } = launch(fixture, ['trap']);
    const pid = await nativePid(t, fixture);
    child.kill(signal);
    assert.deepEqual(await exited, { code: 7, signal: null });
    assert.equal(fs.readFileSync(fixture.marker, 'utf8'), signal);
    assert.equal(isAlive(pid), false);
  });
}

for (const signal of ['SIGTERM', 'SIGHUP', 'SIGQUIT']) {
  test(`re-raises ${signal} when it terminates the native binary`, { skip }, async (t) => {
    const fixture = installFixture(t);
    const { child, exited } = launch(fixture, ['wait']);
    const pid = await nativePid(t, fixture);
    child.kill(signal);
    assert.deepEqual(await exited, { code: null, signal });
    await waitFor(() => !isAlive(pid), 'the native binary to terminate');
  });
}
