#!/usr/bin/env node
// Inspect the staged npm packages before `npm publish`: what will be uploaded
// is packed (dry run), listed, and checked, and the package for this host is
// executed. Usage:
//   node scripts/verify-staged-npm.mjs --version VERSION [--root DIR]
//        [--min-bytes N] [--skip-host-run] [--skip-pack]
import { execFileSync } from 'node:child_process';
import { openSync, readSync, closeSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const version = option('--version');
const root = resolve(option('--root', join(import.meta.dirname, '..')));
// A real binary is tens of megabytes; an empty or truncated extraction is not.
const minBytes = Number(option('--min-bytes', String(1024 * 1024)));
if (!version) {
  console.error('usage: verify-staged-npm.mjs --version VERSION [--root DIR] [--min-bytes N] [--skip-host-run] [--skip-pack]');
  process.exit(2);
}

const PLATFORMS = {
  'darwin-arm64': { os: 'darwin', cpu: 'arm64', target: 'aarch64-apple-darwin' },
  'darwin-x64': { os: 'darwin', cpu: 'x64', target: 'x86_64-apple-darwin' },
  'linux-arm64-gnu': { os: 'linux', cpu: 'arm64', libc: 'glibc', target: 'aarch64-unknown-linux-gnu' },
  'linux-x64-gnu': { os: 'linux', cpu: 'x64', libc: 'glibc', target: 'x86_64-unknown-linux-gnu' },
};

/** The Rust target family an executable's header declares, or `unknown`. */
function binaryFormat(path) {
  const head = Buffer.alloc(20);
  const descriptor = openSync(path, 'r');
  try {
    readSync(descriptor, head, 0, 20, 0);
  } finally {
    closeSync(descriptor);
  }
  if (head.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) && head[5] === 1) {
    return { 62: 'x86_64-unknown-linux', 183: 'aarch64-unknown-linux' }[head.readUInt16LE(18)] ?? 'unknown';
  }
  if (head.readUInt32LE(0) === 0xfeedfacf) {
    return { 0x01000007: 'x86_64-apple-darwin', 0x0100000c: 'aarch64-apple-darwin' }[head.readUInt32LE(4)] ?? 'unknown';
  }
  return 'unknown';
}

/** Paths `npm publish` would upload from `directory`. */
function packedFiles(directory) {
  const output = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: directory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const parsed = JSON.parse(output);
  const entry = Array.isArray(parsed) ? parsed[0] : (parsed.files ? parsed : Object.values(parsed)[0]);
  return entry.files.map((file) => file.path).sort();
}

const problems = [];
const report = [];
const hostLibc = process.platform === 'linux' && !process.report?.getReport().header.glibcVersionRuntime ? 'musl' : 'glibc';
let ranHost = false;

for (const [directory, expected] of Object.entries(PLATFORMS)) {
  const base = join(root, 'npm', 'platforms', directory);
  const fail = (message) => problems.push(`${directory}: ${message}`);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(base, 'package.json'), 'utf8'));
  } catch (error) {
    fail(`package.json cannot be read (${error.message})`);
    continue;
  }
  if (manifest.version !== version) fail(`version is ${manifest.version}, expected ${version}`);
  if (manifest.os?.join() !== expected.os) fail(`os is ${JSON.stringify(manifest.os)}, expected ["${expected.os}"]`);
  if (manifest.cpu?.join() !== expected.cpu) fail(`cpu is ${JSON.stringify(manifest.cpu)}, expected ["${expected.cpu}"]`);
  if ((manifest.libc?.join() ?? undefined) !== expected.libc) fail(`libc is ${JSON.stringify(manifest.libc)}`);
  if (manifest.scripts) fail('declares npm scripts; platform packages must not run any');
  if (expected.libc && !/^\d+\.\d+(\.\d+)?$/.test(manifest.premier?.glibc ?? '')) {
    fail('does not record the glibc its binary requires (premier.glibc)');
  }

  const binary = join(base, 'bin', 'premier');
  let stat;
  try {
    stat = statSync(binary);
  } catch {
    fail('bin/premier is missing');
    continue;
  }
  if (!stat.isFile()) fail('bin/premier is not a regular file');
  if ((stat.mode & 0o111) !== 0o111) fail(`bin/premier is not executable (mode ${(stat.mode & 0o777).toString(8)})`);
  if (stat.size < minBytes) fail(`bin/premier is only ${stat.size} bytes`);
  const format = binaryFormat(binary);
  if (format !== expected.target.replace(/-gnu$/, '')) fail(`bin/premier is a ${format} executable, expected ${expected.target}`);

  if (!flag('--skip-pack')) {
    const files = packedFiles(base);
    const wanted = ['LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md', 'bin/premier', 'package.json'];
    if (files.join() !== wanted.join()) fail(`would publish [${files.join(', ')}], expected [${wanted.join(', ')}]`);
  }

  const isHost = expected.os === process.platform && expected.cpu === process.arch && (expected.libc ?? 'glibc') === hostLibc;
  if (isHost && !flag('--skip-host-run')) {
    ranHost = true;
    try {
      const shown = execFileSync(binary, ['--version'], { encoding: 'utf8' }).trim();
      if (shown !== `premier ${version}`) fail(`--version printed "${shown}"`);
      const info = Object.fromEntries(
        execFileSync(binary, ['build-info'], { encoding: 'utf8' }).trim().split('\n').map((line) => line.split('=')),
      );
      if (info.version !== version) fail(`build-info version is ${info.version}`);
      if (info.target !== expected.target) fail(`build-info target is ${info.target}`);
      if (info.viewer !== 'embedded') fail(`build-info viewer is ${info.viewer}; the binary embeds the placeholder page`);
    } catch (error) {
      fail(`the staged binary does not run on this host: ${error.message.split('\n')[0]}`);
    }
  }
  report.push(`${directory}: ${stat.size} bytes, ${format}${manifest.premier?.glibc ? `, glibc ${manifest.premier.glibc}` : ''}`);
}

const launcher = join(root, 'packages', 'premier-cli');
const launcherManifest = JSON.parse(readFileSync(join(launcher, 'package.json'), 'utf8'));
if (launcherManifest.version !== version) problems.push(`launcher: version is ${launcherManifest.version}, expected ${version}`);
if (!flag('--skip-pack')) {
  const files = packedFiles(launcher);
  const wanted = ['LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md', 'bin/premier.js', 'package.json'];
  if (files.join() !== wanted.join()) problems.push(`launcher: would publish [${files.join(', ')}], expected [${wanted.join(', ')}]`);
}
if (!ranHost && !flag('--skip-host-run')) {
  problems.push(`no staged package matches this host (${process.platform}-${process.arch}), so none was executed`);
}

if (problems.length > 0) {
  console.error('staged npm packages failed verification:');
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
for (const line of report) console.log(line);
console.log(`staged npm packages for ${version} verified${ranHost ? '; host package executed' : ''}`);
