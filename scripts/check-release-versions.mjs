#!/usr/bin/env node
// Every manifest that carries the release version must carry the same one.
// Usage: node scripts/check-release-versions.mjs [VERSION] [--root DIR]
// With no VERSION the workspace version in Cargo.toml is the reference.
// Prints every mismatch (not just the first) and exits 1 if there is any.
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const rootFlag = args.indexOf('--root');
const root = rootFlag === -1 ? resolve(import.meta.dirname, '..') : resolve(args.splice(rootFlag, 2)[1]);
const json = (path) => JSON.parse(readFileSync(join(root, path), 'utf8'));

const cargoVersion = readFileSync(join(root, 'Cargo.toml'), 'utf8').match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const expected = (args[0] ?? cargoVersion ?? '').replace(/^v/, '');
const problems = [];
const check = (where, actual) => {
  if (actual !== expected) problems.push(`${where} is ${actual ?? 'missing'}, expected ${expected}`);
};

if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(expected)) {
  problems.push(`"${expected}" is not a release version (MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-PRERELEASE)`);
}
check('Cargo.toml [workspace.package] version', cargoVersion);
check('package.json version', json('package.json').version);
check('packages/premier-cli/package.json version', json('packages/premier-cli/package.json').version);
check('sdk/js/package.json version', json('sdk/js/package.json').version);
const platforms = readdirSync(join(root, 'npm', 'platforms')).sort();
const published = new Set();
for (const directory of platforms) {
  const manifest = json(`npm/platforms/${directory}/package.json`);
  published.add(manifest.name);
  check(`npm/platforms/${directory}/package.json version`, manifest.version);
}
const pins = json('packages/premier-cli/package.json').optionalDependencies ?? {};
for (const [name, pinned] of Object.entries(pins)) {
  check(`launcher optionalDependencies ${name}`, pinned);
  if (!published.has(name)) problems.push(`launcher depends on ${name}, which npm/platforms does not define`);
}
for (const name of published) {
  if (!(name in pins)) problems.push(`npm/platforms defines ${name}, which the launcher does not depend on`);
}
// Cargo.lock records the workspace crates' version; --locked builds need it current.
const lock = readFileSync(join(root, 'Cargo.lock'), 'utf8');
for (const crate of ['premier-cli', 'premier-trace']) {
  check(`Cargo.lock ${crate}`, lock.match(new RegExp(`name = "${crate}"\\nversion = "([^"]+)"`))?.[1]);
}

if (problems.length > 0) {
  console.error(`release version check failed for ${expected}:`);
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log(`release version ${expected}: ${6 + platforms.length + Object.keys(pins).length} manifests and pins agree`);
