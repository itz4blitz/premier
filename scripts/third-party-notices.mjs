// Writes THIRD_PARTY_NOTICES.md: the third-party code that ships inside Premier, with the licence
// each package declares.
//
//   node scripts/third-party-notices.mjs                  regenerate the file
//   node scripts/third-party-notices.mjs --check          fail when the checked-in file is out of date
//                                                         (works without the crates on disk, see below)
//   node scripts/third-party-notices.mjs --targets a,b    cover only these Rust targets (see below)
//
// Nothing is downloaded. The Rust list is the dependency closure of the `premier` binary as pinned
// by Cargo.lock, resolved once per release target, with licences read by `cargo metadata --offline`
// from the crates in the local registry. Cargo.lock records no licences, so every crate of every
// release target has to be in that registry: run `cargo fetch --locked` once on a machine that has
// only ever built for its own platform. Without that, `--targets` restricts the file to the targets
// that do resolve, and the file says which release targets it leaves out.
//
// The JavaScript list is every package in package-lock.json that is not development-only: the
// dependencies of the viewer build and of the SDK. package-lock.json records each package's licence.
//
// The file also records a digest of the third-party packages each lockfile pins. `--check` always
// compares those digests and the JavaScript list, which needs nothing but the two lockfiles, so it
// fails on a stale file in CI without downloading anything. When every release target's crates are
// in the local registry it also regenerates the whole file and compares it byte for byte.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = join(root, 'THIRD_PARTY_NOTICES.md');
/** The crate whose binary is released. */
const BINARY_CRATE = 'premier-cli';
/** The targets .github/workflows/release.yml builds. */
const RELEASE_TARGETS = ['aarch64-apple-darwin', 'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'x86_64-unknown-linux-gnu'];
/** Asset-only package scopes carry no code and are outside the scope of this file. */
const ASSET_ONLY_SCOPES = ['@fontsource/', '@fontsource-variable/'];

function fail(message) {
  console.error(`third-party notices: ${message}`);
  process.exit(1);
}

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const targets = (option('--targets')?.split(',').map((target) => target.trim()).filter(Boolean) ?? RELEASE_TARGETS).sort();
const unknownTargets = targets.filter((target) => !RELEASE_TARGETS.includes(target));
if (targets.length === 0 || unknownTargets.length > 0) {
  fail(`--targets takes a comma-separated list of release targets (${RELEASE_TARGETS.join(', ')})${unknownTargets.length ? `; not one of them: ${unknownTargets.join(', ')}` : ''}`);
}
const uncovered = RELEASE_TARGETS.filter((target) => !targets.includes(target));

const checking = process.argv.includes('--check');

/** Thrown in `--check` mode when a target's crates are not in the local registry. */
class UnresolvedTarget extends Error {
  constructor(target, reason) {
    super(`${target}: ${reason}`);
    this.target = target;
  }
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * Digest of the third-party crates Cargo.lock pins: name, version and checksum of every package
 * that has a source. Workspace members are left out, so a Premier version bump does not change it.
 */
function cargoLockDigest() {
  const lock = readFileSync(join(root, 'Cargo.lock'), 'utf8');
  const lines = [];
  for (const block of lock.split(/^\[\[package\]\]$/m).slice(1)) {
    const field = (name) => block.match(new RegExp(`^${name} = "([^"]*)"$`, 'm'))?.[1];
    if (!field('source')) continue;
    lines.push(`${field('name')} ${field('version')} ${field('checksum') ?? field('source')}`);
  }
  if (lines.length === 0) fail('Cargo.lock lists no third-party package');
  return sha256(`${lines.sort().join('\n')}\n`);
}

/** Digest of the packages package-lock.json pins, with whether each is development-only. */
function packageLockDigest() {
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  const lines = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path.includes('node_modules/') || entry.link) continue;
    lines.push(`${path} ${entry.version} ${entry.integrity ?? ''} ${entry.dev ? 'dev' : 'bundled'} ${entry.license ?? ''}`);
  }
  return sha256(`${lines.sort().join('\n')}\n`);
}

/** Crates linked into the binary released for `target`: normal dependencies only. */
function rustPackagesFor(target) {
  let metadata;
  try {
    metadata = JSON.parse(execFileSync(
      'cargo',
      ['metadata', '--format-version', '1', '--locked', '--offline', '--filter-platform', target],
      { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }
    ));
  } catch (error) {
    const reason = String(error.stderr ?? error.message).trim().split('\n')[0];
    if (checking) throw new UnresolvedTarget(target, reason);
    fail(`the dependencies of ${target} could not be resolved offline (${reason}).\n`
      + 'Run `cargo fetch --locked` once so every release target\'s crates are in the local registry, then retry;\n'
      + 'or pass --targets with the targets that do resolve, and the file will say which ones it leaves out.');
  }
  const byId = new Map(metadata.packages.map((item) => [item.id, item]));
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const start = metadata.packages.find((item) => item.name === BINARY_CRATE && item.source === null);
  if (!start) fail(`workspace crate ${BINARY_CRATE} was not found`);
  const seen = new Set([start.id]);
  const queue = [start.id];
  while (queue.length > 0) {
    const node = nodes.get(queue.pop());
    for (const dependency of node?.deps ?? []) {
      // `kind: null` is a normal dependency; build- and dev-dependencies are not in the binary.
      if (!dependency.dep_kinds.some((kind) => kind.kind === null) || seen.has(dependency.pkg)) continue;
      seen.add(dependency.pkg);
      queue.push(dependency.pkg);
    }
  }
  return [...seen]
    .map((id) => byId.get(id))
    // Workspace members are Premier itself.
    .filter((item) => item.source !== null)
    .map((item) => ({
      name: item.name,
      version: item.version,
      license: item.license ?? (item.license_file ? `see ${item.license_file} in the crate` : null),
      source: item.repository ?? `https://crates.io/crates/${item.name}`
    }));
}

function rustPackages() {
  return targets.flatMap(rustPackagesFor);
}

/** Packages the lockfile does not mark as development-only: what the viewer and the SDK depend on. */
function javascriptPackages() {
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion < 2) fail('package-lock.json must be lockfileVersion 2 or later (it records licences)');
  const packages = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    // Workspace packages and their links are Premier itself.
    if (!path.includes('node_modules/') || entry.link || entry.dev) continue;
    const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    if (ASSET_ONLY_SCOPES.some((scope) => name.startsWith(scope))) continue;
    packages.push({
      name,
      version: entry.version,
      license: entry.license ?? null,
      source: `https://www.npmjs.com/package/${name}/v/${entry.version}`
    });
  }
  return packages;
}

function sorted(packages) {
  const unique = new Map(packages.map((item) => [`${item.name}@${item.version}`, item]));
  return [...unique.values()].sort((a, b) => a.name.localeCompare(b.name, 'en') || a.version.localeCompare(b.version, 'en', { numeric: true }));
}

function table(packages) {
  const cell = (value) => String(value).replace(/\|/g, '\\|');
  return [
    '| Package | Version | Declared licence | Source |',
    '| --- | --- | --- | --- |',
    ...packages.map((item) => `| ${cell(item.name)} | ${cell(item.version)} | ${cell(item.license)} | ${cell(item.source)} |`)
  ].join('\n');
}

function licenceSummary(packages) {
  const counts = new Map();
  for (const item of packages) counts.set(item.license, (counts.get(item.license) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'en'))
    .map(([license, count]) => `- ${license}: ${count}`)
    .join('\n');
}

const javascript = sorted(javascriptPackages());
const digestLine = `Lockfile digests: \`Cargo.lock\` third-party packages \`sha256:${cargoLockDigest()}\`; \`package-lock.json\` packages \`sha256:${packageLockDigest()}\`.`;

function requireLicences(packages) {
  const undeclared = packages.filter((item) => !item.license);
  if (undeclared.length > 0) {
    fail(`no declared licence for: ${undeclared.map((item) => `${item.name}@${item.version}`).join(', ')}. Record it before releasing.`);
  }
}

/** What the published SDK adds: its own runtime dependencies are in the same lockfile. */
function sdkSentence() {
  const sdk = JSON.parse(readFileSync(join(root, 'sdk', 'js', 'package.json'), 'utf8'));
  const names = Object.keys(sdk.dependencies ?? {});
  return names.length === 0
    ? `\`${sdk.name}\` declares no runtime dependencies and includes no third-party code.`
    : `The runtime dependencies of \`${sdk.name}\` (${names.join(', ')}) are in this list too.`;
}

function javascriptSection() {
  return `## JavaScript packages bundled into the viewer

${javascript.length} packages: every package in \`package-lock.json\` that is not development-only. They
are the dependencies of the viewer embedded in the binary. ${sdkSentence()}

${licenceSummary(javascript)}

${table(javascript)}
`;
}

function render(rust) {
  return `# Third-party notices

The \`premier\` binary and the viewer embedded in it include the third-party software listed
below. Each package is distributed under the licence its authors declare, shown as an SPDX
expression; where an expression offers a choice (\`MIT OR Apache-2.0\`), Premier uses the package
under either. The full licence text and copyright notices of a package are published with it at
the listed source.

Premier itself is licensed under the terms in the \`LICENSE\` file distributed beside this one.

This file is generated by \`node scripts/third-party-notices.mjs\` from \`Cargo.lock\` and
\`package-lock.json\` in the Premier repository. Do not edit it by hand: change a dependency, then
regenerate it. \`docs/releasing.md\` there says what is and is not listed.

${digestLine}

## Rust crates in the \`premier\` binary

${rust.length} crates: the normal (not build-time, not test-only) dependency closure of
\`${BINARY_CRATE}\` for ${targets.map((target) => `\`${target}\``).join(', ')}.
${uncovered.length > 0 ? `
**Incomplete.** The crates specific to ${uncovered.map((target) => `\`${target}\``).join(' and ')} were not in the
local registry when this file was generated, so a binary for ${uncovered.length === 1 ? 'that target' : 'those targets'} may link crates that are not
listed here. Run \`cargo fetch --locked\`, then \`node scripts/third-party-notices.mjs\`, before this file
ships with a release.
` : ''}
${licenceSummary(rust)}

${table(rust)}

${javascriptSection()}`;
}

requireLicences(javascript);
const regenerate = 'Run `cargo fetch --locked`, then `node scripts/third-party-notices.mjs`, and commit the result.';

if (checking) {
  let current = '';
  try {
    current = readFileSync(output, 'utf8');
  } catch {
    fail('THIRD_PARTY_NOTICES.md is missing. Run `node scripts/third-party-notices.mjs`.');
  }
  // These three need only the lockfiles.
  if (!current.includes(`\n${digestLine}\n`)) {
    fail(`THIRD_PARTY_NOTICES.md is out of date: Cargo.lock or package-lock.json pins different packages than the file was generated from. ${regenerate}`);
  }
  if (!current.endsWith(`\n${javascriptSection()}`)) {
    fail(`THIRD_PARTY_NOTICES.md is out of date: its JavaScript list differs from package-lock.json. ${regenerate}`);
  }
  if (uncovered.length === 0 && current.includes('**Incomplete.**')) {
    fail(`THIRD_PARTY_NOTICES.md does not cover every release target. ${regenerate}`);
  }
  let rust;
  try {
    rust = sorted(rustPackages());
  } catch (error) {
    if (!(error instanceof UnresolvedTarget)) throw error;
    console.log(`Third-party notices match the lockfiles (${javascript.length} JavaScript packages; lockfile digests agree). `
      + `The Rust table was not regenerated: the crates of ${error.target} are not in the local registry.`);
    process.exit(0);
  }
  requireLicences(rust);
  if (current !== render(rust)) fail(`THIRD_PARTY_NOTICES.md is out of date${uncovered.length ? ' for the targets given' : ''}. ${regenerate}`);
  console.log(`Third-party notices are current (${rust.length} crates, ${javascript.length} JavaScript packages).`);
} else {
  const rust = sorted(rustPackages());
  requireLicences(rust);
  writeFileSync(output, render(rust));
  console.log(`Wrote THIRD_PARTY_NOTICES.md (${rust.length} crates, ${javascript.length} JavaScript packages).`);
}
