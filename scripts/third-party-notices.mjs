// Writes THIRD_PARTY_NOTICES.md: the third-party code that ships inside Premier, with the licence
// each package declares.
//
//   node scripts/third-party-notices.mjs                  regenerate the file
//   node scripts/third-party-notices.mjs --check          fail when the checked-in file is out of date
//   node scripts/third-party-notices.mjs --targets a,b    cover only these Rust targets (see below)
//
// Nothing is downloaded. The Rust list is the dependency closure of the `premier` binary as pinned
// by Cargo.lock, resolved once per release target, with licences read by `cargo metadata --offline`
// from the crates in the local registry. Cargo.lock records no licences, so every crate of every
// release target has to be in that registry: run `cargo fetch --locked` once on a machine that has
// only ever built for its own platform. Without that, `--targets` restricts the file to the targets
// that do resolve, and the file says which release targets it leaves out.
//
// The JavaScript list is every package in package-lock.json that is not development-only: what the
// viewer build bundles. package-lock.json records each package's licence.
import { execFileSync } from 'node:child_process';
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

/** Packages the lockfile does not mark as development-only: the viewer's bundled dependencies. */
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

const rust = sorted(rustPackages());
const javascript = sorted(javascriptPackages());
const undeclared = [...rust, ...javascript].filter((item) => !item.license);
if (undeclared.length > 0) {
  fail(`no declared licence for: ${undeclared.map((item) => `${item.name}@${item.version}`).join(', ')}. Record it before releasing.`);
}

const document = `# Third-party notices

The \`premier\` binary and the viewer embedded in it include the third-party software listed
below. Each package is distributed under the licence its authors declare, shown as an SPDX
expression; where an expression offers a choice (\`MIT OR Apache-2.0\`), Premier uses the package
under either. The full licence text and copyright notices of a package are published with it at
the listed source.

Premier itself is licensed under the terms in [LICENSE](LICENSE).

This file is generated by \`node scripts/third-party-notices.mjs\` from \`Cargo.lock\` and
\`package-lock.json\`. Do not edit it by hand: change a dependency, then regenerate it.
[docs/releasing.md](docs/releasing.md#third-party-notices) says what is and is not listed.

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

## JavaScript packages bundled into the viewer

${javascript.length} packages: every package in \`package-lock.json\` that is not development-only.

${licenceSummary(javascript)}

${table(javascript)}
`;

if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(output, 'utf8');
  } catch {
    fail('THIRD_PARTY_NOTICES.md is missing. Run `node scripts/third-party-notices.mjs`.');
  }
  if (current !== document) fail(`THIRD_PARTY_NOTICES.md is out of date${uncovered.length ? ' for the targets given' : ''}. Run \`node scripts/third-party-notices.mjs\` and commit the result.`);
  console.log(`Third-party notices are current (${rust.length} crates, ${javascript.length} JavaScript packages).`);
} else {
  writeFileSync(output, document);
  console.log(`Wrote THIRD_PARTY_NOTICES.md (${rust.length} crates, ${javascript.length} JavaScript packages).`);
}
