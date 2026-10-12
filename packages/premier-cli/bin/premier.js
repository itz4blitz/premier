#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { constants } = require('node:os');
const { join } = require('node:path');
const { isatty } = require('node:tty');

const FORWARDED_SIGNALS = Object.freeze(['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT']);
const TERMINAL_SIGNALS = new Set(['SIGINT', 'SIGQUIT']);

const PLATFORM_PACKAGES = Object.freeze({
  'darwin-arm64': '@premierstudio/premier-darwin-arm64',
  'darwin-x64': '@premierstudio/premier-darwin-x64',
  'linux-arm64': '@premierstudio/premier-linux-arm64-gnu',
  'linux-x64': '@premierstudio/premier-linux-x64-gnu',
});

const SOURCE_BUILD =
  'Build it from source instead (Rust and Node.js required): https://github.com/PremierStudio/premier/blob/main/CONTRIBUTING.md';

function packageFor(platform, arch, report = process.report) {
  if (platform === 'linux' && !glibcVersion(report)) {
    throw new Error(
      [
        'Premier publishes Linux binaries for glibc only; this system uses another C library (musl, as on Alpine).',
        'Use a glibc-based image (for example node:22-slim instead of node:22-alpine), or:',
        SOURCE_BUILD,
      ].join('\n'),
    );
  }
  const name = PLATFORM_PACKAGES[`${platform}-${arch}`];
  if (!name) {
    const lines = [
      `Premier does not publish a binary for ${platform}-${arch}.`,
      `Published: ${Object.keys(PLATFORM_PACKAGES).join(', ')} (Linux: glibc only).`,
    ];
    if (platform === 'win32') lines.push('On Windows, install and run Premier inside WSL 2.');
    lines.push(SOURCE_BUILD);
    throw new Error(lines.join('\n'));
  }
  return name;
}

// The glibc version of this process, or undefined on musl and non-Linux.
function glibcVersion(report = process.report) {
  const header = report && typeof report.getReport === 'function' ? report.getReport().header : {};
  return header.glibcVersionRuntime || undefined;
}

// Numeric comparison of dotted versions such as 2.9 and 2.39.
function versionBelow(actual, required) {
  const left = String(actual).split('.').map(Number);
  const right = String(required).split('.').map(Number);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = (left[index] || 0) - (right[index] || 0);
    if (difference !== 0) return difference < 0;
  }
  return false;
}

/**
 * Refuse a platform package that is not the one this launcher was published
 * with, or whose binary needs a newer glibc than this system has. Without
 * these checks a stale or hoisted package of another version is run without a
 * word, and an old glibc surfaces as a loader error about missing symbols.
 */
function checkPlatformPackage(packageName, platformManifest, launcherManifest, report = process.report) {
  if (platformManifest.version !== launcherManifest.version) {
    throw new Error(
      [
        `${packageName} is version ${platformManifest.version}, but this launcher (${launcherManifest.name}) is ${launcherManifest.version}.`,
        'The two are published together and must match; a stale or hoisted copy was resolved.',
        `Reinstall ${launcherManifest.name} (remove node_modules and the lockfile entry for ${packageName} if it persists).`,
      ].join('\n'),
    );
  }
  const required = platformManifest.premier && platformManifest.premier.glibc;
  const actual = glibcVersion(report);
  if (required && actual && versionBelow(actual, required)) {
    throw new Error(
      [
        `This Premier binary needs glibc ${required} or later; this system has glibc ${actual}.`,
        'Use a newer distribution or container image, or:',
        SOURCE_BUILD,
      ].join('\n'),
    );
  }
}

function resolveBinary(platform = process.platform, arch = process.arch, options = {}) {
  const resolve = options.resolve ?? require.resolve;
  const packageName = packageFor(platform, arch, options.report);
  let manifest;
  try {
    manifest = resolve(`${packageName}/package.json`);
  } catch (error) {
    const message = [
      `The optional package ${packageName} is missing.`,
      'Reinstall @premierstudio/premier without omitting optional dependencies.',
      `Original resolution error: ${error.message}`,
    ].join('\n');
    throw new Error(message);
  }
  checkPlatformPackage(
    packageName,
    JSON.parse(readFileSync(manifest, 'utf8')),
    options.launcherManifest ?? require('../package.json'),
    options.report,
  );
  return join(manifest, '..', 'bin', 'premier');
}

function main() {
  let binary;
  try {
    binary = resolveBinary();
  } catch (error) {
    process.stderr.write(`premier: ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  run(binary, process.argv.slice(2));
}

// Run the native binary without blocking the event loop, so signals sent to
// this launcher reach it. A synchronous spawn would let SIGTERM/SIGHUP kill
// only the launcher and leave the recorder and the recorded agent running.
function run(binary, args) {
  // stdio stays inherited so the native binary owns the terminal (PTY mode).
  const child = spawn(binary, args, { stdio: 'inherit' });
  const handlers = new Map();
  for (const signal of FORWARDED_SIGNALS) {
    const handler = () => {
      // Ctrl-C and Ctrl-\ are delivered by the terminal to the whole
      // foreground process group, which already includes the native binary;
      // forwarding them again would look like a second, forceful interrupt.
      // isatty(0) rather than process.stdin, which would open the inherited
      // terminal in this process and disturb the child that is using it.
      if (TERMINAL_SIGNALS.has(signal) && isatty(0)) return;
      try {
        child.kill(signal);
      } catch {
        // The child has already exited; its exit event settles the launcher.
      }
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  const release = () => {
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  };
  child.on('error', (error) => {
    release();
    process.stderr.write(`premier: unable to launch ${binary}: ${error.message}\n`);
    process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    release();
    if (signal) {
      // Die by the same signal so callers observe the real termination; the
      // exit code only applies if that signal is ignored in this process.
      process.exitCode = 128 + (constants.signals[signal] ?? 0);
      process.kill(process.pid, signal);
      return;
    }
    process.exitCode = code ?? 1;
  });
}

if (require.main === module) main();

module.exports = { PLATFORM_PACKAGES, checkPlatformPackage, packageFor, resolveBinary, versionBelow };
