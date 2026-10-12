#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
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

function packageFor(platform, arch, report = process.report) {
  if (platform === 'linux') {
    const header = report && typeof report.getReport === 'function' ? report.getReport().header : {};
    if (!header.glibcVersionRuntime) {
      throw new Error('Premier currently supports glibc Linux; musl packages are not published yet.');
    }
  }
  const name = PLATFORM_PACKAGES[`${platform}-${arch}`];
  if (!name) throw new Error(`Premier does not publish a binary for ${platform}-${arch}.`);
  return name;
}

function resolveBinary(platform = process.platform, arch = process.arch) {
  const packageName = packageFor(platform, arch);
  let manifest;
  try {
    manifest = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    const message = [
      `The optional package ${packageName} is missing.`,
      'Reinstall @premierstudio/premier without omitting optional dependencies.',
      `Original resolution error: ${error.message}`,
    ].join('\n');
    throw new Error(message);
  }
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

module.exports = { PLATFORM_PACKAGES, packageFor, resolveBinary };
