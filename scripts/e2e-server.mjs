// Builds the viewer and the CLI, records the traces the Playwright suite needs, and serves them.
//
// Seeded traces, oldest first (the viewer opens the newest, the demo, by default):
//
//   passing-smoke.atrace   a real recording that exits 0
//   failing-build.atrace   a real recording that exits 3, with an error on stderr and a
//                          credential-shaped value on stdout for the safe-export test
//   adapter-claude.atrace  recorded through the Claude adapter from its checked-in fixture
//   signed.atrace          recorded with --sign-key
//   encrypted.atrace       recorded with --key-file; the server is started WITHOUT that key
//   tampered.atrace        a copy of failing-build whose manifest was edited to claim exit 0
//   multi-agent.atrace     `premier demo`
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// fileURLToPath, not URL.pathname: a checkout path with a space or a non-ASCII character is
// percent-encoded in the URL and would not exist as a directory.
const cwd = fileURLToPath(new URL('..', import.meta.url));
const port = process.env.PREMIER_E2E_PORT ?? '4318';
const traceRoot = join('.tmp', 'e2e-traces');
const keyRoot = join('.tmp', 'e2e-keys');
for (const directory of [traceRoot, keyRoot]) {
  rmSync(join(cwd, directory), { recursive: true, force: true });
  mkdirSync(join(cwd, directory), { recursive: true });
}

/** Run a step to completion. Any exit status outside `allow` stops the seed and says which step. */
function run(command, args, { allow = [0], quiet = false } = {}) {
  const result = spawnSync(command, args, { cwd, stdio: quiet ? ['ignore', 'ignore', 'inherit'] : 'inherit' });
  if (result.error) {
    console.error(`e2e seed: could not run ${command}: ${result.error.message} (cwd ${cwd})`);
    process.exit(1);
  }
  if (!allow.includes(result.status)) {
    console.error(`e2e seed: ${command} ${args.join(' ')} exited with ${result.status ?? `signal ${result.signal}`}`);
    process.exit(result.status ?? 1);
  }
}

run('npm', ['run', 'build', '--workspace', '@premier/viewer']);
// One build, then the binary directly: `cargo run` per step re-checks the workspace every time.
run('cargo', ['build', '--quiet', '-p', 'premier-cli', '--bin', 'premier']);
const targetDir = process.env.CARGO_TARGET_DIR ?? join(cwd, 'target');
const premier = join(targetDir, 'debug', process.platform === 'win32' ? 'premier.exe' : 'premier');
if (!existsSync(premier)) {
  console.error(`e2e seed: the premier binary was not found at ${premier}; set CARGO_TARGET_DIR to cargo's target directory`);
  process.exit(1);
}

const trace = (name) => join(traceRoot, name);
/** `premier record` exits with the recorded command's status. */
const record = (args, allow = [0]) => run(premier, args, { allow, quiet: true });

record(['record', '--output', trace('passing-smoke.atrace'), '--name', 'Passing smoke run', 'sh', '-c', 'printf "passing evidence\\n"']);

// Assembled here so no credential-shaped literal is checked in; tests/viewer.spec.ts builds the same value.
const credential = ['e2e', 'deploy', 'credential', '0001'].join('-');
record([
  'record', '--output', trace('failing-build.atrace'), '--name', 'Failing build run', 'sh', '-c',
  `printf "compiling ledger\\n"; printf "deploy password=${credential} region=test\\n"; printf "error: rounding check failed\\n" >&2; exit 3`
], [3]);

record(['record', '--adapter', 'claude', '--output', trace('adapter-claude.atrace'), '--name', 'Adapter recorded run', '--', 'cat', join('crates', 'premier-cli', 'tests', 'fixtures', 'adapters', 'claude.jsonl')]);

run(premier, ['keygen', join(keyRoot, 'sign.key')], { quiet: true });
record(['record', '--sign-key', join(keyRoot, 'sign.key'), '--output', trace('signed.atrace'), '--name', 'Signed run', 'sh', '-c', 'printf "signed evidence\\n"']);

run(premier, ['keygen', '--encryption', join(keyRoot, 'encryption.key')], { quiet: true });
record(['--key-file', join(keyRoot, 'encryption.key'), 'record', '--output', trace('encrypted.atrace'), '--name', 'Encrypted run', 'sh', '-c', 'printf "sealed evidence\\n"']);

// A copy whose manifest was edited after finalization to hide the failure.
cpSync(join(cwd, trace('failing-build.atrace')), join(cwd, trace('tampered.atrace')), { recursive: true });
const tamperedManifest = join(cwd, trace('tampered.atrace'), 'manifest.json');
const manifest = JSON.parse(readFileSync(tamperedManifest, 'utf8'));
manifest.name = 'Tampered copy';
manifest.exit_code = 0;
manifest.termination = { kind: 'exit', exit_code: 0 };
writeFileSync(tamperedManifest, JSON.stringify(manifest, null, 2));

// Last, so it is the newest run and the one the viewer opens first.
run(premier, ['demo', '--output', trace('multi-agent.atrace')], { quiet: true });

// Serve uses the embedded viewer by default (built into the binary after npm run build). The
// encryption key is deliberately not passed: encrypted.atrace must be listed as locked.
const environment = { ...process.env };
delete environment.PREMIER_TRACE_KEY_FILE;
const server = spawn(premier, ['serve', '--trace-dir', traceRoot, '--bind', `127.0.0.1:${port}`, '--password', 'e2e-secret'], { cwd, stdio: 'inherit', env: environment });
server.on('error', (error) => {
  console.error(`e2e seed: could not start the viewer server: ${error.message}`);
  process.exit(1);
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.kill(signal));
server.on('exit', (code) => process.exit(code ?? 0));
