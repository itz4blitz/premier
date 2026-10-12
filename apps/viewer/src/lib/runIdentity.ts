import type { TraceManifest } from './types';

export interface RunIdentityContext {
  goal?: string | null;
  summary?: string | null;
}

export interface RunIdentity {
  title: string;
  source: 'name' | 'goal' | 'summary' | 'command' | 'fallback';
}

type IdentityManifest = Pick<TraceManifest, 'name' | 'command'>;

const GENERIC_LABELS = new Set([
  'agent run',
  'command run',
  'recorded run',
  'run',
  'shell agent run',
  'shell command',
  'shell run',
]);

/** Shells: any flag cluster containing `c` (`-c`, `-lc`, `-ec`) passes the script inline. */
const SHELLS = new Set(['ash', 'bash', 'dash', 'fish', 'ksh', 'sh', 'zsh']);
/** Interpreters and the flags that take source text as the next argument. */
const INLINE_CODE_FLAGS: Record<string, Set<string>> = {
  bun: new Set(['-e', '--eval', '-p', '--print']),
  cmd: new Set(['/c', '/k']),
  deno: new Set(['eval']),
  node: new Set(['-e', '--eval', '-p', '--print']),
  perl: new Set(['-e', '-E']),
  php: new Set(['-r']),
  powershell: new Set(['-c', '-command', '-encodedcommand', '-e', '-ec']),
  pwsh: new Set(['-c', '-command', '-encodedcommand', '-e', '-ec']),
  python: new Set(['-c']),
  python3: new Set(['-c']),
  ruby: new Set(['-e']),
};
/** Wrappers that run the command that follows them. */
const WRAPPERS = new Set(['command', 'doas', 'env', 'exec', 'nice', 'nohup', 'stdbuf', 'sudo', 'time', 'timeout']);
const MAX_TITLE_LENGTH = 80;
/** A flag or variable whose name says its value is a credential. */
const SECRET_NAME = /(?:api[-_]?key|access[-_]?key|auth|bearer|credential|passphrase|passwd|password|private[-_]?key|secret|session|signature|token)/i;
const MASK = '[redacted]';

function executableName(value: string): string {
  const name = value.split(/[\\/]/).pop()?.toLowerCase() ?? '';
  return name.replace(/\.(?:exe|cmd|bat|com)$/, '').replace(/^(python|pypy)[\d.]+$/, '$1');
}

function normalizeSemanticLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (!normalized || GENERIC_LABELS.has(normalized.toLowerCase())) return null;
  // Semantic metadata occasionally inherits an invocation verbatim. Keep scripts in
  // the command disclosure rather than turning them into navigation labels.
  if (
    value.includes('\n') ||
    /^#!\s*\//.test(normalized) ||
    /(?:^|\s)(?:curl|wget)\s.+(?:--data|-d)\b/i.test(normalized) ||
    /(?:^|\s)(?:function\s+\w+|\w+\s*\(\)\s*\{)/.test(normalized) ||
    /(?:&&|\|\||;\s*(?:curl|post|printf|echo)\b)/i.test(normalized)
  ) return null;
  return normalized;
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const WRAPPER_VALUE_OPTIONS = new Set(['-n', '-u', '-g', '-k', '-s', '-C', '-S']);

/** The command a wrapper runs: `env A=1 nice -n 5 bash -lc ...` is a `bash` invocation. */
function unwrapped(command: string[]): string[] {
  let rest = command;
  for (let depth = 0; depth < 4 && rest.length > 1 && WRAPPERS.has(executableName(rest[0])); depth += 1) {
    let index = 1;
    // Skip the wrapper's own options, their values (`-n 5`, `-u root`), durations and variable assignments.
    while (index < rest.length - 1) {
      const argument = rest[index];
      if (WRAPPER_VALUE_OPTIONS.has(argument)) index += 2;
      else if (argument.startsWith('-') || ASSIGNMENT.test(argument) || /^\d+(?:\.\d+)?[smhd]?$/.test(argument)) index += 1;
      else break;
    }
    index = Math.min(index, rest.length - 1);
    rest = rest.slice(index);
  }
  return rest;
}

function isInlineCodeInvocation(input: string[]): boolean {
  const command = unwrapped(input);
  if (command.length < 2) return false;
  const executable = executableName(command[0]);
  const flags = INLINE_CODE_FLAGS[executable];
  const shell = SHELLS.has(executable);
  if (!flags && !shell) return false;
  // Options may come before the one that carries the source (`python -u -c`, `bash -l -c`).
  for (const argument of command.slice(1)) {
    const lowered = argument.toLowerCase();
    if (flags?.has(argument) || flags?.has(lowered)) return true;
    if (shell && /^-[a-z]*c[a-z]*$/i.test(argument)) return true;
    if (!argument.startsWith('-') && !(executable === 'cmd' && argument.startsWith('/'))) return false;
  }
  return false;
}

/** Arguments with credentials masked: `--token=x`, `--token x`, `KEY=x`, and URL user info. */
function maskedArguments(command: string[]): string[] {
  const output: string[] = [];
  let maskNext = false;
  for (const argument of command) {
    if (maskNext) {
      output.push(MASK);
      maskNext = false;
      continue;
    }
    const assignment = /^(-{0,2}[A-Za-z_][\w.-]*)=(.*)$/s.exec(argument);
    if (assignment && SECRET_NAME.test(assignment[1])) {
      output.push(`${assignment[1]}=${MASK}`);
      continue;
    }
    if (argument.startsWith('-') && SECRET_NAME.test(argument) && !argument.includes('=')) {
      output.push(argument);
      maskNext = true;
      continue;
    }
    output.push(argument.replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi, `$1${MASK}@`));
  }
  return output;
}

function commandTitle(command: string[]): string | null {
  if (command.length === 0 || isInlineCodeInvocation(command)) return null;
  const masked = maskedArguments(command);
  const safeArguments = masked
    .slice(1, 4)
    .filter((argument) => argument && !argument.includes('\n'));
  const title = safeArguments.length === 0 ? masked[0] || null : [masked[0], ...safeArguments].join(' ');
  if (!title) return null;
  return title.length > MAX_TITLE_LENGTH ? `${title.slice(0, MAX_TITLE_LENGTH - 1)}…` : title;
}

/**
 * Derives the stable, human-facing identity of a recorded run.
 *
 * Explicit semantic metadata wins. Inline source passed to a shell or interpreter
 * is never returned; callers can still present the complete invocation separately.
 */
export function deriveRunIdentity(
  manifest: IdentityManifest,
  context: RunIdentityContext = {},
): RunIdentity {
  const candidates: Array<[RunIdentity['source'], string | null | undefined]> = [
    ['name', manifest.name],
    ['goal', context.goal],
    ['summary', context.summary],
  ];

  for (const [source, candidate] of candidates) {
    const title = normalizeSemanticLabel(candidate);
    if (title) return { title, source };
  }

  const title = commandTitle(manifest.command);
  if (title) return { title, source: 'command' };

  return {
    title: isInlineCodeInvocation(manifest.command) ? 'Recorded inline workflow' : 'Recorded run',
    source: 'fallback',
  };
}
