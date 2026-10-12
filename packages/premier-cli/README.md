# @premierstudio/premier

The script-free npm distribution of the Premier agent flight recorder. The
package selects a platform-specific optional dependency and launches the native
`premier` binary. It does not run install scripts or download remote binaries.

```sh
npm install --global @premierstudio/premier
premier --version
premier demo
```

See [premier.dev/docs/install](https://premier.dev/docs/install) for global,
project-local, and provider-specific recording workflows.

## Supported platforms

Node.js 18 or later, on:

| Platform | Architecture | Native package |
| --- | --- | --- |
| macOS | Apple silicon (`arm64`) | `@premierstudio/premier-darwin-arm64` |
| macOS | Intel (`x64`) | `@premierstudio/premier-darwin-x64` |
| Linux (glibc) | `arm64` | `@premierstudio/premier-linux-arm64-gnu` |
| Linux (glibc) | `x64` | `@premierstudio/premier-linux-x64-gnu` |

Not published: Windows, and Linux with a C library other than glibc (musl, as
on Alpine). `npm install` still succeeds there, because the launcher itself
runs anywhere Node.js does; the first `premier` command then exits `1` and
says why:

| System | What `premier` prints | What to do |
| --- | --- | --- |
| musl Linux (Alpine) | `Premier publishes Linux binaries for glibc only` | Use a glibc-based image (`node:22-slim` rather than `node:22-alpine`), or build from source. |
| Windows | `Premier does not publish a binary for win32-<arch>` | Run Premier inside WSL 2. |
| Any other platform or architecture | `Premier does not publish a binary for <platform>-<arch>`, with the list of published ones | Build from source. |
| glibc older than the binary needs | `This Premier binary needs glibc <x.y> or later; this system has glibc <a.b>` | Use a newer distribution or image, or build from source. |
| Native package not installed (`npm install --omit=optional`) | `The optional package <name> is missing` | Reinstall without omitting optional dependencies. |

Building from source needs Rust and Node.js; the steps are in
[CONTRIBUTING.md](https://github.com/PremierStudio/premier/blob/main/CONTRIBUTING.md#build-order).

The Linux binaries are built on Ubuntu 24.04 (glibc 2.39) and may need a glibc
as new as that. The exact requirement of a release is recorded in its Linux
packages (`premier.glibc` in their `package.json`), which is what the launcher
compares against.

## What the launcher checks

Before it starts the native binary the launcher:

1. picks the platform package for this operating system, architecture and C
   library, as above;
2. resolves it the way Node.js resolves any package, and reads its
   `package.json`;
3. requires that package's version to equal the launcher's own. The two are
   published together, and the launcher pins the exact version, but a stale
   lockfile entry or a hoisted copy from another install can still put a
   different one in the way. That is refused
   (`<name> is version X, but this launcher (@premierstudio/premier) is Y`)
   rather than run;
4. on Linux, compares the system's glibc with the package's `premier.glibc`.

It does not verify a signature or digest of the binary. What protects the
binary is npm's integrity check of the package at install time and its
provenance attestation (`npm audit signatures`). macOS binaries are ad hoc
signed and not notarized; see
[docs/releasing.md](https://github.com/PremierStudio/premier/blob/main/docs/releasing.md#macos-signing).

## The launcher

`premier` on your `PATH` is a small Node.js launcher that starts the native
binary with the same arguments and inherited standard streams, and exits the
way it does:

- If the binary exits with a code, the launcher exits with that code.
- If the binary is killed by a signal, the launcher re-raises the same signal
  on itself, so the caller sees the real termination.

### Signal forwarding

The launcher stays between your shell or supervisor and the native binary, so
it relays stop signals to it:

| Signal | Forwarded to the native binary |
| --- | --- |
| `SIGTERM`, `SIGHUP` | Always. |
| `SIGINT`, `SIGQUIT` | Only when standard input is not a terminal. |

When standard input is a terminal, Ctrl-C and Ctrl-\ are delivered by the
terminal to the whole foreground process group, which already includes the
native binary. Forwarding them again would hand the recorder a second
interrupt for one keypress, and the recorder treats repeated interrupts as a
request to kill the recorded command.

One consequence: with a terminal on standard input, `kill -INT <launcher pid>`
from another shell is not forwarded either. Use `SIGTERM` to stop a recording
from outside; it is always forwarded, and the recorder forwards it to the
recorded command and finalizes the trace.

What the native binary does with each signal during `premier record` is
described in [docs/cli.md](https://github.com/PremierStudio/premier/blob/main/docs/cli.md#signals).
