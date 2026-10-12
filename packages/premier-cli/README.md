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

Windows and musl-based Linux (for example Alpine) are not published. On an
unsupported platform, or when the optional native package was not installed
(for example with `npm install --omit=optional`), `premier` prints the reason
and exits `1`.

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
