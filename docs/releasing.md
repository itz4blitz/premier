# Premier release packaging

Premier release archives are reproducible wrappers around a single executable
that already embeds the production viewer. Packaging adds `README.md`, the
Apache-2.0 `LICENSE`, the `premier-emit.sh` shell helper, machine-readable
`RELEASE-METADATA`, internal `SHA256SUMS`, and an archive checksum sidecar.
Official GitHub releases also include keyless Sigstore bundles, an
authenticated aggregate checksum manifest, SPDX SBOMs, a standalone installer
(`premier-install.sh`), and GitHub build-provenance attestations.

## Supported binary matrix

| Operating system | Architecture | Rust target | Packaging | Installation |
| --- | --- | --- | --- | --- |
| macOS 13+ | Apple silicon | `aarch64-apple-darwin` | supported | supported |
| macOS 13+ | Intel | `x86_64-apple-darwin` | supported | supported |
| Linux (glibc) | x86-64 | `x86_64-unknown-linux-gnu` | supported | supported |
| Linux (glibc) | ARM64 | `aarch64-unknown-linux-gnu` | supported | supported |

Windows and musl targets (Alpine) are not packaged or published. On those
systems the npm launcher exits `1` with that reason and points at the source
build ([CONTRIBUTING.md](../CONTRIBUTING.md#build-order)); on Windows, run
Premier inside WSL 2. A native runner can build its own target directly. For
cross compilation, the release job must first produce a compatible binary and
pass it through `--binary`; the packaging script does not pretend to provision
cross-linkers or SDKs.

### glibc

The Linux binaries are built on `ubuntu-24.04` runners, whose glibc is 2.39,
and are not built against an older one. A binary therefore needs a glibc no
newer than 2.39 but possibly as new as that; what a given release needs is
measured, not assumed:

- `package-release.sh` reads the highest `GLIBC_x.y` symbol version the binary
  requires (`objdump -T`), writes it to `RELEASE-METADATA` as `GLIBC_MIN`, and
  refuses a binary that needs more than `DISTRIBUTION_GLIBC_CEILING` (2.39, in
  `scripts/lib/distribution.sh`).
- `stage-npm-packages.sh` copies `GLIBC_MIN` into the Linux platform packages
  as `premier.glibc` in their `package.json`.
- The npm launcher compares that with the running system's glibc and, when
  the system is older, exits `1` naming both versions instead of letting the
  dynamic loader fail on missing symbols.

Lowering the floor (building in an older container, or with a pinned glibc
through `cargo-zigbuild`) is not done yet.

## Produce an archive

On a native runner, build the viewer and release binary together:

```sh
./scripts/package-release.sh --target aarch64-apple-darwin --version 0.1.0
```

To package a binary built by an earlier CI step:

```sh
./scripts/package-release.sh \
  --target x86_64-unknown-linux-gnu \
  --version 0.1.0 \
  --binary ./target/x86_64-unknown-linux-gnu/release/premier
```

The default output directory is `./dist`, which git ignores.

The tar stream has sorted paths, normalized ownership and modes, and zeroed
timestamps; gzip also has a zero timestamp. Identical inputs therefore produce
identical archives and checksums.

### What packaging checks first

`RELEASE-METADATA` is signed along with the archive, so the script writes
nothing it has not observed:

| Binary | Check | Recorded as |
| --- | --- | --- |
| For this host's target | It is run: `premier build-info` must report the release version, the target, and `viewer=embedded`. A binary that embeds the placeholder page, reports another version or target, or does not answer is refused. | `VIEWER=embedded` |
| For another target | It cannot be run. Its executable header (ELF or Mach-O, and the CPU) must match the target; anything else is refused. | `VIEWER=unverified` |
| Linux, either case | The glibc requirement is read (see above). | `GLIBC_MIN=<x.y>` |

`premier build-info` is a hidden command that prints three lines:
`version=`, `target=` (the triple the binary was compiled for), and
`viewer=embedded` or `viewer=placeholder`.

**The placeholder page.** `crates/premier-cli/build.rs` embeds a placeholder
("Premier viewer assets missing") when `apps/viewer/dist` has not been built.
That is convenient for development and wrong for a release, so with
`PREMIER_REQUIRE_VIEWER=1` in the environment the build script fails instead.
`package-release.sh` sets it for the build it runs itself, and the release
workflow sets it for its release build, after it has built the viewer and
checked that `apps/viewer/dist/index.html` exists.

## Signed public release workflow

`.github/workflows/release.yml` is the only public signing path. It runs only
for version tags and requires the protected `release` environment. In order:

1. **`ci`** runs the whole CI workflow (`.github/workflows/ci.yml`) on the
   tagged commit: dependency audits, the secret scan, the Rust, viewer, SDK,
   launcher, distribution and shell tests, and the macOS job. Nothing is built
   for release until it passes.
2. **`sdk-package`** builds, tests and packs `@premierstudio/trace` in a job
   with no release permissions, and hands the tarball on as an artifact.
3. **`build`** runs once per target on a native runner: it checks that every
   manifest carries the tag's version (`scripts/check-release-versions.mjs`,
   which lists each mismatch), builds the viewer, runs the Rust suite, builds
   the release binary with `PREMIER_REQUIRE_VIEWER=1`, signs and notarizes the
   macOS binaries when signing is configured (see below), packages the
   archive, and generates an SPDX SBOM.
4. **`publish`** has narrowly scoped `contents`, `id-token`, and
   `attestations` permissions, installs no dependency tree, and uses an
   exactly pinned npm. It builds `premier-install.sh`, writes `SHA256SUMS`
   over the archives, the SBOMs and the installer, signs that manifest and
   every archive with keyless Sigstore, immediately verifies the pinned GitHub
   workflow identity and OIDC issuer, runs `verify-release.sh` on the result,
   and creates build-provenance attestations for the same files. It then
   creates the GitHub release **as a draft**, stages and verifies the npm
   packages, publishes them through npm trusted publishing with provenance,
   and only then publishes the draft.

Pull requests and branch builds cannot obtain the release signing identity or
npm publication trust.

**Prereleases.** A tag with a hyphen (`v0.2.0-rc.1`) is published as a GitHub
prerelease that is not marked latest, and its npm packages get the dist-tag
`next` instead of `latest`, so `npm install @premierstudio/premier` keeps
giving the last full release.

**If the npm stage fails**, the GitHub release is still a draft: nothing
public claims a version that npm does not have. Re-running the workflow skips
packages that were already published.

**Before npm publish**, `scripts/stage-npm-packages.sh` extracts each archive's
executable into its platform package and refuses an archive whose metadata
names another version or target, or whose viewer was not verified. Then
`scripts/verify-staged-npm.mjs` packs every package as a dry run and checks
the file list that would be uploaded, each binary's size, mode and executable
format, each manifest's version, `os`, `cpu` and `libc`, and runs the package
for the publishing host (`--version` and `build-info`).

The npm launcher and platform packages intentionally have no `preinstall`,
`install`, or `postinstall` lifecycle scripts. npm selects a platform package as
an optional dependency; package installation never downloads an executable from
an arbitrary URL and works with npm 12's secure install-time defaults.

### Pins

- Every action is pinned by commit SHA.
- The Rust toolchain is pinned in `rust-toolchain.toml`, and both workflows
  install that version.
- The publish job installs one exact npm version.
- Every checkout sets `persist-credentials: false`.

`scripts/tests/release-config.test.mjs` checks these, and the order of the
release build, on every pull request.

### Before enabling the public channel

Repository administrators must protect the `v*` tag namespace, require
approval for the `release` environment, and give every published package on
npmjs.com a GitHub Actions trusted publisher pinned to
`PremierStudio/premier`, workflow `release.yml`, environment `release`.
That link cannot be observed locally, so the release workflow exposes a
manual preflight: dispatching **Signed release** from the Actions tab runs
only `verify-npm-trusted-publishing`, which performs the same OIDC token
exchange `npm publish` will use for all six packages without publishing
anything. Run it before pushing a tag; a tag push repeats the preflight and
publishes nothing — no GitHub release, no npm packages — until it passes. CI
also rehearses the preflight's token exchange against a stub OIDC issuer and
registry (`scripts/tests/preflight-npm-trusted-publishing.test.mjs`), so a
regression in that flow fails pull requests instead of tag pushes.

### macOS signing

**Release binaries for macOS are ad hoc signed and not notarized** unless the
repository has an Apple Developer ID configured, which it does not today.
Sigstore authenticates the downloaded release asset; it is not Apple
notarization, and Gatekeeper does not consult it. Gatekeeper may therefore
block a binary that carries the quarantine attribute, as files downloaded
with a browser do, until it is allowed in System Settings or the attribute is
removed (`xattr -d com.apple.quarantine premier`).

The workflow has the step ready. When these repository secrets exist, each
macOS build signs the binary with the hardened runtime and a secure timestamp
and submits it to Apple's notary service before it is packaged
(`scripts/macos-sign-notarize.sh`); when `APPLE_SIGNING_IDENTITY` is empty the
step is skipped and the run says so in a notice.

| Secret | Value |
| --- | --- |
| `APPLE_SIGNING_IDENTITY` | The certificate's name, for example `Developer ID Application: Example Inc (TEAMID1234)` |
| `APPLE_CERTIFICATE_P12_BASE64` | The Developer ID Application certificate and key as a `.p12`, base64 |
| `APPLE_CERTIFICATE_PASSWORD` | The password of that `.p12` |
| `APPLE_API_KEY_P8_BASE64` | An App Store Connect API key (`.p8`), base64 |
| `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID` | That key's id and issuer id |

The signing script has not been run against Apple's services from this
repository. Rehearse it on a throwaway prerelease tag before relying on it.
A notarized bare executable cannot carry a stapled ticket, so Gatekeeper
checks it online the first time it runs.

The npm launcher does not verify the native binary itself: it relies on npm's
integrity check of the platform package, the exact version pin in the
launcher's `optionalDependencies`, and the version check described in
[packages/premier-cli/README.md](../packages/premier-cli/README.md#what-the-launcher-checks).

## Consumer workflow

The primary consumer path is npm:

```sh
npm install --global @premierstudio/premier
premier --version
```

For a project-local, version-pinned toolchain:

```sh
npm install --save-dev @premierstudio/premier
npx premier record -- npm test
```

The signed archive path below is the Node-free alternative. It needs `bash`,
`python3` (to validate and extract the archive safely), and `cosign`.

### Install from a signed archive

Download from the release: the archive for your platform, its sibling
`.sigstore.json` bundle, and `premier-install.sh`. The installer is
`scripts/install.sh` with its library inlined, so no source checkout is
needed; from a checkout, `./scripts/install.sh` takes the same options.

```sh
bash premier-install.sh \
  --archive ./premier-0.1.0-aarch64-apple-darwin.tar.gz \
  --signature-bundle ./premier-0.1.0-aarch64-apple-darwin.tar.gz.sigstore.json
```

`premier-install.sh` is itself listed in the signed `SHA256SUMS`; check it
with `verify-release.sh` (below) or against the manifest by hand before
running it.

The installer:

- verifies the archive against the pinned `PremierStudio/premier` release
  workflow and GitHub Actions OIDC issuer before extraction, then requires the
  signature to come from the tag of the version the archive says it is;
- rejects absolute and traversal archive paths, links and device files,
  foreign architectures (unless `--allow-foreign-architecture`), missing
  metadata, missing required payloads, and checksum mismatches;
- stages extraction outside the destination and renames the validated
  executable into place atomically;
- installs `bin/premier` and `share/premier/premier-emit.sh` under the prefix
  (`--prefix`, default `$CARGO_HOME` or `~/.cargo`), and prints a note when
  `<prefix>/bin` is not on `PATH`;
- refuses a destination that exists and is not a regular file, and an
  existing binary unless `--force` is given.

Its last line says who vouched for the archive. `(publisher signature
verified)` appears only for the pinned identity and issuer. With
`--verification-key`, or a caller-supplied `--certificate-identity-regexp` or
`--certificate-oidc-issuer`, the line names that key or identity and says it
is not the pinned publisher identity.

Unsigned archives are rejected by default. `--allow-unsigned` exists only for a
locally produced developer archive and prints an explicit warning; it is never
part of the public installation path.

From a source checkout with no `--archive`, `install.sh` uses the archive for
this host in `./dist` with the **highest version** (not the last file name:
`0.10.0` beats `0.9.0`), and otherwise builds from source. The standalone
installer never builds from source and requires `--archive`.

### Verify a downloaded release

To authenticate a complete downloaded release set in one operation, verify the
signed aggregate manifest:

```sh
./scripts/verify-release.sh --directory ./downloaded-release
```

It verifies the signature on `SHA256SUMS`, then every listed file's checksum:
the archives, the SBOMs (`premier-<target>.spdx.json`), and
`premier-install.sh`. It **fails on any file in the directory the manifest
does not cover**. Only these may sit beside the listed files: `SHA256SUMS` and
its bundle, the `.sigstore.json` bundle of a listed file, and a `.sha256`
sidecar that agrees with its listed file.

To check the build provenance of an asset (an archive, an SBOM, or the
installer) with the GitHub CLI:

```sh
gh attestation verify ./premier-0.1.0-aarch64-apple-darwin.tar.gz \
  --repo PremierStudio/premier \
  --signer-workflow PremierStudio/premier/.github/workflows/release.yml
```

Both scripts take the pinned signer from one constant,
`DISTRIBUTION_SIGNER_IDENTITY_REGEXP` in `scripts/lib/distribution.sh`: tag
builds of `.github/workflows/release.yml` in `PremierStudio/premier`. The
release workflow runs `verify-release.sh` against the assets it has just signed,
and `scripts/tests/distribution.sh` checks the constant against the identity in
`release.yml`, so a pin that no longer matches the signing workflow fails CI and
blocks publication instead of breaking every consumer install. If the
repository or workflow file is ever renamed, change that constant,
`DISTRIBUTION_SIGNER_IDENTITY_PREFIX` beside it, and the workflow's
`--certificate-identity` together.

### Check, update, uninstall

These three live in `scripts/` of the repository and take the same `--prefix`
as the installer. (With npm, use `npm outdated`, `npm update`, and
`npm uninstall` instead.)

**`scripts/version-check.sh --archive PATH [--prefix PATH]`** prints the
installed version, the archive's version, and one status:

| Status | Meaning |
| --- | --- |
| `current` | The versions are equal. |
| `update available` | The archive is newer. |
| `installed version is newer than this archive (installing it would downgrade)` | The archive is older. |
| `not installed` | Nothing is installed at the prefix. |
| `versions cannot be compared` | The installed binary did not report a version. |

**`scripts/update.sh --archive PATH [options]`** is the installer with
`--force`, and accepts `--checksum`, `--signature-bundle`, `--prefix`,
`--dry-run`, `--allow-unsigned`, and `--allow-downgrade`. The standalone
installer does the same with `--force`.

- The binary it replaces is kept beside the new one as
  `<prefix>/bin/premier.previous`, and the installer says so. To go back, move
  it over `premier`. Only one previous binary is kept.
- An archive older than the installed version is refused
  (`installed Premier X is newer than the archive (Y)`) unless
  `--allow-downgrade` is given. Versions are compared as semantic versions, so
  a prerelease is older than its release.

**`scripts/uninstall.sh [--prefix PATH] [--dry-run]`** removes
`<prefix>/bin/premier`, `<prefix>/bin/premier.previous`, and
`<prefix>/share/premier/premier-emit.sh`, and nothing else. It then lists what
it leaves alone:

- recorded traces: every `.premier/traces` directory under the projects you
  recorded in, and any path given to `premier record --output`;
- key files created with `premier keygen`;
- copies installed another way (`npm uninstall --global @premierstudio/premier`,
  `cargo uninstall premier-cli`).

The prefix must be an absolute path other than `/`.
