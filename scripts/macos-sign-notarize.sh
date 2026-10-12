#!/usr/bin/env bash
# Sign a macOS executable with a Developer ID certificate (hardened runtime,
# secure timestamp) and have Apple notarize it. Used by the release workflow
# before packaging, and only when the signing secrets are configured; without
# them release binaries stay ad hoc signed and are not notarized.
#
# This script has never run against Apple's services from this repository: it
# needs an Apple Developer ID that the project does not have yet. Treat the
# first run as a rehearsal (docs/releasing.md, "macOS signing").
#
# Usage: ./scripts/macos-sign-notarize.sh PATH_TO_EXECUTABLE
# Environment:
#   APPLE_CERTIFICATE_P12_BASE64   Developer ID Application certificate and key (.p12), base64
#   APPLE_CERTIFICATE_PASSWORD     password of that .p12
#   APPLE_SIGNING_IDENTITY         e.g. "Developer ID Application: Example Inc (TEAMID1234)"
#   APPLE_API_KEY_P8_BASE64        App Store Connect API key (.p8), base64
#   APPLE_API_KEY_ID               its key id
#   APPLE_API_ISSUER_ID            its issuer id
set -euo pipefail

BINARY="${1:?usage: macos-sign-notarize.sh PATH_TO_EXECUTABLE}"
[[ "$(uname -s)" == Darwin ]] || { echo "macOS signing runs on macOS only" >&2; exit 1; }
[[ -f "$BINARY" ]] || { echo "not a file: $BINARY" >&2; exit 1; }
for name in APPLE_CERTIFICATE_P12_BASE64 APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY \
  APPLE_API_KEY_P8_BASE64 APPLE_API_KEY_ID APPLE_API_ISSUER_ID; do
  [[ -n "${!name:-}" ]] || { echo "$name is not set" >&2; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/premier-sign.XXXXXX")"
KEYCHAIN="$WORK/signing.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)"
cleanup() {
  security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# The certificate lives in a keychain of its own that is deleted on exit.
printf '%s' "$APPLE_CERTIFICATE_P12_BASE64" | base64 --decode >"$WORK/certificate.p12"
printf '%s' "$APPLE_API_KEY_P8_BASE64" | base64 --decode >"$WORK/api-key.p8"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 3600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$WORK/certificate.p12" -k "$KEYCHAIN" -P "$APPLE_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null

codesign --force --options runtime --timestamp \
  --keychain "$KEYCHAIN" --sign "$APPLE_SIGNING_IDENTITY" "$BINARY"
codesign --verify --strict --verbose=2 "$BINARY"

# notarytool takes an archive, not a bare executable. A notarized executable
# cannot have its ticket stapled; Gatekeeper looks the ticket up online.
ditto -c -k --keepParent "$BINARY" "$WORK/premier.zip"
xcrun notarytool submit "$WORK/premier.zip" \
  --key "$WORK/api-key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" \
  --wait --timeout 30m | tee "$WORK/notary.log"
grep -q 'status: Accepted' "$WORK/notary.log" || { echo "notarization was not accepted" >&2; exit 1; }
echo "signed and notarized $BINARY as $APPLE_SIGNING_IDENTITY"
