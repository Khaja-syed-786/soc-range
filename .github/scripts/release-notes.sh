#!/usr/bin/env bash
# Release notes and verification commands, built from the README's "Verify a release" block so the README,
# the release notes and the publish job's own check all use exactly the same commands.
#   release-notes.sh commands            print the README block with VERSION and DIGEST filled in
#   release-notes.sh notes CHANGELOG.md  print the full release notes (changelog + digest + verify commands)
# Env: TAG (vX.Y.Z), DIGEST (sha256:...)
set -euo pipefail

: "${TAG:?}" "${DIGEST:?}"
readme=${README:-README.md}

commands() {
  local tmp
  tmp=$(mktemp)
  awk '/<!-- release-verify/{f=1;next} /<!-- \/release-verify -->/{f=0} f && !/^```/' "$readme" > "$tmp"
  if ! { grep -q '^VERSION=' "$tmp" && grep -q '^DIGEST=' "$tmp" && grep -q '^cosign verify ' "$tmp"; }; then
    echo "README.md has no complete release-verify block" >&2
    exit 1
  fi
  sed -e "s|^VERSION=.*|VERSION=${TAG}|" -e "s|^DIGEST=.*|DIGEST=${DIGEST}|" "$tmp"
}

case "${1:-}" in
  commands) commands ;;
  notes)
    changelog=${2:?usage: release-notes.sh notes CHANGELOG.md}
    cat "$changelog"
    echo
    echo "## Container image"
    echo
    echo "\`ghcr.io/khaja-syed-786/soc-range:${TAG#v}\`, digest \`${DIGEST}\`. Pull by digest, not by tag."
    echo
    echo "## Verify this release"
    echo
    echo "Signed with cosign keyless (GitHub OIDC) by this repository's release workflow for ${TAG}."
    echo "The SBOM (SPDX JSON, also attached below) is attested to the same digest."
    echo
    echo '```bash'
    commands
    echo '```'
    ;;
  *) echo "usage: $0 commands | notes CHANGELOG.md" >&2; exit 2 ;;
esac
