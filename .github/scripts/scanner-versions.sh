#!/usr/bin/env bash
# Compare every version- and checksum-pinned tool binary in the workflows with its latest GitHub release,
# and flag drift when the same tool is pinned differently in two workflows (for example Trivy in docker.yml
# and release.yml). Writes a Markdown table to report.md and "behind=0|1" to $GITHUB_OUTPUT (1 when any pin
# is behind or drifting). Needs gh (with GH_TOKEN) and jq. Fails if a pin can't be found or a release read.
set -euo pipefail

# tool | pin prefix (<PREFIX>_VERSION and <PREFIX>_SHA256) | workflow file | GitHub repo
pins=(
  "gitleaks|GITLEAKS|.github/workflows/ci.yml|gitleaks/gitleaks"
  "hadolint|HADOLINT|.github/workflows/docker.yml|hadolint/hadolint"
  "Trivy|TRIVY|.github/workflows/docker.yml|aquasecurity/trivy"
  "Trivy|TRIVY|.github/workflows/release.yml|aquasecurity/trivy"
  "Syft|SYFT|.github/workflows/release.yml|anchore/syft"
  "git-cliff|GIT_CLIFF|.github/workflows/release.yml|orhun/git-cliff"
  "cosign|COSIGN|.github/workflows/release.yml|sigstore/cosign"
)

read_pin() {  # read_pin FILE VAR -> value of "VAR: value" in FILE (exactly one match required)
  local v
  v=$(sed -nE "s/^ *$2: *([0-9A-Za-z.]+) *$/\1/p" "$1")
  if [ "$(printf '%s' "$v" | grep -c .)" -ne 1 ]; then echo "::error::expected exactly one $2 pin in $1" >&2; exit 1; fi
  printf '%s' "$v"
}

behind=0
declare -A latest_of published_of first_version first_sha first_file
{
  echo "| Tool | Workflow | Pinned | Latest release | Published | Status |"
  echo "|---|---|---|---|---|---|"
} > report.md
drift_rows=""

for p in "${pins[@]}"; do
  IFS='|' read -r tool prefix file repo <<<"$p"
  version=$(read_pin "$file" "${prefix}_VERSION")
  sha=$(read_pin "$file" "${prefix}_SHA256")
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::${prefix}_SHA256 in $file is not a SHA-256"; exit 1; }

  if [ -z "${latest_of[$repo]:-}" ]; then
    read -r latest published < <(gh api "repos/${repo}/releases/latest" \
      --jq '(.tag_name | ltrimstr("v")) + " " + .published_at[:10]')
    if [ -z "${latest:-}" ]; then echo "::error::could not read the latest ${tool} release"; exit 1; fi
    latest_of[$repo]=$latest; published_of[$repo]=$published
  fi
  latest=${latest_of[$repo]}; published=${published_of[$repo]}

  if [ "$version" = "$latest" ]; then
    status="up to date"
  elif [ "$(printf '%s\n%s\n' "$version" "$latest" | sort -V | tail -n1)" = "$latest" ]; then
    status="**behind**"; behind=1
  else
    status="pinned is newer than latest release"
  fi
  echo "| ${tool} | \`${file##*/}\` | ${version} | ${latest} | ${published} | ${status} |" >> report.md

  # Drift: the same tool pinned to a different version or checksum in another workflow
  if [ -z "${first_version[$tool]:-}" ]; then
    first_version[$tool]=$version; first_sha[$tool]=$sha; first_file[$tool]=${file##*/}
  elif [ "$version" != "${first_version[$tool]}" ] || [ "$sha" != "${first_sha[$tool]}" ]; then
    behind=1
    drift_rows+="| ${tool} | \`${first_file[$tool]}\` ${first_version[$tool]} (${first_sha[$tool]:0:12}…) vs \`${file##*/}\` ${version} (${sha:0:12}…) |"$'\n'
  fi
done

if [ -n "$drift_rows" ]; then
  { echo; echo "**Drift:** the same tool is pinned differently in two workflows. Pin both to the same version and SHA-256."
    echo; echo "| Tool | Pins |"; echo "|---|---|"; printf '%s' "$drift_rows"; } >> report.md
fi

cat report.md
echo "behind=${behind}" >> "${GITHUB_OUTPUT:-/dev/null}"
