#!/usr/bin/env bash
# Gate for release.yml. Checks that a commit is fit to release and writes a summary.
#   MODE=release   tag push: the tag must be vX.Y.Z and match package.json, the commit must be on main,
#                  and CI, Docker and Security must have succeeded on that commit's push to main.
#   MODE=dry-run   manual or PR run: the same workflow checks on the commit (any event), but the tag and
#                  on-main checks are reported only, because a dry run has no tag and may be on a branch.
# Env: MODE, SHA, TAG (release only), GH_TOKEN, GH_REPO, WAIT_SECONDS (default 1200)
# Needs: git history with origin/main fetched, gh, jq.
set -euo pipefail

: "${MODE:?}" "${SHA:?}" "${GH_REPO:?}"
wait_seconds=${WAIT_SECONDS:-1200}
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}
fail() { echo "::error::$*"; exit 1; }

version=$(jq -er '.version' package.json)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "package.json version '$version' is not X.Y.Z"

if [ "$MODE" = release ]; then
  [[ "${TAG:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag '${TAG:-}' is not vX.Y.Z"
  [ "$TAG" = "v$version" ] || fail "tag $TAG does not match package.json version $version"
  tag_check="tag $TAG matches package.json $version"
else
  tag_check="dry run: no tag; package.json version is $version (a release would need tag v$version)"
fi

if git merge-base --is-ancestor "$SHA" origin/main; then
  on_main=yes
else
  on_main=no
  [ "$MODE" = release ] && fail "commit $SHA is not on main"
fi

# Wait for each workflow's run on this exact commit to finish, then require success. A tag pushed right
# after a merge would otherwise race the post-merge runs.
check_workflow() {
  local name=$1 deadline=$((SECONDS + wait_seconds)) run status conclusion
  while :; do
    # Latest run of this workflow for the commit; for a release only the push-to-main run counts
    run=$(gh api "repos/${GH_REPO}/actions/runs?head_sha=${SHA}&per_page=100" --jq \
      "[.workflow_runs[] | select(.name == \"${name}\")
        | select(\"${MODE}\" != \"release\" or (.event == \"push\" and .head_branch == \"main\"))]
       | sort_by(.created_at) | last // empty | \"\(.id) \(.status) \(.conclusion) \(.event)\"")
    if [ -n "$run" ]; then
      read -r id status conclusion event <<<"$run"
      if [ "$status" = completed ]; then
        [ "$conclusion" = success ] || fail "$name run $id on $SHA ended '$conclusion'"
        echo "| $name | $event | [run $id](${GITHUB_SERVER_URL:-https://github.com}/${GH_REPO}/actions/runs/$id) | success |" >> "$summary"
        return 0
      fi
      echo "$name run $id is $status; waiting"
    else
      echo "no $name run for $SHA yet; waiting"
    fi
    [ "$SECONDS" -lt "$deadline" ] || fail "timed out after ${wait_seconds}s waiting for $name on $SHA"
    sleep 20
  done
}

{
  if [ "$MODE" = release ]; then
    echo "## Release gate: $TAG"
  else
    echo "## Release gate: DRY RUN"
    echo
    echo "Nothing is pushed, signed or released. Publish and Create GitHub Release run only for a pushed vX.Y.Z tag."
  fi
  echo
  echo "- Commit: \`$SHA\`"
  echo "- Version: $tag_check"
  echo "- On main: $on_main$([ "$MODE" = release ] || echo ' (reported only in a dry run)')"
  echo
  echo "| Workflow | Event | Run | Result |"
  echo "|---|---|---|---|"
} >> "$summary"

for wf in CI Docker Security; do check_workflow "$wf"; done
echo "Release gate passed for $SHA ($MODE)"
