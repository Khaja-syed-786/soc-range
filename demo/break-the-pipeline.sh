#!/usr/bin/env bash
# Create a throwaway local branch that breaks exactly one CI gate, to show the pipeline catching it.
# It only creates the branch and commit locally; pushing and opening a draft PR are separate steps
# (see demo/break-the-pipeline.md). Never merge these branches.
#
# Usage: demo/break-the-pipeline.sh GATE [BASE]
#   GATE: lint | test | vuln-dep | dockerfile | coverage | secret
#   BASE: commit to branch from (default origin/main)
set -euo pipefail

gate=${1:?usage: break-the-pipeline.sh lint|test|vuln-dep|dockerfile|coverage|secret [BASE]}
base=${2:-origin/main}
branch="demo/break-$gate"

cd "$(git rev-parse --show-toplevel)"
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean; commit or stash first" >&2; exit 1; }
git fetch -q origin
git switch -q -c "$branch" "$base"
# If anything below fails, go back and drop the half-made branch
trap 'git reset -q --hard && git switch -q - && git branch -q -D "$branch"; echo "failed to prepare $branch" >&2' ERR

case "$gate" in
  lint)        # ESLint no-unused-vars
    printf '\nconst demoUnusedVariable = 1; // DEMO: unused on purpose\n' >> src/config.js
    msg="ESLint fails on an unused variable" ;;
  test)        # a test that can never pass
    printf "\ntest('DEMO: deliberately failing test', () => {\n  assert.strictEqual(1, 2);\n});\n" >> test/config.test.js
    msg="a unit test fails" ;;
  vuln-dep)    # lodash 4.17.20 has a high-severity advisory (command injection, fixed in 4.17.21)
    npm install --save-exact --no-fund --no-audit lodash@4.17.20 > /dev/null
    msg="a runtime dependency with a known high-severity advisory" ;;
  dockerfile)  # hadolint DL3003: use WORKDIR instead of cd
    sed -i 's|^USER 1000:1000$|RUN cd /app \&\& ls\nUSER 1000:1000|' Dockerfile
    grep -q '^RUN cd /app' Dockerfile
    msg="hadolint fails on a Dockerfile anti-pattern" ;;
  coverage)    # ~600 lines that are loaded by the tests but never run
    {
      echo "// DEMO: loaded by the tests through src/config.js but never called, to drop line coverage"
      echo "module.exports = function demoNeverCalled(x) {"
      echo "  let total = 0;"
      for i in $(seq 1 600); do echo "  total += x * $i;"; done
      echo "  return total;"
      echo "};"
    } > src/demo-uncovered.js
    printf "\nrequire('./demo-uncovered'); // DEMO\n" >> src/config.js
    msg="line coverage drops below the 90% gate" ;;
  secret)      # a fake, randomly generated AWS-style key pair; assembled here so this script never contains one
    # Random characters from openssl; cut reads all of its input, so nothing is killed by SIGPIPE
    prefix="AK""IA"
    key_id="$prefix$(openssl rand -base64 96 | LC_ALL=C tr -dc 'A-Z2-7' | cut -c1-16)"
    secret=$(openssl rand -base64 96 | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-40)
    [ ${#key_id} -eq 20 ] && [ ${#secret} -eq 40 ] || { echo "random generation came up short" >&2; exit 1; }
    mkdir -p demo
    printf '# DEMO: fake credentials, never valid\naws_access_key_id = %s\naws_secret_access_key = %s\n' \
      "$key_id" "$secret" > demo/leaked-credentials.ini
    msg="a committed (fake) cloud credential" ;;
  *) echo "unknown gate: $gate" >&2; git switch -q - && git branch -q -D "$branch"; exit 2 ;;
esac

git add -A
git commit -q -m "DEMO, do not merge: break $gate ($msg)"
echo "created $branch at $(git rev-parse --short HEAD): $msg"
git switch -q -
