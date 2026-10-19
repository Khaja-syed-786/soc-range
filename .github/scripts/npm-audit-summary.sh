#!/usr/bin/env bash
# Turn `npm audit --json` output into a Markdown report on stdout.
# Usage: npm-audit-summary.sh audit.json
# Exits non-zero if the file is not a valid npm audit report (for example an npm error object).
set -euo pipefail

report=${1:?usage: npm-audit-summary.sh audit.json}

if jq -e 'has("error")' "$report" > /dev/null; then
  echo "npm audit did not produce a report:" >&2
  jq '.error' "$report" >&2
  exit 1
fi
jq -e '.metadata.vulnerabilities.total | type == "number"' "$report" > /dev/null

total=$(jq '.metadata.vulnerabilities.total' "$report")

echo "## Full dependency audit (informational, does not block merges)"
echo
echo "Includes dev dependencies. The blocking gate is **Dependency audit (production, blocking)**."
echo
echo "| Severity | Count |"
echo "|---|---|"
jq -r '.metadata.vulnerabilities | to_entries[] | "| \(.key) | \(.value) |"' "$report"
echo
jq -r '.metadata.dependencies
  | "Dependencies audited: \(.prod) production, \(.dev) dev, \(.total) total."' "$report"

if [ "$total" -gt 0 ]; then
  echo
  echo "| Package | Severity | Direct | Advisory | Fix available |"
  echo "|---|---|---|---|---|"
  jq -r '
    def advisories: [.via[] | if type == "object" then .title else "via " + . end] | unique | join("; ");
    def fix: .fixAvailable | if type == "object" then "yes (\(.name) \(.version))" else tostring end;
    .vulnerabilities | to_entries[]
    | "| \(.key) | \(.value.severity) | \(.value.isDirect) | \(.value | advisories) | \(.value | fix) |"
  ' "$report"
fi
