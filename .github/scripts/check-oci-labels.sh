#!/usr/bin/env bash
# Check the OCI labels on a built image. Used by docker.yml and release.yml.
# Usage: check-oci-labels.sh IMAGE EXPECTED_REVISION
set -euo pipefail

image=${1:?usage: check-oci-labels.sh IMAGE EXPECTED_REVISION}
revision=${2:?usage: check-oci-labels.sh IMAGE EXPECTED_REVISION}

labels=$(docker inspect --format '{{json .Config.Labels}}' "$image")
echo "$labels" | jq .
jq -e --arg rev "$revision" '
  .["org.opencontainers.image.source"] == "https://github.com/Khaja-syed-786/soc-range"
  and .["org.opencontainers.image.licenses"] == "MIT"
  and (.["org.opencontainers.image.description"] | type == "string" and length > 0)
  and .["org.opencontainers.image.revision"] == $rev' <<<"$labels" > /dev/null
echo "OCI labels OK (revision $revision)"
