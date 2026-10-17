#!/usr/bin/env bash
# Render the winget manifests for one release into <out-dir>.
# Usage: render-manifests.sh <version> <az-firewall-watch.exe> <out-dir>
set -euo pipefail

version="$1"
sha=$(shasum -a 256 "$2" | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
mkdir -p "$3"
for template in "$(dirname "$0")"/*.yaml.in; do
  sed -e "s/@VERSION@/${version}/g" -e "s/@SHA256_WINDOWS@/${sha}/" \
      "$template" > "$3/$(basename "$template" .in)"
done
