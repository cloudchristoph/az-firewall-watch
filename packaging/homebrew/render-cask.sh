#!/usr/bin/env bash
# Render the Homebrew cask for one release.
# Usage: render-cask.sh <version> <macos.tar.gz> <linux.tar.gz>  (cask on stdout)
set -euo pipefail

version="$1"
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

sed -e "s/@VERSION@/${version}/" \
    -e "s/@SHA256_MACOS@/$(sha "$2")/" \
    -e "s/@SHA256_LINUX@/$(sha "$3")/" \
    "$(dirname "$0")/az-firewall-watch.rb.in"
