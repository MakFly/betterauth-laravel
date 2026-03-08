#!/usr/bin/env bash
# Sync core-embedded from betterauth-core repository.
# Usage: ./sync-core.sh [path-to-core-repo]
#
# If no path is provided, clones the archived repo into a temp directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${SCRIPT_DIR}/core-embedded"

if [ -n "${1:-}" ] && [ -d "$1" ]; then
    SOURCE_DIR="$1"
else
    SOURCE_DIR=$(mktemp -d)
    echo "Cloning betterauth-core into ${SOURCE_DIR}..."
    git clone --depth=1 https://github.com/MakFly/betterauth-core.git "${SOURCE_DIR}"
fi

echo "Syncing core-embedded..."

# Sync core
rsync -av --delete \
    "${SOURCE_DIR}/src/core/" \
    "${TARGET_DIR}/core/"

# Sync providers
rsync -av --delete \
    "${SOURCE_DIR}/src/providers/" \
    "${TARGET_DIR}/providers/"

# Contracts are Laravel-specific, keep them as-is
echo "Done. core-embedded is up to date."
