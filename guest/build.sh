#!/usr/bin/env bash
# guest/build.sh -- builds guest/Containerfile and tags it locally as
# `localhost/habitat-guest:alpine`, the exact name `crates/vm::launcher`
# and every `tests/manual/` runbook expect to already exist before a
# launch is attempted. Nothing in `habitat run`'s own path builds this
# automatically yet (Phase 7 wires the full lifecycle, not this) -- this
# script is the only thing that produces it today.
#
# Usage: guest/build.sh [alpine-version]
#   guest/build.sh          # builds ARG ALPINE_VERSION's default (3.20)
#   guest/build.sh 3.21     # builds a specific pinned Alpine version instead

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="localhost/habitat-guest:alpine"
ALPINE_VERSION="${1:-}"

if ! command -v podman >/dev/null 2>&1; then
    echo "podman not found on PATH -- this script needs the same podman the launcher/runbooks use." >&2
    exit 1
fi

BUILD_ARGS=(-t "$IMAGE_TAG" -f "$REPO_ROOT/guest/Containerfile" "$REPO_ROOT/guest")
if [[ -n "$ALPINE_VERSION" ]]; then
    BUILD_ARGS=(--build-arg "ALPINE_VERSION=$ALPINE_VERSION" "${BUILD_ARGS[@]}")
fi

echo "Building $IMAGE_TAG from guest/Containerfile ..."
podman build "${BUILD_ARGS[@]}"
echo "Built and tagged $IMAGE_TAG."
