#!/bin/sh
# guest/habitat-sync.sh -- installed on the guest's PATH as `habitat-sync`.
#
# Asks the host side to replay the workspace repo's commits onto a new
# branch in the real project repo (`habitat_workspace::sync::
# merge_workspace_commits_to_host`) right now, instead of waiting for the
# session to end. The host's background sync loop
# (`crates/cli/src/run.rs`'s `run_shell_session`) already polls
# `/workspace` every `SHELL_SYNC_INTERVAL` for ordinary host<->sandbox
# sync -- this just drops a sentinel file into that same bind-mounted
# directory for it to notice on its next tick, since `/workspace` is the
# only channel guest and host actually share. No guest-side git access to
# the real host repo is needed, or possible.
set -eu
touch /workspace/.habitat-sync-request
echo "habitat-sync: requested -- the host will merge any new commits into a new 'habitat/<timestamp>' branch on its next sync tick."
