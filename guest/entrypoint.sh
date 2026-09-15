#!/bin/sh
# guest/entrypoint.sh -- this image's only startup job: install this
# session's authorized SSH key (passed in as the HABITAT_AUTHORIZED_KEY
# environment variable -- a public key, not a secret, see
# docs/decisions/0008-guest-exec-channel.md) and start sshd in the
# foreground, since podman exec does not work against the krun runtime
# at all and SSH is this project's real guest exec channel.
set -eu

HOME_DIR="/home/habitat"
SSH_DIR="$HOME_DIR/.ssh"

mkdir -p "$SSH_DIR"
if [ -n "${HABITAT_AUTHORIZED_KEY:-}" ]; then
    printf '%s\n' "$HABITAT_AUTHORIZED_KEY" > "$SSH_DIR/authorized_keys"
else
    # Fail closed, not open: no key means no way in, never "accept
    # anything" -- an empty authorized_keys file, not a missing check.
    : > "$SSH_DIR/authorized_keys"
fi
chmod 700 "$SSH_DIR"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R habitat:habitat "$SSH_DIR"

exec /usr/sbin/sshd -D -e
