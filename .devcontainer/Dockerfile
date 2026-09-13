FROM mcr.microsoft.com/devcontainers/typescript-node:1-22-bookworm

# Tools opencode's LSP/agent features commonly reach for, plus the linker
# toolchain rustc itself needs to produce a binary (Rust doesn't bundle
# one) -- `habitat` (crates/*) is a Rust workspace with no external crate
# dependencies yet (see Cargo.lock), so nothing beyond a linker is needed
# for now; add pkg-config/*-dev headers here if/when a crate picks up a
# dependency that needs one.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ripgrep \
        fd-find \
        curl \
        ca-certificates \
        git \
        zsh \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN ln -s $(which fdfind) /usr/local/bin/fd

# Pre-create and own the whole ~/.local tree as the "node" user *before*
# anything mounts a volume under it. Otherwise podman auto-creates the
# mount-point parent directories as root at container start, which then
# blocks opencode from writing sibling dirs like ~/.local/state.
RUN mkdir -p /home/node/.local/share/opencode /home/node/.local/state /home/node/.config/opencode \
    && chown -R node:node /home/node/.local /home/node/.config

# This base image ships a "node" user at uid/gid 1000 (Node's Docker
# convention) rather than the "vscode" user some other devcontainer base
# images use. Using the real username here so $HOME resolves correctly.
USER node

# Official OpenCode install script (installs the `opencode` binary to ~/.opencode/bin
# and adds it to PATH via the user's shell profile)
RUN curl -fsSL https://opencode.ai/install | bash

ENV PATH="/home/node/.opencode/bin:${PATH}"

# Rust toolchain -- this repo's actual product (crates/*, a Cargo
# workspace building the `habitat` binary) is Rust, so building and
# running `cargo test` needs rustc/cargo present. No `rust-toolchain.toml`
# pins a version yet, so this tracks stable. Installed as the "node" user
# (rustup's own convention, same reasoning as Claude Code above: no root
# needed and none of its state should be root-owned) and rustup's default
# profile pulls in rustfmt and clippy alongside rustc/cargo, so no separate
# `rustup component add` step is needed.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default

ENV PATH="/home/node/.cargo/bin:${PATH}"

# Claude Code — installed as a global npm package as the "node" user.
# Anthropic's docs explicitly warn against `sudo npm install -g` for this
# package (permission issues + security risk), so this must run after
# `USER node`, not as root. Requires Node.js 22+, which this base image
# already provides.
RUN npm install -g @anthropic-ai/claude-code
