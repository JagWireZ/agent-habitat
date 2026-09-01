FROM mcr.microsoft.com/devcontainers/typescript-node:1-22-bookworm

# Tools opencode's LSP/agent features commonly reach for
RUN apt-get update && apt-get install -y --no-install-recommends \
        ripgrep \
        fd-find \
        curl \
        ca-certificates \
        git \
        zsh \
    && rm -rf /var/lib/apt/lists/*

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
