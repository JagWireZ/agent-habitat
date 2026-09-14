# Installing the sandbox isolation layer (Kata Containers + Firecracker)

`habitat install` checks for two binaries on `PATH`: `containerd-shim-kata-v2`
and `firecracker`. Together they're what let each Agent Habitat session run
inside its own hardware-isolated Firecracker microVM, instead of a plain
namespace-isolated container.

Upstream Kata Containers' own install docs are written for two audiences
that don't quite match this checklist item: running Kata on a Kubernetes
cluster via its Helm chart, or building it from source. Neither applies
here -- Agent Habitat drives a single host's containerd directly. This page
is the manual-tarball path, narrowed to exactly what's needed to satisfy
`habitat install`'s check, for the two host families v1 supports (Fedora-
based, Ubuntu-based; see `docs/decisions/0003-fedora-and-ubuntu-based-host-in-v1.md`).

If you haven't already, install and start containerd + nerdctl first --
`habitat install`'s checklist covers that step, and it's a plain package
install (`sudo apt install containerd` / `sudo dnf install containerd`).

## 1. Install Kata Containers from the static release tarball

```sh
export VERSION=$(curl -sSL https://api.github.com/repos/kata-containers/kata-containers/releases/latest | jq -r .tag_name)

case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

curl -fsSL -o kata-static.tar.zst \
  "https://github.com/kata-containers/kata-containers/releases/download/${VERSION}/kata-static-${VERSION}-${ARCH}.tar.zst"

# The archive uses an /opt/kata/ prefix.
sudo tar -xvf kata-static.tar.zst -C /
```

This lays down the shim at `/opt/kata/runtime-rs/bin/containerd-shim-kata-v2`,
plus its packaged configuration files under
`/opt/kata/share/defaults/kata-containers/`. It is not yet on `PATH` --
`habitat install` (and containerd itself, later) both need it to be:

```sh
sudo ln -s /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
```

Confirm it resolves:

```sh
containerd-shim-kata-v2 --version
```

## 2. Install the Firecracker binary

Firecracker isn't bundled in the Kata static archive -- it's a separate
download from the Firecracker project itself:

```sh
export FC_VERSION=$(curl -sSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | jq -r .tag_name)
ARCH=$(uname -m) # firecracker's release assets use uname -m directly (x86_64/aarch64)

curl -fsSL -o firecracker \
  "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}"
chmod +x firecracker
sudo mv firecracker /usr/local/bin/firecracker
```

Confirm it resolves:

```sh
firecracker --version
```

## 3. Re-run the checklist

```sh
habitat install
```

Both `containerd-shim-kata-v2` and `firecracker` should now show as found.

## What this doesn't cover yet

Passing `habitat install`'s check confirms the two binaries are present and
runnable -- it does not register a `kata-fc` runtime in containerd's config,
set up the `devmapper` snapshotter Firecracker needs for its block-device
backing store, or wire either into an actual session launch. That end-to-end
wiring is part of the session lifecycle (disk build, VM launch) that's still
being built -- see `AGENTS.md` and `docs/plan.md` for where that stands.
