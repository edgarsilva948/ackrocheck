#!/bin/sh
# AckroCheck installer.
#
#   curl -fsSL https://raw.githubusercontent.com/edgarsilva948/ackrocheck/main/install.sh | sh
#
# Environment overrides:
#   ACKROCHECK_VERSION   release tag to install (default: latest)
#   ACKROCHECK_BIN_DIR   install directory     (default: /usr/local/bin, or
#                        $HOME/.local/bin when /usr/local/bin is not writable)
#
# Downloads the release archive for the host OS/arch from GitHub, verifies it
# against the published checksums.txt, and installs the ackrocheck binary.
# POSIX sh; needs curl (or wget), tar, and sha256sum (or shasum).
set -eu

REPO="edgarsilva948/ackrocheck"
BIN="ackrocheck"

err() { echo "install.sh: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- pick a downloader -----------------------------------------------------
if have curl; then
  dl() { curl -fsSL "$1" -o "$2"; }
  dl_stdout() { curl -fsSL "$1"; }
elif have wget; then
  dl() { wget -qO "$2" "$1"; }
  dl_stdout() { wget -qO- "$1"; }
else
  err "need curl or wget"
fi

# --- detect platform -------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux) os=linux ;;
  darwin) os=darwin ;;
  *) err "unsupported OS '$os' (Windows: download the .zip from the releases page)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) err "unsupported architecture '$arch'" ;;
esac

# --- resolve version -------------------------------------------------------
version="${ACKROCHECK_VERSION:-}"
if [ -z "$version" ]; then
  # Follow the /releases/latest redirect to read the tag without the API.
  version=$(dl_stdout "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)
  [ -n "$version" ] || err "could not determine latest version; set ACKROCHECK_VERSION"
fi

archive="${BIN}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

# --- download + verify -----------------------------------------------------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $BIN $version ($os/$arch)..."
dl "$base/$archive" "$tmp/$archive" || err "download failed: $base/$archive"

if dl "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
  expected=$(grep " $archive\$" "$tmp/checksums.txt" | cut -d' ' -f1)
  [ -n "$expected" ] || err "no checksum found for $archive"
  if have sha256sum; then
    actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
  elif have shasum; then
    actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
  else
    err "need sha256sum or shasum to verify the download"
  fi
  [ "$expected" = "$actual" ] || err "checksum mismatch (expected $expected, got $actual)"
  echo "Checksum verified."
else
  err "could not download checksums.txt; refusing to install unverified binary"
fi

tar -xzf "$tmp/$archive" -C "$tmp" "$BIN" || err "failed to extract $BIN"

# --- choose install dir ----------------------------------------------------
bindir="${ACKROCHECK_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    bindir=/usr/local/bin
  else
    bindir="$HOME/.local/bin"
  fi
fi
mkdir -p "$bindir"

install -m 0755 "$tmp/$BIN" "$bindir/$BIN" 2>/dev/null \
  || { cp "$tmp/$BIN" "$bindir/$BIN" && chmod 0755 "$bindir/$BIN"; } \
  || err "failed to install to $bindir (try ACKROCHECK_BIN_DIR=\$HOME/.local/bin)"

echo "Installed $BIN to $bindir/$BIN"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) echo "Note: $bindir is not on your PATH; add it to use '$BIN' directly." ;;
esac
"$bindir/$BIN" version || true
