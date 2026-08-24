#!/bin/sh
# natprobe installer.
#
#   curl -fsSL https://raw.githubusercontent.com/samishal1998/natprobe/main/install.sh | sh
#
# Options (environment variables):
#
#   NATPROBE_VERSION=v0.1.0   install a specific version (default: latest)
#   NATPROBE_INSTALL_DIR=...  where to put the binary (default: see below)
#
# POSIX sh on purpose, not bash: this has to run under dash on Debian/Ubuntu
# and under BusyBox ash in a container, where /bin/sh is not bash.
set -eu

REPO="samishal1998/natprobe"
BINARY="natprobe"

# Everything writes through these so a failure is visible on a terminal even
# when stdout is being piped somewhere.
info() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Platform detection
#
# The names have to match the archives .goreleaser.yaml produces:
#   natprobe_<version>_<os>_<arch>.tar.gz
# ---------------------------------------------------------------------------
detect_os() {
  os="$(uname -s)"
  case "${os}" in
    Linux) printf 'linux' ;;
    Darwin) printf 'darwin' ;;
    # Windows users have a .zip release, but this script cannot usefully
    # install it: say so rather than fail obscurely three steps later.
    MINGW* | MSYS* | CYGWIN*)
      die "Windows is not supported by this script. Download the .zip from https://github.com/${REPO}/releases and add it to your PATH." ;;
    *) die "unsupported operating system: ${os}" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "${arch}" in
    x86_64 | amd64) printf 'amd64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *) die "unsupported architecture: ${arch}. Prebuilt binaries cover amd64 and arm64; build from source with: go install github.com/${REPO}/cmd/${BINARY}@latest" ;;
  esac
}

# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# fetch URL DEST. curl and wget cover every system this is likely to meet.
fetch() {
  url="$1"; dest="$2"
  if have curl; then
    # --fail turns an HTTP error into a non-zero exit instead of a file
    # containing GitHub's 404 page.
    curl -fsSL --retry 3 --retry-delay 1 -o "${dest}" "${url}"
  elif have wget; then
    wget -q -t 3 -O "${dest}" "${url}"
  else
    die "need curl or wget to download"
  fi
}

# fetch_stdout URL. Same tools, output to stdout.
fetch_stdout() {
  url="$1"
  if have curl; then
    curl -fsSL --retry 3 --retry-delay 1 "${url}"
  elif have wget; then
    wget -q -t 3 -O- "${url}"
  else
    die "need curl or wget to download"
  fi
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
resolve_version() {
  if [ -n "${NATPROBE_VERSION:-}" ]; then
    printf '%s' "${NATPROBE_VERSION}"
    return
  fi
  # Read the tag from the releases API rather than following /latest, so the
  # exact version is known before anything is downloaded and can be reported
  # in errors and in the checksum lookup.
  tag="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)"
  [ -n "${tag}" ] || die "could not determine the latest version. Set NATPROBE_VERSION=v0.1.0 to pin one, or check https://github.com/${REPO}/releases"
  printf '%s' "${tag}"
}

# ---------------------------------------------------------------------------
# Install location
#
# Preference order: an explicit override, then a directory already on PATH
# that is writable without sudo, then ~/.local/bin. Never sudo silently.
# ---------------------------------------------------------------------------
resolve_install_dir() {
  if [ -n "${NATPROBE_INSTALL_DIR:-}" ]; then
    printf '%s' "${NATPROBE_INSTALL_DIR}"
    return
  fi
  for candidate in "${HOME}/.local/bin" /usr/local/bin; do
    if [ -d "${candidate}" ] && [ -w "${candidate}" ]; then
      printf '%s' "${candidate}"
      return
    fi
  done
  # Nothing writable exists yet; ~/.local/bin is the one we can create
  # without asking for root.
  printf '%s' "${HOME}/.local/bin"
}

on_path() {
  case ":${PATH}:" in
    *":$1:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  os="$(detect_os)"
  arch="$(detect_arch)"
  version="$(resolve_version)"
  install_dir="$(resolve_install_dir)"

  # goreleaser strips the leading v from the archive name but keeps it on the
  # tag, so both spellings are needed.
  bare="${version#v}"
  archive="${BINARY}_${bare}_${os}_${arch}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${version}"

  info "installing ${BINARY} ${version} (${os}/${arch}) into ${install_dir}"

  # Everything happens in a temp dir that is always cleaned up, so a failed
  # download never leaves a half-written binary on PATH.
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT INT TERM

  fetch "${base_url}/${archive}" "${tmp}/${archive}" \
    || die "could not download ${archive}. Check that ${version} exists at https://github.com/${REPO}/releases"

  # Verify the download before trusting it. checksums.txt is published
  # alongside the archives and is `sha256sum -c` compatible.
  if fetch "${base_url}/checksums.txt" "${tmp}/checksums.txt" 2>/dev/null; then
    if have sha256sum; then
      ( cd "${tmp}" && grep " ${archive}\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
        || die "checksum mismatch for ${archive}. The download may be corrupt or tampered with; nothing was installed."
      info "checksum ok"
    elif have shasum; then
      ( cd "${tmp}" && grep " ${archive}\$" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1 ) \
        || die "checksum mismatch for ${archive}. The download may be corrupt or tampered with; nothing was installed."
      info "checksum ok"
    else
      # Worth saying out loud rather than staying silent: the user should
      # know the integrity check did not happen.
      info "warning: no sha256sum or shasum available, skipping checksum verification"
    fi
  else
    info "warning: checksums.txt not published for ${version}, skipping checksum verification"
  fi

  tar -xzf "${tmp}/${archive}" -C "${tmp}" "${BINARY}" \
    || die "could not extract ${BINARY} from ${archive}"
  chmod +x "${tmp}/${BINARY}"

  mkdir -p "${install_dir}" 2>/dev/null \
    || die "could not create ${install_dir}. Set NATPROBE_INSTALL_DIR to somewhere writable."

  # `mv` across filesystems can fail, and it cannot replace a running binary
  # on some systems; install into place via a temp name in the SAME directory
  # so the swap is atomic and never leaves a truncated file on PATH.
  if ! mv "${tmp}/${BINARY}" "${install_dir}/${BINARY}.new" 2>/dev/null; then
    cat "${tmp}/${BINARY}" > "${install_dir}/${BINARY}.new" 2>/dev/null \
      || die "could not write to ${install_dir}. Set NATPROBE_INSTALL_DIR to somewhere writable, or re-run with sudo."
    chmod +x "${install_dir}/${BINARY}.new"
  fi
  mv "${install_dir}/${BINARY}.new" "${install_dir}/${BINARY}" \
    || die "could not install into ${install_dir}"

  info "installed ${install_dir}/${BINARY}"

  # Report the version from the binary itself rather than the tag we asked
  # for: it proves the thing on disk actually runs on this machine.
  if "${install_dir}/${BINARY}" --version >/dev/null 2>&1; then
    info "$("${install_dir}/${BINARY}" --version)"
  fi

  if ! on_path "${install_dir}"; then
    info ""
    info "${install_dir} is not on your PATH. Add it with:"
    info "    export PATH=\"${install_dir}:\$PATH\""
  fi

  info ""
  info "try:  ${BINARY} check"
}

main "$@"
