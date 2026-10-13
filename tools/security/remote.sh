#!/bin/sh
# Run `make security` on the build server instead of this machine.
#
# Over SSH, outside GitHub Actions: this repo is public, and the build
# server's runner groups do not allow public repositories (a fork PR could
# otherwise run code on it). Only this checkout's committed history is sent,
# as a git bundle; uncommitted changes are not scanned. The container runs
# there exactly as it does locally: read-only checkout, no network, a
# throwaway HOME. Reports come back to security-out/.
#
#     make security-remote [SECURITY_HOST=mac-mini] [FUZZ_ITERATIONS=300]
set -eu
HOST=${SECURITY_HOST:-mac-mini}
ITER=${FUZZ_ITERATIONS:-300}
# Both values reach ssh and a remote shell: accept only plain shapes. A host
# starting with "-" would be read as an ssh option (e.g. -oProxyCommand=…).
case "$HOST" in
  -*|*[!A-Za-z0-9._@-]*|"") echo "SECURITY_HOST must be a plain host name: $HOST" >&2; exit 2 ;;
esac
case "$ITER" in
  *[!0-9]*|"") echo "FUZZ_ITERATIONS must be a whole number: $ITER" >&2; exit 2 ;;
esac
TOP=$(git rev-parse --show-toplevel)
cd "$TOP"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "note: uncommitted changes are not sent; scanning $(git rev-parse --short HEAD)" >&2
fi

BUNDLE=$(mktemp "${TMPDIR:-/tmp}/actualis-security.XXXXXX")
trap 'rm -f "$BUNDLE"' EXIT
trap 'exit 130' INT TERM HUP          # dash skips the EXIT trap on a signal otherwise
git bundle create "$BUNDLE" HEAD >/dev/null 2>"$BUNDLE.err" || { cat "$BUNDLE.err" >&2; rm -f "$BUNDLE.err"; exit 1; }
rm -f "$BUNDLE.err"

# Under $HOME, not $TMPDIR: colima (the build server's Docker) shares only the
# home directory with containers, so a bind mount from /var/folders is empty.
REMOTE=$(ssh -o BatchMode=yes -- "$HOST" 'mkdir -p "$HOME/.cache" && mktemp -d "$HOME/.cache/actualis-security.XXXXXX"')
# The build server's own colima VM for tools (profile "tools"), never the CI
# runner pool (profile "pool", the default context): a scan must not take
# runner capacity. `colima start` switches the default context to the profile
# it starts, so it is switched straight back to the pool.
REMOTE_ENV='export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH
  export DOCKER_HOST="unix://$HOME/.colima/tools/docker.sock"
  if ! colima status tools >/dev/null 2>&1; then
    colima start tools >/dev/null 2>&1 && docker context use colima-pool >/dev/null 2>&1
  fi'

# Stops a container still running from an interrupted scan before removing
# its directory (containers are named after the remote directory).
cleanup() {
  ssh -o BatchMode=yes -- "$HOST" "$REMOTE_ENV
    docker ps -q --filter label=actualis-security='$REMOTE' | xargs docker rm -f >/dev/null 2>&1
    rm -rf '$REMOTE'" || true
  rm -f "$BUNDLE"
}
trap cleanup EXIT

scp -q -o BatchMode=yes -- "$BUNDLE" "$HOST:$REMOTE/repo.bundle"
rc=0
ssh -o BatchMode=yes -- "$HOST" "$REMOTE_ENV
  set -e
  cd '$REMOTE'
  git -c advice.detachedHead=false clone -q repo.bundle src
  cd src
  make security FUZZ_ITERATIONS=$ITER SECURITY_LABEL='$REMOTE'" || rc=$?

rm -rf security-out
mkdir -p security-out
scp -q -r -o BatchMode=yes -- "$HOST:$REMOTE/src/security-out/." security-out/ || true
echo "reports copied to security-out/ (exit $rc on $HOST)"
exit "$rc"
