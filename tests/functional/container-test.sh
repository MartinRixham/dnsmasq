#! /bin/sh
#
# Build dnsmasq and run the functional tests inside a container.
#
# Meant to be the entry point of a throwaway container with the source
# tree mounted read-only, e.g.
#
#   docker run --rm -v "$PWD:/src:ro" alpine:latest \
#     sh /src/tests/functional/container-test.sh
#
# Installs the build and test dependencies with whatever package manager
# the image has, copies the source to a scratch directory so that objects
# built for one image never leak into another, then runs the tests as
# root (so the TFTP test runs too). Set CC to pick a compiler.

set -eu

SRC=${SRC:-$(cd "$(dirname "$0")/../.." && pwd)}
CC=${CC:-gcc}

. /etc/os-release
echo "=== $PRETTY_NAME, $(uname -m), CC=$CC"

case "$CC" in
  clang) cc_pkg=clang ;;
  *)     cc_pkg=gcc ;;
esac

if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    $cc_pkg make libc6-dev dnsutils python3 curl shunit2 >/dev/null
elif command -v apk >/dev/null; then
  apk add -q $cc_pkg make musl-dev linux-headers bind-tools python3 curl shunit2
elif command -v dnf >/dev/null; then
  # Some images have curl-minimal, which lacks TFTP, hence the tftp client.
  dnf install -y -q $cc_pkg make glibc-devel bind-utils findutils tftp \
    python3 shunit2
elif command -v zypper >/dev/null; then
  zypper -n -q install $cc_pkg make glibc-devel bind-utils findutils gawk \
    tftp python3 curl shunit2
elif command -v pacman >/dev/null; then
  pacman -Syu --noconfirm --needed -q $cc_pkg make bind python curl shunit2
else
  echo "Don't know how to install packages on $PRETTY_NAME" >&2
  exit 1
fi

BUILD=$(mktemp -d)
cp -R "$SRC/." "$BUILD"
cd "$BUILD"
make clean >/dev/null
echo "=== building with $("$CC" --version | head -n 1), target $("$CC" -dumpmachine)"
make -j"$(nproc)" CC="$CC"

exec make check-functional
