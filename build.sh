#!/bin/bash
# build hp_uploadprogress_guard-<v>.so per PHP minor into dist/, from src/ (the
# module source and per-branch parser copy (rfc1867/rfc1867_copy-<v>.c), on the OLDEST official PHP image that
# ships that minor. The .so must load on every host in the fleet (Debian 10+, Ubuntu 18.04+, EL7+): a binary
# built on a newer glibc references symbol versions older hosts lack (glibc 2.38 turned strtoll into
# __isoc23_strtoll@GLIBC_2.38, which broke the v3.0 rollout: "GLIBC_2.38 not found" on Debian 12).
# Every built file is checked and rejected if it requires anything above GLIBC_2.17 (EL7).
#   ./build.sh 8.5 8.4 8.3 8.2 8.1 8.0 7.4 7.3 7.2 7.1 7.0 5.6
set -u -o pipefail
R="$(cd "$(dirname "$0")" && pwd)"; S="$R/src"
OUT="${HP_UPG_OUT:-$R/dist}"
MAX_GLIBC=2.17
mkdir -p "$OUT"
[ "$#" -gt 0 ] || { echo "Usage: $0 <PHP minor> [...] (development helper only)"; exit 2; }
image() {
  case "$1" in
    5.6|7.0|7.1|7.2|7.3) echo "php:$1-cli-stretch" ;;   # glibc 2.24
    7.4|8.0|8.1)         echo "php:$1-cli-buster" ;;    # glibc 2.28
    8.2|8.3|8.4)         echo "php:$1-cli-bullseye" ;;  # glibc 2.31
    *)                   echo "php:$1-cli-bookworm" ;;  # glibc 2.36 (8.5: no older image exists)
  esac
}
rc=0
for v in "$@"; do
  case "$v" in 5.6|7.0|7.1|7.2|7.3|7.4|8.0|8.1|8.2|8.3|8.4|8.5) ;; *) echo "Unsupported minor: $v"; exit 2;; esac
  d="$S/build-$v"; rm -rf "$d"; mkdir -p "$d"
  cp "$S/config.m4" "$S/hp_uploadprogress_guard.c" "$d/"
  mkdir -p "$d/rfc1867"
  cp "$S/rfc1867/rfc1867_copy-$v.c" "$d/rfc1867/rfc1867_copy-$v.c"
  img=$(image "$v")
  echo "=== $img"
  rm -f "$OUT/hp_uploadprogress_guard-$v.so"
  if ! docker run --rm -v "$d:/src:ro" -v "$OUT:/out" "$img" bash -c '
    set -eu
    cp -r /src /build
    cd /build
    phpize >/dev/null 2>&1
    ./configure --quiet >/dev/null 2>&1
    make -s >/tmp/make.log 2>&1
    grep -E "warning: |error" /tmp/make.log | grep -v shtool | head -20
    v=$(php -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;")
    cp modules/hp_uploadprogress_guard.so /out/hp_uploadprogress_guard-$v.so || exit 1
    echo "built on glibc $(ldd --version | head -1 | sed "s/.*) //") : $(php -n -d extension=/out/hp_uploadprogress_guard-$v.so --ri hp_uploadprogress_guard | grep -E "^version" | tr -s " ")"' 2>&1 | grep -vE "^$|shtool|Pulling|Pull complete|Download complete|Digest:|Status:|Unable to find image"; then
    rm -f "$OUT/hp_uploadprogress_guard-$v.so"
    echo "$v: BUILD FAILED; stale output removed"
    rc=1
    continue
  fi
  rm -rf "$d"
  so="$OUT/hp_uploadprogress_guard-$v.so"
  [ -f "$so" ] || { echo "$v: BUILD FAILED"; rc=1; continue; }
  need=$(objdump -T "$so" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
  if [ "$(printf '%s\n%s\n' "$need" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
    echo "$v: REJECTED, requires GLIBC_$need > $MAX_GLIBC: $(objdump -T "$so" | grep "GLIBC_$need" | awk '{print $NF}' | tr '\n' ' ')"
    rm -f "$so"; rc=1
  else
    echo "$v: ok, max required GLIBC_$need"
  fi
done
(cd "$OUT" && sha256sum hp_uploadprogress_guard-*.so > SHA256SUMS)
exit $rc
