#!/bin/bash
# Record every core architecture's cdhash in the helper, BEFORE signing the helper.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: $0 <helper> <core>" >&2
  exit 2
fi
helper=$1
core=$2
hashes=()
for arch in $(lipo -archs "$core"); do
  signature=$(codesign -d -a "$arch" -vvv "$core" 2>&1)
  hash=$(printf '%s\n' "$signature" | sed -n 's/^CDHash=//p' | tr '[:upper:]' '[:lower:]')
  if [[ ! $hash =~ ^[0-9a-f]{40}$ ]]; then
    echo "missing or invalid cdhash for core architecture $arch" >&2
    exit 1
  fi
  hashes+=("$hash")
done
if [[ ${#hashes[@]} == 0 ]]; then
  echo "no core architectures found" >&2
  exit 1
fi
hash_list=$(IFS=,; echo "${hashes[*]}")
SLUICE_CORE_HASHES=$hash_list perl -0777 -i -pe '
  BEGIN {
    $prefix = "SLUICE-CORE-CDHASH:";
    $payload = $ENV{SLUICE_CORE_HASHES};
    $size = 200 - length($prefix);
    die "core cdhashes exceed helper slot capacity\n" if length($payload) >= $size;
  }
  $count = s/\Q$prefix\E.{$size}/
    $prefix . $payload . ("\0" x ($size - length($payload)))
  /ges;
  die "helper cdhash slot not found\n" unless $count;
' "$helper"
