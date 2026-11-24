#!/bin/sh
set -eu
mkdir -p vendor
archive=vendor/bearssl-0.6.tar.gz
if [ ! -f "$archive" ]; then
  curl --fail --location --retry 3 --proto '=https' https://bearssl.org/bearssl-0.6.tar.gz -o "$archive.tmp"
  mv "$archive.tmp" "$archive"
fi
printf '%s  %s\n' '6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14' "$archive" | sha256sum -c -
# Extract fresh so an altered cached source tree cannot bypass archive validation.
rm -rf vendor/bearssl-0.6
tar -xzf "$archive" -C vendor
