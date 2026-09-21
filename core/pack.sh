#!/bin/sh
# Pack THIS checkout into a file tar. No registry, no docker, no curl.
set -eu
cd "$(dirname "$0")/.."
umask 022
node --experimental-strip-types core/pack.ts
tar -C .pack -czf nmzp-core.tgz nmzp
echo "nmzp-core.tgz ready. Copy it to the CT. Do not pull from a registry."
