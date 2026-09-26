#!/bin/sh
# Pack THIS checkout by delegating to core/pack.ts. No registry, no docker, no curl.
set -eu
cd "$(dirname "$0")/.."
umask 022
node --experimental-strip-types core/pack.ts
echo "nmzp-core.tgz ready. Copy it to the CT. Do not pull from a registry."
