#!/bin/sh
# Pack THIS checkout by delegating to scripts/build.mjs. No registry, no docker, no curl.
set -eu
cd "$(dirname "$0")/.."
umask 022
node scripts/build.mjs
echo "nmzp-core.tgz ready. Copy it to the CT. Do not pull from a registry."
