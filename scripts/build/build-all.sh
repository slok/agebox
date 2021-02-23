#!/usr/bin/env bash

set -o errexit
set -o nounset

ostypes=("Linux" "Darwin" "Windows" "ARM64" "ARM")
for ostype in "${ostypes[@]}"
do
	ostype="${ostype}" ./scripts/build/build.sh
done