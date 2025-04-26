#!/usr/bin/env bash

set -uo pipefail

for d in ./test/*/; do
	(
		cd "$d" &&
		if ! cmp -s <(../../merge.py overlay.yml) result.yml; then
			echo "Test failed: $d"
		fi
	)
done
