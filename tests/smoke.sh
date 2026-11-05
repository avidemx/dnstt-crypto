#!/bin/sh
set -eu
BIN="${1:-./dnstt-crypto}"
[ "$("$BIN" blake2s '')" = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9" ]
[ "$("$BIN" blake2s 616263)" = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982" ]
echo "BLAKE2s smoke tests: PASS"
