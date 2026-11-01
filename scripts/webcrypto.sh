#!/bin/bash
# K5 against a real WebCrypto: `roc tests/webcrypto.roc` prints the public JWK
# text (Jwk.to_public_json) of the RS256, PS256, ES256 and EdDSA test keys,
# and scripts/webcrypto.mjs imports each one with Node webcrypto and verifies
# the signature of its token. Then two mutants of to_public_json (RSA without
# "e", EC with x and y swapped) must make that check fail.
# Usage: scripts/webcrypto.sh [ROC]. Needs node. Exit 0 only when all pass.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
ROC=${1:-roc}
W=$HERE/.work
export XDG_CACHE_HOME=$W/xdg ROC_CACHE_DIR=$W/xdg/roc
SRC=$HERE/package/Jwk.roc
cd "$HERE"
check() { "$ROC" tests/webcrypto.roc 2>&1 | node scripts/webcrypto.mjs; }
echo "== to_public_json in Node webcrypto"
check || { echo "FAILED"; exit 1; }
cp "$SRC" "$W/Jwk.roc.orig"
trap 'cp "$W/Jwk.roc.orig" "$SRC"' EXIT
FAIL=0
mutant() { # name, python replace (old, new)
	python3 -I -c 'import sys; p,o,n=sys.argv[1:4]; s=open(p).read(); assert s.count(o)==1, "mutant text not found"; open(p,"w").write(s.replace(o,n))' "$SRC" "$2" "$3" || { FAIL=1; return; }
	echo "== mutant: $1"
	if check; then echo "SURVIVED: $1"; FAIL=1; else echo "killed: $1"; fi
	cp "$W/Jwk.roc.orig" "$SRC"
}
mutant 'RSA without e' 'Json.to_str({ kty: "RSA", n: B64u.encode(n), e: B64u.encode(e) })' 'Json.to_str({ kty: "RSA", n: B64u.encode(n), f: B64u.encode(e) })'
mutant 'EC with x and y swapped' 'x: B64u.encode(x), y: B64u.encode(y) })' 'x: B64u.encode(y), y: B64u.encode(x) })'
echo
[ $FAIL = 0 ] && echo "WEBCRYPTO PASSED" || { echo "WEBCRYPTO FAILED"; exit 1; }
