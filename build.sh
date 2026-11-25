#!/bin/sh
# Builds mpn-demo for Linux (amd64 by default; GOARCH=arm64 ./build.sh for ARM).
#
# The demo imports mini-panel's internal packages, which Go allows only from inside that module. So the demo's files
# are laid into mini-panel/cmd/mpn-demo with a build overlay, without copying anything into the submodule. The same
# overlay swaps internal/web/serverip.go for one that never reveals the demo host's real address.
set -eu
cd "$(dirname "$0")"
here=$(pwd -W 2>/dev/null || pwd) # Git Bash on Windows needs the Windows form of the path
[ -f mini-panel/go.mod ] || git submodule update --init
cat > overlay.json <<EOF
{"Replace": {
  "$here/mini-panel/cmd/mpn-demo/main.go": "$here/main.go",
  "$here/mini-panel/cmd/mpn-demo/sshfake.go": "$here/sshfake.go",
  "$here/mini-panel/cmd/mpn-demo/sshfake_test.go": "$here/sshfake_test.go",
  "$here/mini-panel/internal/web/serverip.go": "$here/serverip.go"
}}
EOF
cd mini-panel
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH:-amd64}" go build -trimpath -ldflags '-s -w' -overlay ../overlay.json -o ../mpn-demo ./cmd/mpn-demo
echo "built ./mpn-demo ($(git describe --tags --always) of mini-panel)"
