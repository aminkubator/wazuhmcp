#!/usr/bin/env bash
# Self-test for deploy/wazuhmcp-update: signature, anti-rollback and rollback
# checks, with fake binaries and stubbed id/systemctl. No root, no network.
#   scripts/test-update.sh
set -euo pipefail
UPD="$(cd "$(dirname "$0")/.." && pwd)/deploy/wazuhmcp-update"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/stub" "$T/rel"

cat > "$T/stub/id" <<'EOF'
#!/bin/sh
echo 0
EOF
# systemctl: "restart" runs the installed binary's selftest to decide whether it is up.
cat > "$T/stub/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
  show) echo 0 ;;
  restart) if "$WAZUHMCP_BIN" selftest; then echo up > "$STATE"; else echo down > "$STATE"; fi ;;
  is-active) [ "$(cat "$STATE")" = up ] ;;
esac
EOF
chmod +x "$T/stub/"*

ssh-keygen -q -t ed25519 -N '' -f "$T/good" -C test
ssh-keygen -q -t ed25519 -N '' -f "$T/evil" -C test
echo "wazuhmcp-release namespaces=\"wazuhmcp-release\" $(cut -d' ' -f1,2 "$T/good.pub")" > "$T/allowed_signers"

fake() { # fake <file> <version> <selftest exit code>
  printf '#!/bin/sh\n[ "$1" = version ] && echo "wazuhmcp %s" && exit 0\nexit %s\n' "$2" "$3" > "$1"
  chmod +x "$1"
}
release() { # release <version> <selftest rc> <key>
  rm -rf "$T/rel"/* && mkdir "$T/rel/wazuhmcp-$1-linux-amd64"
  fake "$T/rel/wazuhmcp-$1-linux-amd64/wazuhmcp" "$1" "$2"
  tar -czf "$T/rel/wazuhmcp-linux-amd64.tar.gz" -C "$T/rel" "wazuhmcp-$1-linux-amd64"
  ssh-keygen -q -Y sign -f "$T/$3" -n wazuhmcp-release "$T/rel/wazuhmcp-linux-amd64.tar.gz"
}
export PATH="$T/stub:$PATH" STATE="$T/state" WAZUHMCP_BIN="$T/bin" WAZUHMCP_SIGNERS="$T/allowed_signers" WAZUHMCP_HEALTH_WAIT=0
run() { "$UPD" --from-dir "$T/rel" > "$T/out" 2>&1; }
installed() { "$T/bin" version | awk '{print $2}'; }
fails=0
check() { # check <name> <expected exit: ok|fail> <expected installed version>
  local rc=ok; run || rc=fail
  if [ "$rc" = "$2" ] && [ "$(installed)" = "$3" ]; then echo "PASS $1"
  else echo "FAIL $1 (exit $rc, installed $(installed))"; cat "$T/out"; fails=$((fails + 1)); fi
}

fake "$T/bin" 4e5bc1b 0 # current prod build: a commit hash, not semver
release v1.0.0 0 good;  check "upgrade from untagged build" ok v1.0.0
release v1.0.0 0 good;  check "same version is a no-op" ok v1.0.0
release v1.1.0 0 evil;  check "signature by another key refused" fail v1.0.0
release v1.1.0 0 good;  echo tampered >> "$T/rel/wazuhmcp-linux-amd64.tar.gz"
                        check "tampered tarball refused" fail v1.0.0
release v0.9.0 0 good;  check "downgrade refused" fail v1.0.0
release v1.2.0 1 good;  check "failed start rolls back" fail v1.0.0
release v1.2.0 0 good;  check "normal upgrade" ok v1.2.0
exit $fails
