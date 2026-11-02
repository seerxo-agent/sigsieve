#!/usr/bin/env bash
# Regression test for scripts/f46-ci.sh: scope classification and the
# NOT_APPLICABLE / VERIFIED / NOT_VERIFIED decision.
set -euo pipefail
ci=$(cd "$(dirname "$0")" && pwd)/f46-ci.sh
n=0
scope() { # expected, then paths
  local want=$1; shift
  got=$(printf '%s\n' "$@" | bash "$ci" scope)
  [ "$got" = "applicable=$want" ] || { echo "FAIL: scope $* -> $got, want $want"; exit 1; }
  n=$((n+1))
}
status() { # expected-exit expected-prefix args...
  local code=$1 prefix=$2; shift 2
  set +e; out=$(bash "$ci" status "$@"); rc=$?; set -e
  [ "$rc" = "$code" ] && [ "${out%%:*}" = "$prefix" ] \
    || { echo "FAIL: status $* -> rc=$rc '$out', want $code $prefix"; exit 1; }
  n=$((n+1))
}
scope true src/upstream.rs
scope true docs/USAGE.md src/proxy.rs
scope true Cargo.lock
scope true rust-toolchain.toml
scope true tests/common/mod.rs
scope true tests/support/xu-mock-agent.py
scope true .github/workflows/cross-user.yml
scope true scripts/cross-user-test.sh
scope true scripts/f46-ci.sh
scope true scripts/test-f46-ci.sh
scope true tests/cross_user/helpers.rs
scope false docs/FINDINGS.md CHANGELOG.md
scope false .github/workflows/ci.yml scripts/verify-release.sh
scope false tests/e2e_sshd.rs
scope false ""
scope false srcx/a.rs
scope false docs/src/a.md
status 0 NOT_APPLICABLE success false false skipped
status 0 VERIFIED      success true  false success
status 1 NOT_VERIFIED  success true  true  skipped
status 1 NOT_VERIFIED  success true  false failure
status 1 NOT_VERIFIED  success true  false cancelled
status 1 NOT_VERIFIED  success true  false skipped
status 1 NOT_VERIFIED  failure ""    false skipped
status 1 NOT_VERIFIED  success ""    false skipped
status 1 NOT_VERIFIED  cancelled true false success
# A cross-user success never makes an inapplicable change "verified".
status 0 NOT_APPLICABLE success false false success
echo "test-f46-ci: ok ($n cases)"
