#!/usr/bin/env bash
# F-46 CI decisions for .github/workflows/cross-user.yml (no privileges).
#
#   f46-ci.sh scope            reads changed paths (one per line) on stdin;
#                              prints "applicable=true|false"
#   f46-ci.sh status SCOPE_RESULT APPLICABLE FORK CROSS_USER_RESULT
#                              prints the F-46 state and exits 0 for
#                              NOT_APPLICABLE or VERIFIED, 1 for NOT_VERIFIED
#
# NOT_APPLICABLE: nothing the cross-user test builds from changed.
# VERIFIED:       the cross-user job ran and passed (both the real two-user
#                 run and the mutant run).
# NOT_VERIFIED:   anything else: it applied but was skipped (fork pull
#                 request), failed, was cancelled, or the scope could not be
#                 decided. Never reported as success.
set -euo pipefail

# Everything the test builds from, and the files that decide the status.
relevant='^(src/|tests/common/|tests/support/|tests/cross_user/|Cargo\.toml$|Cargo\.lock$|rust-toolchain\.toml$|tests/cross_user\.rs$|scripts/cross-user-test\.sh$|scripts/f46-ci\.sh$|scripts/test-f46-ci\.sh$|\.github/workflows/cross-user\.yml$)'

case "${1:-}" in
  scope)
    if grep -qE "$relevant"; then echo applicable=true; else echo applicable=false; fi
    ;;
  status)
    [ "$#" = 5 ] || { echo "usage: $0 status SCOPE_RESULT APPLICABLE FORK CROSS_USER_RESULT" >&2; exit 2; }
    scope=$2 applicable=$3 fork=$4 xu=$5
    if [ "$scope" != success ]; then
      echo "NOT_VERIFIED: scope job result '$scope'"; exit 1
    elif [ "$applicable" = false ]; then
      echo "NOT_APPLICABLE: no change to anything the cross-user test builds from"; exit 0
    elif [ "$applicable" != true ]; then
      echo "NOT_VERIFIED: scope undecided ('$applicable')"; exit 1
    elif [ "$xu" = success ]; then
      echo "VERIFIED: cross-user and mutant runs passed"; exit 0
    elif [ "$fork" = true ]; then
      echo "NOT_VERIFIED: fork pull request; the privileged test is not run for forks"; exit 1
    else
      echo "NOT_VERIFIED: cross-user job result '$xu'"; exit 1
    fi
    ;;
  *) echo "usage: $0 scope | status ..." >&2; exit 2 ;;
esac
