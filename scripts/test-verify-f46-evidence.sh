#!/usr/bin/env bash
# Regression test for scripts/verify-f46-evidence.sh in a throwaway repo.
set -euo pipefail
verify=$(cd "$(dirname "$0")" && pwd)/verify-f46-evidence.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
g() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }
g init -q -b main .
echo base >f; g add f; g commit -qm base
g checkout -qb pr; echo change >>f; g commit -qam change; head=$(git rev-parse HEAD)
g checkout -q main; echo other >g; g add g; g commit -qm unrelated
# What GitHub tests: a temporary merge of the head into the base.
g checkout -q --detach main; g merge -q --no-ff -m tested pr; tested=$(git rev-parse HEAD)
ev=$work/tested-commits.txt
printf 'event=pull_request\ntested=%s\ntree=%s\npr_head=%s\n' \
  "$tested" "$(git rev-parse "$tested^{tree}")" "$head" >"$ev"

pass() { "$verify" "$@" >/dev/null 2>&1 || { echo "FAIL: expected OK: $*"; exit 1; }; }
# fail WHY ARGS...: must be rejected, for the reason WHY.
fail() {
  local why=$1; shift
  if out=$("$verify" "$@" 2>&1); then echo "FAIL: expected rejection: $*"; exit 1; fi
  grep -qF "$why" <<<"$out" || { echo "FAIL: rejected for another reason: $out"; exit 1; }
}

# The real merge commit on main, unchanged base: accepted.
g checkout -q main; g merge -q --no-ff -m "merge pr" pr; pass HEAD "$ev"
# Base moved after the run: different tree, rejected.
g reset -q --hard HEAD~1; echo later >h; g add h; g commit -qm later
g merge -q --no-ff -m "merge pr" pr; fail "differs from tested tree" HEAD "$ev"
# Squash of the same content onto the tested base: no second parent.
g reset -q --hard HEAD~2; g merge -q --squash pr; g commit -qm squash; fail "is not a merge commit" HEAD "$ev"
# Evidence from a non-PR run, or a missing file: rejected.
sed 's/^event=.*/event=workflow_dispatch/' "$ev" >"$work/manual.txt"; fail "not from a pull_request run" HEAD "$work/manual.txt"
fail "no evidence file" HEAD "$work/missing.txt"
# Right tree but another head as second parent: rejected.
g reset -q --hard HEAD~1; g checkout -q -b other pr; g commit -q --allow-empty -m extra
g checkout -q main; g merge -q --no-ff -m "merge other" other; fail "is not the tested head" HEAD "$ev"
echo "test-verify-f46-evidence: ok (6 cases)"
