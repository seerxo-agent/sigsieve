#!/usr/bin/env bash
# Check that a merged commit is exactly what the F-46 cross-user workflow
# tested (docs/FINDINGS.md, F-46 closure criteria).
#
# Usage: scripts/verify-f46-evidence.sh MERGED_COMMIT tested-commits.txt
#
# tested-commits.txt comes from the workflow's f46-cross-user-evidence
# artifact. This checks ONLY that the evidence is bound to the merged
# source; whether the run passed (both cross-user steps green, artifact from
# this repository's run) must be checked separately, see FINDINGS F-46.
#
# Accepted:
# - pull_request evidence: the merged commit has the tested tree (so a base
#   that moved after the run, a squash that dropped changes, or any later
#   edit is caught) and is a merge commit whose second parent is the tested
#   pull request head;
# - workflow_dispatch evidence (a re-run on the default branch): the tested
#   commit is the merged commit itself.
set -euo pipefail

merged=${1:?merged commit}
evidence=${2:?tested-commits.txt}
die() { echo "verify-f46-evidence: FAIL: $*" >&2; exit 1; }
field() { sed -n "s/^$1=//p" "$evidence" | head -1; }

[ -f "$evidence" ] || die "no evidence file $evidence"
event=$(field event); tree=$(field tree)
[ -n "$tree" ] || die "evidence lacks tree"
commit=$(git rev-parse --verify "$merged^{commit}") || die "unknown commit $merged"
case "$event" in
  workflow_dispatch)
    [ "$(field tested)" = "$commit" ] || die "dispatch run tested $(field tested), not $commit"
    [ "$(git rev-parse "$commit^{tree}")" = "$tree" ] || die "tree mismatch for $commit"
    echo "verify-f46-evidence: OK (source binding only): dispatch run tested $commit itself"
    exit 0 ;;
  pull_request) ;;
  *) die "evidence is from an unsupported event '$event'" ;;
esac
head=$(field pr_head)
[ -n "$head" ] || die "evidence lacks pr_head"
actual=$(git rev-parse "$commit^{tree}")
[ "$actual" = "$tree" ] \
  || die "merged tree $actual differs from tested tree $tree: the base moved or the content changed; run the workflow again"
parent2=$(git rev-parse --verify -q "$commit^2") \
  || die "$commit is not a merge commit (squash or rebase): it does not record the tested head"
[ "$parent2" = "$head" ] || die "second parent $parent2 is not the tested head $head"
echo "verify-f46-evidence: OK (source binding only): $commit has the tested tree $tree and merges head $head"
