#!/usr/bin/env bash
# Check that a merged commit is exactly what the F-46 cross-user workflow
# tested (docs/FINDINGS.md, F-46 closure criteria).
#
# Usage: scripts/verify-f46-evidence.sh MERGED_COMMIT tested-commits.txt
#
# tested-commits.txt comes from the workflow's f46-cross-user-evidence
# artifact. The merged commit must have the tested tree (so a base that
# moved after the run, a squash that dropped changes, or any later edit is
# caught) and must be a merge commit whose second parent is the tested pull
# request head. Exit 0 only if both hold.
set -euo pipefail

merged=${1:?merged commit}
evidence=${2:?tested-commits.txt}
die() { echo "verify-f46-evidence: FAIL: $*" >&2; exit 1; }
field() { sed -n "s/^$1=//p" "$evidence" | head -1; }

[ -f "$evidence" ] || die "no evidence file $evidence"
[ "$(field event)" = pull_request ] || die "evidence is not from a pull_request run"
tree=$(field tree); head=$(field pr_head)
[ -n "$tree" ] && [ -n "$head" ] || die "evidence lacks tree or pr_head"

commit=$(git rev-parse --verify "$merged^{commit}") || die "unknown commit $merged"
actual=$(git rev-parse "$commit^{tree}")
[ "$actual" = "$tree" ] \
  || die "merged tree $actual differs from tested tree $tree: the base moved or the content changed; run the workflow again"
parent2=$(git rev-parse --verify -q "$commit^2") \
  || die "$commit is not a merge commit (squash or rebase): it does not record the tested head"
[ "$parent2" = "$head" ] || die "second parent $parent2 is not the tested head $head"
echo "verify-f46-evidence: OK: $commit has the tested tree $tree and merges head $head"
