#!/usr/bin/env bash
# Regression tests for scripts/verify-release.sh step 1/1a: the tag is
# resolved as refs/tags/TAG (RV-3) and its commit must be on main (RV-1).
# A stub `gh` answers the run, tag and compare queries and then makes the
# jobs query fail, so each case ends right after the checks under test.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
TAG=v9.9.9
SHA=1111111111111111111111111111111111111111
BRANCH_SHA=2222222222222222222222222222222222222222

cat >"$work/bin/gh" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$work/gh.log"
case "\$*" in
  "run view "*) echo "Release build push $TAG $SHA success" ;;
  *"repos/semihbugrasezer/sigsieve/commits/refs/tags/$TAG "*) echo "$SHA" ;;
  # A branch named like the tag: the ambiguous form would return this.
  *"repos/semihbugrasezer/sigsieve/commits/$TAG "*) echo "$BRANCH_SHA" ;;
  *"repos/semihbugrasezer/sigsieve/compare/$SHA...refs/heads/main "*)
    [ "\${STUB_COMPARE:-}" = error ] && { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    echo "\$STUB_COMPARE" ;;
  # A tag named "main" on the tagged commit: an unqualified "...main" would
  # be answered by it (MR-2), so it always looks identical.
  *"repos/semihbugrasezer/sigsieve/compare/$SHA...main "*) echo identical ;;
  *"/jobs"*) echo "stub: stop after the checks under test" >&2; exit 1 ;;
  *) echo "stub: unexpected gh \$*" >&2; exit 1 ;;
esac
EOF
chmod +x "$work/bin/gh"

passed=0 failed=0
run_case() { # run_case LABEL COMPARE WANT_ON_MAIN(yes|no)
    : >"$work/gh.log"
    out=$(STUB_COMPARE=$2 PATH="$work/bin:$PATH" sh "$repo/scripts/verify-release.sh" 1234 "$TAG" 2>&1) && rc=0 || rc=$?
    local why=""
    [ "$rc" -ne 0 ] || why="exited 0"
    grep -q "^ok    run 1234: Release build, push of $TAG at $SHA, success" <<<"$out" || why="$why; tag not resolved to $SHA"
    grep -q "commits/refs/tags/$TAG " "$work/gh.log" || why="$why; tag not looked up as refs/tags/$TAG"
    if [ "$3" = yes ]; then
        grep -q "^ok    $TAG commit is on main (main is $2)" <<<"$out" || why="$why; missing on-main ok"
        grep -q "stub: stop after the checks under test" <<<"$out" || why="$why; did not continue to the jobs check"
    else
        ! grep -q "commit is on main" <<<"$out" || why="$why; reported on main"
        ! grep -q "/jobs" "$work/gh.log" || why="$why; continued past the ancestry check"
    fi
    if [ -z "$why" ]; then echo "PASS  $1"; passed=$((passed + 1)); else echo "FAIL  $1:${why#;}"; echo "$out" | sed 's/^/      /'; failed=$((failed + 1)); fi
}

run_case "tag commit is main"                    identical yes
run_case "main descends from the tag commit"     ahead     yes
run_case "tag commit diverged from main"         diverged  no
run_case "tag commit is ahead of main (unmerged)" behind   no
run_case "compare query fails"                   error     no
run_case "compare returns nothing"               ""        no

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
