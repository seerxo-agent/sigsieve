#!/usr/bin/env bash
# F-46 cross-user test (tests/cross_user.rs). Runs ONLY as root on a
# disposable GitHub-hosted Linux runner: it creates two system users.
#
# Usage: sudo bash scripts/cross-user-test.sh pass|fail TEST_BIN SIGSIEVE_BIN
#
#   pass  every test in the cross_user binary, the ignored cross-user tests
#         included, must have run and passed;
#   fail  (a build with the peer-uid check removed) each cross-user test
#         must fail and the same-user control must still pass.
#
# Anything else (a missing capability, a test that did not run, a
# precondition failure) exits non-zero. Nothing is reported as a skip.
set -euo pipefail

mode=${1:?pass|fail}
test_bin=${2:?test binary}
sigsieve_bin=${3:?sigsieve binary}
script_dir=$(cd "$(dirname "$0")" && pwd)

die() { echo "::error::cross-user test: $*" >&2; exit 1; }

[ "$mode" = pass ] || [ "$mode" = fail ] || die "mode must be pass or fail"
[ "$(uname -s)" = Linux ] || die "Linux only"
[ "$(id -u)" = 0 ] || die "must run as root (it creates users)"
[ "${GITHUB_ACTIONS:-}" = true ] && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] \
  || die "refusing to create users outside a disposable GitHub-hosted runner"
for t in python3 useradd runuser pkill stat; do
  command -v "$t" >/dev/null || die "missing $t"
done

root=$(mktemp -d /srv/sigsieve-xu.XXXXXX)
chmod 0755 "$root"
cleanup() { pkill -u sigsieve-xb 2>/dev/null || true; }
trap cleanup EXIT

# A runs the tests; B runs the foreign agent. Neither has a login shell.
for u in sigsieve-xa sigsieve-xb; do
  id "$u" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
done
uid_a=$(id -u sigsieve-xa); uid_b=$(id -u sigsieve-xb)
[ "$uid_a" != "$uid_b" ] && [ "$uid_a" != 0 ] && [ "$uid_b" != 0 ] || die "bad uids"

# Readable copies: the workspace under the runner's home may not be.
install -m 0755 "$test_bin" "$root/cross_user"
install -m 0755 "$sigsieve_bin" "$root/sigsieve"
install -m 0644 "$script_dir/../tests/support/xu-mock-agent.py" "$root/xu-mock-agent.py"
install -d -m 0700 -o sigsieve-xa "$root/home-a"
install -d -m 0711 -o sigsieve-xb "$root/foreign"

# B binds and listens: B's uid is the socket's peer credential.
runuser -u sigsieve-xb -- python3 "$root/xu-mock-agent.py" \
  "$root/foreign/agent.sock" "$root/foreign/requests.log" &
for _ in $(seq 100); do [ -S "$root/foreign/agent.sock" ] && break; sleep 0.1; done
[ -S "$root/foreign/agent.sock" ] || die "foreign mock agent did not start"
# Give the socket FILE to A: the pathname check now sees A's socket.
chown sigsieve-xa "$root/foreign/agent.sock"
chmod 0600 "$root/foreign/agent.sock"
[ "$(stat -c %u "$root/foreign/agent.sock")" = "$uid_a" ] || die "chown failed"

out="$root/out.txt"
set +e
runuser -u sigsieve-xa -- env -i \
  HOME="$root/home-a" TMPDIR="$root/home-a" PATH=/usr/bin:/bin \
  SIGSIEVE_XU_FOREIGN_SOCK="$root/foreign/agent.sock" \
  SIGSIEVE_XU_FOREIGN_LOG="$root/foreign/requests.log" \
  SIGSIEVE_XU_MOCK="$root/xu-mock-agent.py" \
  SIGSIEVE_XU_BIN="$root/sigsieve" \
  "$root/cross_user" --include-ignored --test-threads=1 >"$out" 2>&1
rc=$?
set -e
cat "$out"
echo "foreign agent received: $(wc -l <"$root/foreign/requests.log") request(s)"

cross=(
  foreign_agent_behind_our_socket_file_is_refused_by_peer_credential
  served_requests_never_reach_a_foreign_agent
  run_exits_2_on_a_foreign_agent
)
grep -qx "test control_same_mock_run_by_us_is_used ... ok" "$out" \
  || die "the same-user control did not pass"
if [ "$mode" = pass ]; then
  [ "$rc" = 0 ] || die "test binary exited $rc"
  for t in "${cross[@]}"; do
    grep -qx "test $t ... ok" "$out" || die "$t did not run and pass"
  done
  grep -q "^test result: ok. 4 passed; 0 failed; 0 ignored" "$out" \
    || die "expected exactly 4 executed, passing tests"
  [ ! -s "$root/foreign/requests.log" ] || die "a request reached the foreign agent"
  echo "PASS (executed): the foreign agent was refused by its peer credential"
else
  [ "$rc" != 0 ] || die "the mutant passed: the tests do not detect a missing peer-uid check"
  for t in "${cross[@]}"; do
    grep -qx "test $t ... FAILED" "$out" || die "$t did not fail on the mutant"
  done
  grep -q "^test result: FAILED. 1 passed; 3 failed; 0 ignored" "$out" \
    || die "unexpected mutant result"
  # Each test must fail on its own check, not on a precondition.
  if grep -q "precondition" "$out"; then die "a precondition failed on the mutant"; fi
  echo "PASS (executed): every cross-user test fails without the peer-uid check"
fi
