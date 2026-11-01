//! F-46: an upstream agent run by another user is refused even when the
//! socket file looks like ours.
//!
//! The setup needs root and two users, so the cross-user tests are
//! `#[ignore]`d: an ordinary `cargo test` reports them as *ignored*, never
//! as passed. `scripts/cross-user-test.sh` prepares a disposable Linux
//! runner and runs them with `--include-ignored`; run there, a missing
//! precondition fails the test rather than skipping it.
//!
//! The foreign agent is `tests/support/xu-mock-agent.py`, started by user B. Root
//! then gives its socket file to user A, who runs this test. The pathname
//! check (`metadata`: a socket owned by the current uid) therefore passes,
//! and only the peer credential of the connected descriptor
//! (`getpeereid` / `SO_PEERCRED`, taken when B called `listen`) can refuse
//! it. The mock logs every request it receives, so "refused" also means
//! "nothing reached it".

mod common;

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use sigsieve::socket;
use sigsieve::upstream::{Upstream, UpstreamError};

fn env_path(key: &str) -> PathBuf {
    std::env::var_os(key).map(PathBuf::from).unwrap_or_else(|| {
        panic!(
            "{key} is not set: this test needs the two-user setup of \
             scripts/cross-user-test.sh"
        )
    })
}

fn mock_script() -> PathBuf {
    std::env::var_os("SIGSIEVE_XU_MOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/xu-mock-agent.py")
        })
}

fn sigsieve_bin() -> PathBuf {
    std::env::var_os("SIGSIEVE_XU_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_sigsieve")))
}

fn requests(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_else(|e| panic!("cannot read the mock agent's log {}: {e}", log.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The foreign agent, after checking every precondition: its socket file
/// passes the pathname check and its process does not belong to us. The
/// tests share it (run with `--test-threads=1`), so each one compares the
/// log with what it held at the start.
struct Foreign {
    sock: PathBuf,
    log: PathBuf,
    peer: u32,
    seen: usize,
}

impl Foreign {
    fn assert_untouched(&self) {
        let got = requests(&self.log);
        assert_eq!(
            &got[self.seen.min(got.len())..],
            &[] as &[String],
            "a request reached the foreign agent"
        );
    }
}

fn foreign() -> Foreign {
    let sock = env_path("SIGSIEVE_XU_FOREIGN_SOCK");
    let log = env_path("SIGSIEVE_XU_FOREIGN_LOG");
    let me = socket::current_uid();
    assert_ne!(me, 0, "precondition: the test must not run as root");
    let meta = fs::metadata(&sock).expect("precondition: foreign socket exists");
    assert!(meta.file_type().is_socket(), "precondition: a Unix socket");
    assert_eq!(
        meta.uid(),
        me,
        "precondition: the socket file is owned by the test user, so the \
         pathname check alone would accept it"
    );
    // Reading the peer uid sends nothing to the agent.
    let peer = socket::peer_uid(&UnixStream::connect(&sock).expect("precondition: connectable"))
        .expect("precondition: peer credential readable");
    assert_ne!(peer, me, "precondition: the agent runs as another user");
    assert_ne!(peer, 0, "precondition: the other user is not root");
    let seen = requests(&log).len();
    Foreign {
        sock,
        log,
        peer,
        seen,
    }
}

#[test]
#[ignore = "needs two users and root setup: scripts/cross-user-test.sh"]
fn foreign_agent_behind_our_socket_file_is_refused_by_peer_credential() {
    let f = foreign();
    match Upstream::new(&f.sock, Duration::from_secs(5)).identities() {
        Err(UpstreamError::UntrustedSocket(why)) => assert_eq!(
            why,
            format!(
                "agent process runs as uid {}, expected {}",
                f.peer,
                socket::current_uid()
            )
        ),
        Err(e) => panic!("refused, but not by the peer credential: {e}"),
        Ok(ids) => panic!("a foreign agent was used ({} identities)", ids.len()),
    }
    f.assert_untouched();
}

#[test]
#[ignore = "needs two users and root setup: scripts/cross-user-test.sh"]
fn served_requests_never_reach_a_foreign_agent() {
    let f = foreign();
    let p = start_proxy(&f.sock, &[ECDSA_CI_FP]);
    let mut c = connect(&p.path);
    let _ = roundtrip(&mut c, &[sigsieve::protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
    let sign = roundtrip(&mut c, &sign_request(&blob(ECDSA_CI), b"x", 0));
    assert_eq!(sign, FAILURE);
    f.assert_untouched();
}

#[test]
#[ignore = "needs two users and root setup: scripts/cross-user-test.sh"]
fn run_exits_2_on_a_foreign_agent() {
    let f = foreign();
    let dir = private_tempdir();
    let mut child = Command::new(sigsieve_bin())
        .args(["run", "--upstream"])
        .arg(&f.sock)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--socket"])
        .arg(dir.path().join("f.sock"))
        .env_remove("SSH_AUTH_SOCK")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("sigsieve run kept running with a foreign agent");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert_eq!(status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("agent process runs as uid"), "stderr: {err}");
    f.assert_untouched();
}

struct Mock(Child);

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Control, no privileges needed: the same mock run by the test user is
/// accepted and logs the request. So the refusals above come from the
/// peer's uid, not from the mock or the environment.
#[test]
fn control_same_mock_run_by_us_is_used() {
    let dir = private_tempdir();
    let (sock, log) = (dir.path().join("own.sock"), dir.path().join("own.log"));
    let _mock = Mock(
        Command::new("python3")
            .arg(mock_script())
            .arg(&sock)
            .arg(&log)
            .spawn()
            .expect("python3 is required for this control"),
    );
    let start = Instant::now();
    while !sock.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "mock did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let ids = Upstream::new(&sock, Duration::from_secs(5))
        .identities()
        .expect("own mock accepted");
    assert!(ids.is_empty());
    assert_eq!(requests(&log), vec!["11".to_string()]);
}
