//! Destination binding and upstream changes through the served socket: what
//! an ssh client sees, and what the upstream agent receives. The bind and
//! userauth bytes are a real OpenSSH session (the committed fuzz seed);
//! the upstream is a fake agent that records every request.

mod common;

use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use common::*;
use sigsieve::keys::Fingerprint;
use sigsieve::policy::Policy;
use sigsieve::protocol::{self, put_string};

const SUCCESS: [u8; 1] = [protocol::SSH_AGENT_SUCCESS];

/// One recorded session: a forwarding-hop bind, the authentication bind to
/// the final destination, the user key and the userauth request it signs.
struct Session {
    first: Vec<u8>,
    last: Vec<u8>,
    key: Vec<u8>,
    auth: Vec<u8>,
}

fn session() -> Session {
    let mut r = protocol::Reader::new(include_bytes!("data/fuzz-seeds/session_bind/sequence"));
    let mut next = || r.string().unwrap().to_vec();
    let s = Session {
        first: next(),
        last: next(),
        key: next(),
        auth: next(),
    };
    s
}

/// Fingerprint of the host key a bind body was made by.
fn host_of(bind: &[u8]) -> Fingerprint {
    Fingerprint::of_blob(protocol::Reader::new(bind).string().unwrap())
}

fn bind_request(body: &[u8]) -> Vec<u8> {
    let mut r = vec![protocol::SSH_AGENTC_EXTENSION];
    put_string(&mut r, b"session-bind@openssh.com");
    r.extend_from_slice(body);
    r
}

fn serve_bound(upstream: &Path, key: &[u8], destinations: &[Fingerprint]) -> Harness {
    let (policy, _) = Policy::from_fingerprints(&[Fingerprint::of_blob(key).to_string()]).unwrap();
    let dests: Vec<String> = destinations.iter().map(|d| d.to_string()).collect();
    let policy = policy.with_destinations(&dests).unwrap();
    start_proxy_with_policy(upstream, policy, test_limits(), Duration::from_secs(5))
}

#[test]
fn binding_denials_on_a_served_connection_never_reach_upstream() {
    let s = session();
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound(&up.path, &s.key, &[host_of(&s.last)]);
    let mut c = connect(&p.path);

    // Unbound connection: arbitrary data and the real userauth are refused.
    assert_eq!(
        roundtrip(&mut c, &sign_request(&s.key, b"arbitrary data", 0)),
        FAILURE
    );
    assert_eq!(
        roundtrip(&mut c, &sign_request(&s.key, &s.auth, 0)),
        FAILURE
    );
    // Only the forwarding hop is bound: still refused.
    assert_eq!(roundtrip(&mut c, &bind_request(&s.first)), SUCCESS);
    assert_eq!(
        roundtrip(&mut c, &sign_request(&s.key, &s.auth, 0)),
        FAILURE
    );
    assert!(
        up.sign_requests().is_empty(),
        "a denied request reached upstream"
    );

    // Authentication bind to the allowed destination.
    assert_eq!(roundtrip(&mut c, &bind_request(&s.last)), SUCCESS);
    // A userauth whose session id differs from the bound one is refused.
    let mut forged = s.auth.clone();
    forged[4] ^= 1; // first byte of the session-id string
    assert_eq!(
        roundtrip(&mut c, &sign_request(&s.key, &forged, 0)),
        FAILURE
    );
    // Arbitrary data is still refused on a bound connection.
    assert_eq!(
        roundtrip(&mut c, &sign_request(&s.key, b"arbitrary data", 0)),
        FAILURE
    );
    assert!(
        up.sign_requests().is_empty(),
        "a denied request reached upstream"
    );

    // The genuine userauth is signed, and it is the only thing upstream saw.
    assert!(is_sign_response(&roundtrip(
        &mut c,
        &sign_request(&s.key, &s.auth, 0)
    )));
    assert_eq!(up.sign_requests(), vec![sign_request(&s.key, &s.auth, 0)]);
}

#[test]
fn destination_outside_the_allowlist_is_refused_before_upstream() {
    let s = session();
    // The forwarding hop's host key is allowed; the final destination is not.
    for allowed in [host_of(&s.first), Fingerprint::of_blob(&blob(ED_ADMIN))] {
        let up = MockAgent::start(three_identities(), Mode::Normal);
        let p = serve_bound(&up.path, &s.key, &[allowed]);
        let mut c = connect(&p.path);
        assert_eq!(roundtrip(&mut c, &bind_request(&s.first)), SUCCESS);
        assert_eq!(roundtrip(&mut c, &bind_request(&s.last)), SUCCESS);
        assert_eq!(
            roundtrip(&mut c, &sign_request(&s.key, &s.auth, 0)),
            FAILURE
        );
        assert!(up.sign_requests().is_empty());
    }
}

#[test]
fn concurrent_connections_do_not_share_bindings() {
    let s = Arc::new(session());
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound(&up.path, &s.key, &[host_of(&s.last)]);
    const UNBOUND: usize = 4;
    const REPLAY: usize = 4;
    let barrier = Arc::new(Barrier::new(1 + UNBOUND + REPLAY));
    let mut handles = Vec::new();
    // 0: the legitimate client. 1..=UNBOUND: same userauth, no binds.
    // Then: replay only the authentication bind on a fresh connection.
    for i in 0..1 + UNBOUND + REPLAY {
        let (s, b, path) = (Arc::clone(&s), Arc::clone(&barrier), p.path.clone());
        handles.push(thread::spawn(move || {
            let mut c = connect(&path);
            b.wait();
            if i == 0 {
                assert_eq!(roundtrip(&mut c, &bind_request(&s.first)), SUCCESS);
                assert_eq!(roundtrip(&mut c, &bind_request(&s.last)), SUCCESS);
            } else if i > UNBOUND {
                let _ = roundtrip(&mut c, &bind_request(&s.last));
            }
            let signed = is_sign_response(&roundtrip(&mut c, &sign_request(&s.key, &s.auth, 0)));
            (i, signed)
        }));
    }
    let results: Vec<(usize, bool)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, signed) in &results {
        if (1..=UNBOUND).contains(i) {
            assert!(!signed, "an unbound connection {i} got a signature");
        }
    }
    let signed = results.iter().filter(|(_, s)| *s).count();
    // The recorded session can be signed once at most (duplicate-attempt
    // cache, F-22), whichever connection wins; upstream sees exactly that.
    assert_eq!(signed, 1, "{results:?}");
    assert_eq!(up.sign_requests().len(), 1);

    // A connection opened after the bound one closed inherits nothing.
    let mut late = connect(&p.path);
    assert_eq!(
        roundtrip(&mut late, &sign_request(&s.key, &s.auth, 0)),
        FAILURE
    );
    assert_eq!(up.sign_requests().len(), 1);
}

#[test]
fn upstream_replaced_under_an_open_connection_fails_closed_then_recovers() {
    let dir = private_tempdir();
    let path = dir.path().join("up.sock");
    let good = MockAgent::start(three_identities(), Mode::Normal);
    std::os::unix::fs::symlink(&good.path, &path).unwrap();
    let p = start_proxy(&path, &[ECDSA_CI_FP]);
    let mut c = connect(&p.path);
    let list_req = [protocol::SSH_AGENTC_REQUEST_IDENTITIES];
    let sign = sign_request(&blob(ECDSA_CI), b"x", 0);
    assert_eq!(
        roundtrip(&mut c, &list_req)[0],
        protocol::SSH_AGENT_IDENTITIES_ANSWER
    );

    let retarget = |to: &Path| {
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(to, &path).unwrap();
    };
    // A regular file, then a dangling link: refused, nothing sent anywhere.
    let file = dir.path().join("plain");
    std::fs::write(&file, b"").unwrap();
    retarget(&file);
    assert_eq!(roundtrip(&mut c, &list_req), FAILURE);
    assert_eq!(roundtrip(&mut c, &sign), FAILURE);
    retarget(&dir.path().join("gone.sock"));
    assert_eq!(roundtrip(&mut c, &list_req), FAILURE);
    assert_eq!(roundtrip(&mut c, &sign), FAILURE);
    assert!(good.sign_requests().is_empty());

    // A misbehaving agent: its replies are rejected and nothing is retried.
    let garbage = MockAgent::start(three_identities(), Mode::Garbage);
    retarget(&garbage.path);
    assert_eq!(roundtrip(&mut c, &list_req), FAILURE);
    assert_eq!(roundtrip(&mut c, &sign), FAILURE);
    assert_eq!(garbage.sign_requests().len(), 1);

    // A working agent again: the same client connection recovers.
    let back = MockAgent::start(three_identities(), Mode::Normal);
    retarget(&back.path);
    assert_eq!(
        roundtrip(&mut c, &list_req)[0],
        protocol::SSH_AGENT_IDENTITIES_ANSWER
    );
    assert!(is_sign_response(&roundtrip(&mut c, &sign)));
    assert_eq!(back.sign_requests().len(), 1);
    assert!(good.sign_requests().is_empty());
}
