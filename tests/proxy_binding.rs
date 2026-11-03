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
    Session {
        first: next(),
        last: next(),
        key: next(),
        auth: next(),
    }
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
    serve_bound_keys(upstream, &[key], destinations)
}

fn serve_bound_keys(upstream: &Path, keys: &[&[u8]], destinations: &[Fingerprint]) -> Harness {
    let fps: Vec<String> = keys
        .iter()
        .map(|k| Fingerprint::of_blob(k).to_string())
        .collect();
    let (policy, _) = Policy::from_fingerprints(&fps).unwrap();
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

    // A later connection gets nothing either. (After the one signature, the
    // global duplicate-attempt cache would refuse this request anyway, so
    // this does not prove isolation on its own; see
    // a_binding_on_one_connection_never_authorizes_another.)
    let mut late = connect(&p.path);
    assert_eq!(
        roundtrip(&mut late, &sign_request(&s.key, &s.auth, 0)),
        FAILURE
    );
    assert_eq!(up.sign_requests().len(), 1);
}

#[test]
fn a_binding_on_one_connection_never_authorizes_another() {
    let s = session();
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound(&up.path, &s.key, &[host_of(&s.last)]);
    // A binds both hops and stays open without signing. No signature has
    // happened, so the duplicate-attempt cache cannot be what refuses B.
    let mut a = connect(&p.path);
    assert_eq!(roundtrip(&mut a, &bind_request(&s.first)), SUCCESS);
    assert_eq!(roundtrip(&mut a, &bind_request(&s.last)), SUCCESS);
    let mut b = connect(&p.path);
    assert_eq!(
        roundtrip(&mut b, &sign_request(&s.key, &s.auth, 0)),
        FAILURE
    );
    assert!(up.sign_requests().is_empty(), "B used A's binding");
    // A closes without signing: a new connection still gets nothing.
    drop(a);
    let mut c = connect(&p.path);
    assert_eq!(
        roundtrip(&mut c, &sign_request(&s.key, &s.auth, 0)),
        FAILURE
    );
    assert!(up.sign_requests().is_empty(), "C inherited A's binding");
    // Positive control: a connection with its own binding is signed once.
    let mut d = connect(&p.path);
    assert_eq!(roundtrip(&mut d, &bind_request(&s.first)), SUCCESS);
    assert_eq!(roundtrip(&mut d, &bind_request(&s.last)), SUCCESS);
    assert!(is_sign_response(&roundtrip(
        &mut d,
        &sign_request(&s.key, &s.auth, 0)
    )));
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

/// A synthetic ed25519 destination host that can bind any session id.
struct Host(ed25519_dalek::SigningKey);

impl Host {
    fn new(seed: u8) -> Self {
        Host(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    fn blob(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, self.0.verifying_key().as_bytes());
        b
    }

    fn bind(&self, sid: &[u8], forwarding: bool) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut sig = Vec::new();
        put_string(&mut sig, b"ssh-ed25519");
        put_string(&mut sig, &self.0.sign(sid).to_bytes());
        let mut body = Vec::new();
        put_string(&mut body, &self.blob());
        put_string(&mut body, sid);
        put_string(&mut body, &sig);
        body.push(forwarding as u8);
        bind_request(&body)
    }
}

/// To-be-signed hostbound userauth data, as OpenSSH builds it.
fn userauth(sid: &[u8], user: &[u8], key: &[u8], pkalg: &[u8], hostkey: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    put_string(&mut d, sid);
    d.push(50); // SSH2_MSG_USERAUTH_REQUEST
    put_string(&mut d, user);
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey-hostbound-v00@openssh.com");
    d.push(1);
    put_string(&mut d, pkalg);
    put_string(&mut d, key);
    put_string(&mut d, hostkey);
    d
}

fn key_alg(key: &[u8]) -> Vec<u8> {
    protocol::Reader::new(key).string().unwrap().to_vec()
}

#[test]
fn f47_user_name_variants_of_a_recorded_session_get_no_further_signature() {
    // F-47: the recorded session's binds replayed on fresh connections, with
    // the signed userauth re-encoded for other user names. Before the fix,
    // each variant was a new duplicate-cache digest and was signed.
    let s = session();
    let mut r = protocol::Reader::new(&s.last);
    let (hostkey, sid) = (r.string().unwrap().to_vec(), r.string().unwrap().to_vec());
    let alg = key_alg(&s.key);
    // The construction reproduces the recorded request byte for byte.
    assert_eq!(userauth(&sid, b"testuser", &s.key, &alg, &hostkey), s.auth);
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound(&up.path, &s.key, &[host_of(&s.last)]);
    let replay = |user: &[u8]| {
        let mut c = connect(&p.path);
        assert_eq!(roundtrip(&mut c, &bind_request(&s.first)), SUCCESS);
        assert_eq!(roundtrip(&mut c, &bind_request(&s.last)), SUCCESS);
        let data = userauth(&sid, user, &s.key, &alg, &hostkey);
        is_sign_response(&roundtrip(&mut c, &sign_request(&s.key, &data, 0)))
    };
    assert!(replay(b"testuser"), "the first attempt is signed");
    for user in [&b"u0"[..], b"u1", b"u2", b"u3", b"u4", b"root", b"testuser"] {
        assert!(!replay(user), "variant {user:?} was signed");
    }
    // Same connection, after the signature: variants are refused too.
    let mut c = connect(&p.path);
    assert_eq!(roundtrip(&mut c, &bind_request(&s.first)), SUCCESS);
    assert_eq!(roundtrip(&mut c, &bind_request(&s.last)), SUCCESS);
    for flags in [0, 2, 4] {
        let data = userauth(&sid, b"other", &s.key, &alg, &hostkey);
        assert_eq!(
            roundtrip(&mut c, &sign_request(&s.key, &data, flags)),
            FAILURE
        );
    }
    assert_eq!(up.sign_requests(), vec![sign_request(&s.key, &s.auth, 0)]);
}

#[test]
fn rsa_algorithm_variants_share_one_signature_per_session() {
    let host = Host::new(9);
    let rsa = blob(RSA_LEGACY);
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound_keys(&up.path, &[&rsa], &[Fingerprint::of_blob(&host.blob())]);
    let mut c = connect(&p.path);
    assert_eq!(roundtrip(&mut c, &host.bind(b"session-1", false)), SUCCESS);
    let sha256 = userauth(b"session-1", b"u", &rsa, b"rsa-sha2-256", &host.blob());
    let sha512 = userauth(b"session-1", b"u", &rsa, b"rsa-sha2-512", &host.blob());
    assert!(is_sign_response(&roundtrip(
        &mut c,
        &sign_request(&rsa, &sha256, 2)
    )));
    assert_eq!(roundtrip(&mut c, &sign_request(&rsa, &sha512, 4)), FAILURE);
    assert_eq!(up.sign_requests().len(), 1);
}

#[test]
fn legitimate_flows_keep_working_under_the_session_key_cap() {
    let host = Host::new(9);
    let (a, b) = (blob(ECDSA_CI), blob(ED_ADMIN));
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound_keys(&up.path, &[&a, &b], &[Fingerprint::of_blob(&host.blob())]);
    let sign = |c: &mut std::os::unix::net::UnixStream, sid: &[u8], key: &[u8]| {
        let data = userauth(sid, b"u", key, &key_alg(key), &host.blob());
        is_sign_response(&roundtrip(c, &sign_request(key, &data, 0)))
    };
    // A request SigSieve denies does not use up the session's slot.
    let mut c = connect(&p.path);
    assert_eq!(roundtrip(&mut c, &host.bind(b"s1", false)), SUCCESS);
    let wrong_host = userauth(b"s1", b"u", &a, &key_alg(&a), &Host::new(8).blob());
    assert_eq!(
        roundtrip(&mut c, &sign_request(&a, &wrong_host, 0)),
        FAILURE
    );
    assert!(up.sign_requests().is_empty());
    // publickey,publickey: two different keys in one session.
    assert!(sign(&mut c, b"s1", &a));
    assert!(sign(&mut c, b"s1", &b));
    assert!(!sign(&mut c, b"s1", &a), "same key twice in one session");
    // Reconnects: each new session signs once with the same key.
    for sid in [&b"s2"[..], b"s3"] {
        let mut c = connect(&p.path);
        assert_eq!(roundtrip(&mut c, &host.bind(sid, false)), SUCCESS);
        assert!(sign(&mut c, sid, &a));
    }
    assert_eq!(up.sign_requests().len(), 4);
}

#[test]
fn failed_upstream_attempt_blocks_its_session_not_recovery() {
    // A cancelled Touch ID prompt or locked agent answers FAILURE. OpenSSH
    // then tries its next key in the same session, or the user connects
    // again (a new session).
    let host = Host::new(9);
    let (key, next) = (blob(ECDSA_CI), blob(ED_ADMIN));
    let dest = [Fingerprint::of_blob(&host.blob())];
    let failing = MockAgent::start(three_identities(), Mode::Failure);
    let dir = private_tempdir();
    let link = dir.path().join("up.sock");
    std::os::unix::fs::symlink(&failing.path, &link).unwrap();
    let p = serve_bound_keys(&link, &[&key, &next], &dest);
    let attempt = |sid: &[u8], user: &[u8], key: &[u8]| {
        let mut c = connect(&p.path);
        assert_eq!(roundtrip(&mut c, &host.bind(sid, false)), SUCCESS);
        let data = userauth(sid, user, key, &key_alg(key), &host.blob());
        is_sign_response(&roundtrip(&mut c, &sign_request(key, &data, 0)))
    };
    assert!(!attempt(b"s1", b"u", &key));
    assert_eq!(failing.sign_requests().len(), 1);
    // The same session and key, even re-encoded, gets no second prompt.
    assert!(!attempt(b"s1", b"u", &key));
    assert!(!attempt(b"s1", b"v", &key));
    assert_eq!(failing.sign_requests().len(), 1);
    // The next key in the same session still reaches the agent.
    assert!(!attempt(b"s1", b"u", &next));
    assert_eq!(failing.sign_requests().len(), 2);
    // The agent works again: a new session is signed.
    let working = MockAgent::start(three_identities(), Mode::Normal);
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&working.path, &link).unwrap();
    assert!(attempt(b"s2", b"u", &key));
    assert_eq!(working.sign_requests().len(), 1);
}

#[test]
fn concurrent_user_name_variants_admit_exactly_one_signature() {
    let host = Arc::new(Host::new(9));
    let key = Arc::new(blob(ECDSA_CI));
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = serve_bound_keys(&up.path, &[&key], &[Fingerprint::of_blob(&host.blob())]);
    const N: usize = 12;
    let barrier = Arc::new(Barrier::new(N));
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let (host, key, b, path) = (
                Arc::clone(&host),
                Arc::clone(&key),
                Arc::clone(&barrier),
                p.path.clone(),
            );
            thread::spawn(move || {
                let mut c = connect(&path);
                assert_eq!(roundtrip(&mut c, &host.bind(b"shared", false)), SUCCESS);
                let user = format!("u{i}");
                let data = userauth(
                    b"shared",
                    user.as_bytes(),
                    &key,
                    &key_alg(&key),
                    &host.blob(),
                );
                let req = sign_request(&key, &data, 0);
                b.wait();
                is_sign_response(&roundtrip(&mut c, &req))
            })
        })
        .collect();
    let signed = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|s| *s)
        .count();
    assert_eq!(signed, 1);
    assert_eq!(up.sign_requests().len(), 1);
}
