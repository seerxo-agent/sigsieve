//! End-to-end tests over real OpenSSH: `sigsieve connect` -> `ssh` -> an
//! unprivileged throwaway `sshd` on 127.0.0.1 -> hostile commands in the
//! remote session using the forwarded agent.
//!
//! Isolation: every key, host key, authorized_keys file, known_hosts file and
//! sshd config lives in a fresh temp directory; ssh runs with `-F /dev/null`
//! and `IdentitiesOnly`, so neither ~/.ssh nor the developer's agent is used.
//! The sshd binds only to 127.0.0.1 on free ports and runs as the current
//! user (no root, no PAM, no system configuration).
//!
//! Prerequisites: `sshd`, `ssh`, `ssh-agent`, `ssh-add`, `ssh-keygen`, and the
//! ability to run sshd unprivileged (checked with `sshd -t`). If they are
//! missing the tests are skipped with a message, unless
//! `SIGSIEVE_REQUIRE_SSHD=1` is set (as in CI), which turns that into a failure.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn skip_or_fail(reason: &str) -> Option<Env> {
    if std::env::var_os("SIGSIEVE_REQUIRE_SSHD").is_some_and(|v| v == "1") {
        panic!("sshd end-to-end prerequisites not met: {reason}");
    }
    eprintln!("skipping sshd end-to-end test: {reason}");
    None
}

fn ok(cmd: &mut Command) -> String {
    let o = cmd.output().unwrap();
    assert!(o.status.success(), "{cmd:?} failed: {o:?}");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Whether `sshd -t` accepts a configuration keyword (with a throwaway
/// host key, since `-t` requires one).
fn sshd_accepts(sshd: &str, d: &Path, line: &str) -> bool {
    let probe = d.join("probe");
    fs::create_dir_all(&probe).unwrap();
    let key = probe.join("hk");
    if !key.exists() {
        ok(Command::new("ssh-keygen")
            .args(["-q", "-N", "", "-t", "ed25519", "-f"])
            .arg(&key));
    }
    let cfg = probe.join("cfg");
    fs::write(&cfg, format!("HostKey {}\n{line}\n", key.display())).unwrap();
    Command::new(sshd)
        .arg("-t")
        .arg("-f")
        .arg(&cfg)
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn fingerprint(pubkey: &Path) -> String {
    ok(Command::new("ssh-keygen").arg("-lf").arg(pubkey))
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string()
}

/// Absolute path of a python3 interpreter (the remote session has a minimal
/// PATH, so the absolute path is passed).
fn python3() -> Option<String> {
    let o = Command::new("sh")
        .args(["-c", "command -v python3"])
        .output()
        .ok()?;
    let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !p.is_empty()).then_some(p)
}

/// A hostile client speaking the raw agent protocol over $SSH_AUTH_SOCK. It
/// skips the identity listing and asks directly for signatures with keys it
/// only knows the public half of, then tries mutations and extensions.
const RAW_ATTACKER: &str = r#"
import base64, os, socket, struct, sys

def frame(payload):
    return struct.pack(">I", len(payload)) + payload

def string(b):
    return struct.pack(">I", len(b)) + b

def call(payload):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ["SSH_AUTH_SOCK"])
    s.sendall(frame(payload))
    hdr = s.recv(4, socket.MSG_WAITALL)
    n = struct.unpack(">I", hdr)[0]
    body = s.recv(n, socket.MSG_WAITALL)
    s.close()
    return body[0]

for path in sys.argv[1:]:
    name = os.path.basename(path).split(".")[0]
    blob = base64.b64decode(open(path).read().split()[1])
    for flags in (0, 2, 4):
        t = call(bytes([13]) + string(blob) + string(b"attacker-chosen-data") + struct.pack(">I", flags))
        print("RAW-SIGN-%s-%d type=%d" % (name, flags, t))
    t = call(bytes([18]) + string(blob))
    print("RAW-REMOVE-%s type=%d" % (name, t))
    t = call(bytes([27]) + string(b"session-bind@openssh.com") + string(blob) + string(b"x" * 32) + string(b"y" * 64) + b"\x01")
    print("RAW-BIND-%s type=%d" % (name, t))
"#;

/// `N` distinct free ports. Every listener stays bound until all ports are
/// chosen: releasing one before binding the next can hand out the same port
/// twice, and an sshd configured with a duplicate `Port` then applies the hop
/// port's `Match` block to logins too.
fn free_ports<const N: usize>() -> [u16; N] {
    let held: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    std::array::from_fn(|i| held[i].local_addr().unwrap().port())
}

/// Whether the server on `port` presents the host key in `pubkey_line`
/// (`<type> <base64> [comment]`). A port released by `free_ports` can still
/// be taken by another process before sshd binds it.
fn serves_host_key(port: u16, pubkey_line: &str) -> Result<(), String> {
    let key = pubkey_line.split_whitespace().nth(1).unwrap();
    let o = Command::new("ssh-keyscan")
        // Explicit timeout: the default 5 s can expire while parallel tests
        // generate host keys.
        .args(["-T", "15", "-p", &port.to_string(), "127.0.0.1"])
        .output()
        .map_err(|e| format!("ssh-keyscan: {e}"))?;
    let out = String::from_utf8_lossy(&o.stdout);
    if out.split_whitespace().any(|w| w == key) {
        return Ok(());
    }
    Err(format!(
        "port {port} did not present this test's host key ({}); stdout: {:?}; stderr: {:?}",
        o.status,
        out.trim(),
        String::from_utf8_lossy(&o.stderr).trim()
    ))
}

struct Killer(Child);

impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The isolated environment: an ssh-agent with three keys (the "upstream",
/// standing in for Secretive) and an sshd with two ports.
struct Env {
    dir: tempfile::TempDir,
    agent_sock: PathBuf,
    _agent: Killer,
    _sshd: Killer,
    /// Login port: authorizes only the hidden `admin` key.
    login_port: u16,
    /// Hop port: authorizes only the allowed `ci` key.
    hop_port: u16,
    /// A second, separate sshd with its own host key, authorizing `ci`; it
    /// allows local TCP forwarding so it can serve as a ProxyJump hop.
    dest_port: u16,
    /// SHA256 fingerprint of the second sshd's host key.
    dest_hostkey_fp: String,
    /// SHA256 fingerprint of the first sshd's host key.
    hostkey_fp: String,
    _sshd2: Killer,
    known_hosts: PathBuf,
}

impl Env {
    fn d(&self) -> &Path {
        self.dir.path()
    }

    fn pubkey(&self, name: &str) -> PathBuf {
        self.d().join("p").join(format!("{name}.pub"))
    }

    fn upstream_listing(&self) -> String {
        ok(Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", &self.agent_sock))
    }

    /// Common, fully isolated ssh options for a given port and identity.
    fn ssh_opts(&self, port: u16, identity: &str) -> Vec<String> {
        vec![
            "-F".into(),
            "/dev/null".into(),
            "-p".into(),
            port.to_string(),
            "-o".into(),
            format!("UserKnownHostsFile={}", self.known_hosts.display()),
            "-o".into(),
            "GlobalKnownHostsFile=/dev/null".into(),
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            format!("IdentityFile={}", self.pubkey(identity).display()),
        ]
    }
}

fn setup() -> Option<Env> {
    setup_with_dest_key(&["-t", "ecdsa", "-b", "256"])
}

/// Like [`setup`], but the second (destination) sshd uses a host key
/// generated with these `ssh-keygen` type arguments. If another process took
/// one of the chosen ports before an sshd bound it, the environment is
/// rebuilt on new ports (bounded); the tests never run against a server
/// whose host key was not verified.
fn setup_with_dest_key(dest_key: &[&str]) -> Option<Env> {
    let mut last = String::new();
    for _ in 0..3 {
        match try_setup(dest_key)? {
            Ok(env) => return Some(env),
            Err(e) => last = e,
        }
    }
    panic!("isolated sshds kept losing their ports to other processes: {last}");
}

/// One attempt: `None` when prerequisites are missing (see `skip_or_fail`),
/// `Err` when a port did not end up served by this environment's sshd.
fn try_setup(dest_key: &[&str]) -> Option<Result<Env, String>> {
    for tool in ["ssh", "ssh-agent", "ssh-add", "ssh-keygen", "ssh-keyscan"] {
        if !have(tool) {
            return skip_or_fail(&format!("{tool} not installed")).map(Ok);
        }
    }
    let Some(sshd) = ["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
    else {
        return skip_or_fail("sshd not found").map(Ok);
    };
    let dir = tempfile::Builder::new()
        .prefix("ss")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let d = dir.path().to_path_buf();
    // Owner-only whatever the umask: SigSieve refuses a group-writable
    // runtime directory (rt) as an unsafe socket ancestor.
    for sub in ["k", "p", "rt"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(d.join(sub))
            .unwrap();
    }

    // Upstream agent with three disposable keys.
    let agent_sock = d.join("a.sock");
    let agent = Killer(
        Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&agent_sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    while !agent_sock.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "ssh-agent did not start"
        );
        thread::sleep(Duration::from_millis(20));
    }
    for (name, args) in [
        ("ci", &["-t", "ecdsa", "-b", "256"][..]),
        ("admin", &["-t", "ed25519"][..]),
        ("legacy", &["-t", "rsa", "-b", "2048"][..]),
    ] {
        let k = d.join("k").join(name);
        ok(Command::new("ssh-keygen")
            .args(["-q", "-N", "", "-C", &format!("{name}@e2e")])
            .args(args)
            .arg("-f")
            .arg(&k));
        ok(Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &agent_sock)
            .arg(&k));
        fs::copy(
            k.with_extension("pub"),
            d.join("p").join(format!("{name}.pub")),
        )
        .unwrap();
    }
    // A copy of the allowed (synthetic) key, for tests that restart the
    // agent; ssh itself is only ever given public keys (IdentitiesOnly).
    fs::DirBuilder::new()
        .mode(0o700)
        .create(d.join("restart"))
        .unwrap();
    fs::copy(d.join("k").join("ci"), d.join("restart").join("ci")).unwrap();
    // Private keys are only needed inside the agent.
    fs::remove_dir_all(d.join("k")).unwrap();

    // sshd: host key, per-port authorized_keys, config.
    let hostkey = d.join("hostkey");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", "ed25519", "-f"])
        .arg(&hostkey));
    fs::copy(d.join("p/admin.pub"), d.join("ak_login")).unwrap();
    fs::copy(d.join("p/ci.pub"), d.join("ak_hop")).unwrap();
    let [login_port, hop_port, dest_port] = free_ports();
    let cfg = d.join("sshd_config");
    // OpenSSH 9.8+ penalizes a source address after failed logins; the tests
    // fail logins from 127.0.0.1 on purpose. Older sshd rejects the keyword.
    let penalties = if sshd_accepts(sshd, &d, "PerSourcePenalties no") {
        "PerSourcePenalties no\n"
    } else {
        ""
    };
    fs::write(
        &cfg,
        format!(
            "ListenAddress 127.0.0.1\nPort {login_port}\nPort {hop_port}\nHostKey {hk}\n\
             PidFile {d}/sshd.pid\nAuthorizedKeysFile {d}/ak_login\nStrictModes no\n\
             UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             AllowAgentForwarding yes\nAllowTcpForwarding no\nX11Forwarding no\n\
             PermitUserEnvironment no\nLogLevel ERROR\n{penalties}\
             Match LocalPort {hop_port}\n    AuthorizedKeysFile {d}/ak_hop\n",
            hk = hostkey.display(),
            d = d.display()
        ),
    )
    .unwrap();
    let test = Command::new(sshd)
        .arg("-t")
        .arg("-f")
        .arg(&cfg)
        .output()
        .unwrap();
    if !test.status.success() {
        return skip_or_fail(&format!(
            "sshd cannot run unprivileged here: {}",
            String::from_utf8_lossy(&test.stderr).trim()
        ))
        .map(Ok);
    }
    let sshd_proc = Killer(
        Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    for port in [login_port, hop_port] {
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "sshd did not start"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
    // Second sshd: different host key, only the `ci` key authorized.
    let hostkey2 = d.join("hostkey2");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", ""])
        .args(dest_key)
        .arg("-f")
        .arg(&hostkey2));
    let cfg2 = d.join("sshd_config2");
    fs::write(
        &cfg2,
        format!(
            "ListenAddress 127.0.0.1\nPort {dest_port}\nHostKey {hk}\nPidFile {d}/sshd2.pid\n\
             AuthorizedKeysFile {d}/ak_hop\nStrictModes no\nUsePAM no\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             AllowAgentForwarding yes\nAllowTcpForwarding local\nX11Forwarding no\nLogLevel ERROR\n{penalties}",
            hk = hostkey2.display(),
            d = d.display()
        ),
    )
    .unwrap();
    let sshd2 = Killer(
        Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(&cfg2)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // Its own budget: the first sshd's startup and the destination host-key
    // generation (RSA-3072 takes up to seconds) must not use it up.
    let started2 = Instant::now();
    while TcpStream::connect(("127.0.0.1", dest_port)).is_err() {
        assert!(
            started2.elapsed() < Duration::from_secs(10),
            "second sshd did not start"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let host_pub = fs::read_to_string(hostkey.with_extension("pub")).unwrap();
    let host2_pub = fs::read_to_string(hostkey2.with_extension("pub")).unwrap();
    let known_hosts = d.join("known_hosts");
    fs::write(
        &known_hosts,
        format!(
            "[127.0.0.1]:{login_port} {host_pub}[127.0.0.1]:{hop_port} {host_pub}\
             [127.0.0.1]:{dest_port} {host2_pub}"
        ),
    )
    .unwrap();
    let hostkey_fp = fingerprint(&hostkey.with_extension("pub"));
    let dest_hostkey_fp = fingerprint(&hostkey2.with_extension("pub"));

    let env = Env {
        dir,
        agent_sock,
        _agent: agent,
        _sshd: sshd_proc,
        login_port,
        hop_port,
        dest_port,
        dest_hostkey_fp,
        hostkey_fp,
        _sshd2: sshd2,
        known_hosts,
    };
    for (port, key) in [
        (login_port, &host_pub),
        (hop_port, &host_pub),
        (dest_port, &host2_pub),
    ] {
        if let Err(e) = serves_host_key(port, key) {
            return Some(Err(e));
        }
    }
    Some(Ok(env))
}

/// Run `sigsieve connect` with the upstream agent as login agent (like
/// Secretive) and only `ci` allowlisted. `TMPDIR` points at a private
/// directory so the runtime socket's cleanup can be checked.
fn sigsieve_connect(env: &Env, extra_before_host: &[String], remote: &str) -> Output {
    sigsieve_connect_with(env, &[], extra_before_host, remote)
}

fn sigsieve_connect_with(
    env: &Env,
    sigsieve_args: &[String],
    extra_before_host: &[String],
    remote: &str,
) -> Output {
    let ci_fp = fingerprint(&env.pubkey("ci"));
    let mut ssh_args = env.ssh_opts(env.login_port, "admin");
    ssh_args.extend_from_slice(extra_before_host);
    ssh_args.push(remote.to_string());
    Command::new(env!("CARGO_BIN_EXE_sigsieve"))
        .env("SSH_AUTH_SOCK", &env.agent_sock)
        .env("TMPDIR", env.d().join("rt"))
        .args(["connect", "127.0.0.1", "--upstream"])
        .arg(&env.agent_sock)
        .args(["--allow-fingerprint", &ci_fp])
        .args(sigsieve_args)
        .arg("--")
        .args(&ssh_args)
        .output()
        .unwrap()
}

fn marker<'a>(out: &'a str, name: &str) -> &'a str {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{name} rc=")))
        .unwrap_or_else(|| panic!("marker {name} missing in:\n{out}"))
}

#[test]
fn forwarded_agent_is_filtered_end_to_end() {
    let Some(env) = setup() else { return };
    let d = env.d();
    let (ci_fp, admin_fp, legacy_fp) = (
        fingerprint(&env.pubkey("ci")),
        fingerprint(&env.pubkey("admin")),
        fingerprint(&env.pubkey("legacy")),
    );
    fs::write(d.join("msg"), b"e2e").unwrap();
    let hop = |port: u16, key: &str| -> String {
        format!(
            "ssh {} 127.0.0.1 echo hop-ok",
            env.ssh_opts(port, key).join(" ")
        )
    };
    // Everything below runs on the "remote" side with the forwarded agent,
    // acting as a hostile host that knows every public key.
    let script = format!(
        r#"
echo "LIST-BEGIN"; ssh-add -l; echo "LIST rc=$?"
ssh-keygen -Y sign -n test -f {p}/admin.pub {d}/msg >/dev/null 2>&1; echo "SIGN-HIDDEN-ADMIN rc=$?"
ssh-keygen -Y sign -n test -f {p}/legacy.pub {d}/msg >/dev/null 2>&1; echo "SIGN-HIDDEN-LEGACY rc=$?"
ls {d}/msg.sig >/dev/null 2>&1; echo "HIDDEN-SIG-FILE rc=$?"
ssh-keygen -Y sign -n test -f {p}/ci.pub {d}/msg >/dev/null 2>&1; echo "SIGN-ALLOWED rc=$?"
ssh-keygen -Y check-novalidate -n test -f {p}/ci.pub -s {d}/msg.sig < {d}/msg >/dev/null 2>&1; echo "VERIFY-ALLOWED rc=$?"
{hop_ok} 2>/dev/null; echo "HOP-ALLOWED rc=$?"
{hop_hidden} 2>/dev/null; echo "HOP-HIDDEN rc=$?"
ssh-add -D >/dev/null 2>&1; echo "REMOVE-ALL rc=$?"
ssh-add -d {p}/ci.pub >/dev/null 2>&1; echo "REMOVE-ONE rc=$?"
"#,
        p = d.join("p").display(),
        d = d.display(),
        hop_ok = hop(env.hop_port, "ci"),
        hop_hidden = hop(env.login_port, "admin"),
    );
    let py = python3();
    let script = match &py {
        Some(py) => {
            fs::write(d.join("attacker.py"), RAW_ATTACKER).unwrap();
            format!(
                "{script}{py} {d}/attacker.py {p}/admin.pub {p}/legacy.pub {p}/ci.pub\n",
                d = d.display(),
                p = d.join("p").display()
            )
        }
        None => {
            if std::env::var_os("SIGSIEVE_REQUIRE_SSHD").is_some_and(|v| v == "1") {
                panic!("python3 is required for the raw-protocol attacker");
            }
            eprintln!("python3 not found: raw-protocol attacker step skipped");
            script
        }
    };
    fs::write(d.join("remote.sh"), script).unwrap();

    let o = sigsieve_connect(&env, &[], &format!("sh {}/remote.sh", d.display()));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(
        o.status.success(),
        "connect failed\nstdout:\n{out}\nstderr:\n{err}"
    );

    // 1. Login succeeded with the hidden `admin` key (only it is authorized
    //    on the login port): local login auth uses the unfiltered agent.
    // 2. The forwarded agent lists exactly the allowed key.
    let listing: Vec<&str> = out
        .lines()
        .skip_while(|l| *l != "LIST-BEGIN")
        .skip(1)
        .take_while(|l| !l.starts_with("LIST rc="))
        .collect();
    assert_eq!(listing.len(), 1, "{out}");
    assert!(listing[0].contains(&ci_fp), "{out}");
    assert!(
        !out.contains(&admin_fp) && !out.contains(&legacy_fp),
        "{out}"
    );
    // 3. Hidden keys cannot sign even though their public keys are known.
    assert_ne!(marker(&out, "SIGN-HIDDEN-ADMIN"), "0", "{out}");
    assert_ne!(marker(&out, "SIGN-HIDDEN-LEGACY"), "0", "{out}");
    assert_ne!(marker(&out, "HIDDEN-SIG-FILE"), "0", "{out}");
    // 4. The allowed key signs and the signature verifies.
    assert_eq!(marker(&out, "SIGN-ALLOWED"), "0", "{out}");
    assert_eq!(marker(&out, "VERIFY-ALLOWED"), "0", "{out}");
    // 5. A second hop authenticates with the allowed key, though its
    //    session-bind@openssh.com is rejected by SigSieve.
    assert_eq!(marker(&out, "HOP-ALLOWED"), "0", "{out}");
    assert!(out.contains("hop-ok"), "{out}");
    assert!(
        err.contains("rejected unsupported extension request"),
        "{err}"
    );
    // 6. A hop that needs the hidden key fails.
    assert_ne!(marker(&out, "HOP-HIDDEN"), "0", "{out}");
    // 7. Mutations fail and the upstream still holds all three keys.
    assert_ne!(marker(&out, "REMOVE-ALL"), "0", "{out}");
    assert_ne!(marker(&out, "REMOVE-ONE"), "0", "{out}");
    assert_eq!(env.upstream_listing().lines().count(), 3);
    // 8. Raw protocol attacker who knows the hidden public keys: every sign
    //    request for a hidden key is refused (5 = SSH_AGENT_FAILURE) and the
    //    proxy logs the denial or an aggregate when the log budget is full;
    //    the allowed key still signs (14).
    if py.is_some() {
        for name in ["admin", "legacy"] {
            for flags in [0, 2, 4] {
                assert!(
                    out.contains(&format!("RAW-SIGN-{name}-{flags} type=5")),
                    "{name}/{flags}: {out}"
                );
            }
            assert!(out.contains(&format!("RAW-REMOVE-{name} type=5")), "{out}");
            assert!(out.contains(&format!("RAW-BIND-{name} type=5")), "{out}");
        }
        assert!(out.contains("RAW-SIGN-ci-0 type=14"), "{out}");
        for fp in [&admin_fp, &legacy_fp] {
            assert!(
                err.contains(&format!("denied sign request for non-allowlisted key {fp}"))
                    || err.contains("suppressed"),
                "{err}"
            );
        }
        assert_eq!(env.upstream_listing().lines().count(), 3);
    }
    // 9. The runtime socket and its directory were removed.
    let leftovers: Vec<_> = fs::read_dir(d.join("rt")).unwrap().collect();
    assert!(leftovers.is_empty(), "runtime files left: {leftovers:?}");
}

/// Regression for the review finding: an existing ControlMaster connection
/// that forwards the *full* agent must not be reused by `sigsieve connect`.
#[test]
fn existing_control_master_with_full_forwarding_is_not_reused() {
    let Some(env) = setup() else { return };
    let d = env.d();
    let ctl = d.join("cm");
    let mux = vec![
        "-o".to_string(),
        "ControlMaster=auto".into(),
        "-o".into(),
        format!("ControlPath={}", ctl.display()),
        "-o".into(),
        "ControlPersist=60".into(),
    ];
    // A master forwarding the full upstream agent, as `ssh -A` would.
    let mut master_args = env.ssh_opts(env.login_port, "admin");
    master_args.extend(mux.clone());
    let master = Command::new("ssh")
        .env("SSH_AUTH_SOCK", &env.agent_sock)
        .args(&master_args)
        .args(["-o", "ForwardAgent=yes", "-fN", "127.0.0.1"])
        .output()
        .unwrap();
    assert!(master.status.success(), "{master:?}");
    assert!(ctl.exists(), "control master not running");
    // Sanity check: a plain multiplexed session sees all three keys.
    let mut plain = env.ssh_opts(env.login_port, "admin");
    plain.extend(mux.clone());
    let all = Command::new("ssh")
        .env("SSH_AUTH_SOCK", &env.agent_sock)
        .args(&plain)
        .args(["-o", "ForwardAgent=yes", "127.0.0.1", "ssh-add -l"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&all.stdout).lines().count(),
        3,
        "{all:?}"
    );

    let o = sigsieve_connect(&env, &mux, "ssh-add -l");
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let _ = Command::new("ssh")
        .args([
            "-o",
            &format!("ControlPath={}", ctl.display()),
            "-O",
            "exit",
            "127.0.0.1",
        ])
        .output();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        out.lines().count(),
        1,
        "multiplexed onto the full agent:\n{out}"
    );
    assert!(out.contains(&fingerprint(&env.pubkey("ci"))), "{out}");
}

/// Destination binding over real OpenSSH. Only the second sshd's host key is
/// an allowed destination. The hostile remote host (the first sshd's
/// session) holds the allowed key's forwarded agent, but can only use it to
/// authenticate to that destination.
#[test]
fn destination_binding_end_to_end() {
    let Some(env) = setup() else { return };
    let d = env.d();
    let ci_fp = fingerprint(&env.pubkey("ci"));
    fs::write(d.join("msg"), b"e2e").unwrap();
    let hop = |port: u16| -> String {
        format!(
            "ssh {} 127.0.0.1 echo hop-ok",
            env.ssh_opts(port, "ci").join(" ")
        )
    };
    let mut script = format!(
        r#"
echo "LIST-BEGIN"; ssh-add -l; echo "LIST rc=$?"
{to_allowed} 2>/dev/null; echo "HOP-ALLOWED-DEST rc=$?"
{to_other} 2>/dev/null; echo "HOP-OTHER-DEST rc=$?"
ssh-keygen -Y sign -n test -f {p}/ci.pub {d}/msg >/dev/null 2>&1; echo "SIGN-ARBITRARY rc=$?"
"#,
        to_allowed = hop(env.dest_port),
        to_other = hop(env.hop_port),
        p = d.join("p").display(),
        d = d.display(),
    );
    let py = python3();
    if let Some(py) = &py {
        fs::write(d.join("binding_attacker.py"), BINDING_ATTACKER).unwrap();
        script.push_str(&format!(
            "{py} {}/binding_attacker.py {}/ci.pub\n",
            d.display(),
            d.join("p").display()
        ));
    } else if std::env::var_os("SIGSIEVE_REQUIRE_SSHD").is_some_and(|v| v == "1") {
        panic!("python3 is required for the raw-protocol attacker");
    }
    fs::write(d.join("remote.sh"), script).unwrap();

    let o = sigsieve_connect_with(
        &env,
        &[
            "--allow-destination".to_string(),
            env.dest_hostkey_fp.clone(),
        ],
        &[],
        &format!("sh {}/remote.sh", d.display()),
    );
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert!(
        err.contains("destination binding enforced") || err.contains("enforced: allowed keys"),
        "{err}"
    );

    // The allowed key is still listed (filtering unchanged).
    assert!(out.contains(&ci_fp), "{out}");
    // Allowed destination: authentication succeeds through verified bindings.
    assert_eq!(marker(&out, "HOP-ALLOWED-DEST"), "0", "{out}\n{err}");
    assert!(out.contains("hop-ok"), "{out}");
    // Any other destination: refused, with the reason logged.
    assert_ne!(marker(&out, "HOP-OTHER-DEST"), "0", "{out}");
    assert!(
        err.contains(&format!(
            "destination host key {} is not an allowed destination",
            env.hostkey_fp
        )),
        "{err}"
    );
    // Arbitrary data cannot be signed with the restricted key.
    assert_ne!(marker(&out, "SIGN-ARBITRARY"), "0", "{out}");
    if py.is_some() {
        for m in [
            "RAW-SIGN-ARBITRARY",
            "RAW-SIGN-AFTER-FORGED-BIND",
            "RAW-FAKE-USERAUTH",
        ] {
            assert!(out.contains(&format!("{m} type=5")), "{m}: {out}");
        }
        assert!(out.contains("RAW-FORGED-BIND type=28"), "{out}");
        assert!(
            // Without a verified authentication bind of their own, the
            // attacker's requests stop at the forwarding hop check.
            err.contains("(destination binding): sign attempted on a forwarding hop"),
            "{err}"
        );
        assert!(
            err.contains("rejected session-bind: host key signature does not verify"),
            "{err}"
        );
    }
}

/// Raw-protocol attacker against a destination-bound forwarded agent. It
/// knows the allowed public key but none of the destination's secrets.
const BINDING_ATTACKER: &str = r#"
import base64, os, socket, struct, sys

def s(b): return struct.pack(">I", len(b)) + b

def call(conn, payload):
    conn.sendall(struct.pack(">I", len(payload)) + payload)
    n = struct.unpack(">I", conn.recv(4, socket.MSG_WAITALL))[0]
    return conn.recv(n, socket.MSG_WAITALL)[0]

def connect():
    c = socket.socket(socket.AF_UNIX); c.connect(os.environ["SSH_AUTH_SOCK"]); return c

key = base64.b64decode(open(sys.argv[1]).read().split()[1])
alg = open(sys.argv[1]).read().split()[0].encode()
sign = lambda data: bytes([13]) + s(key) + s(data) + struct.pack(">I", 0)

c = connect()
print("RAW-SIGN-ARBITRARY type=%d" % call(c, sign(b"attacker-chosen-data")))

# Forged binding: plausible host key, garbage signature over our own session id.
hostkey = s(b"ssh-ed25519") + s(b"\x11" * 32)
sid = b"\x22" * 32
fake_sig = s(b"ssh-ed25519") + s(b"\x33" * 64)
bind = bytes([27]) + s(b"session-bind@openssh.com") + s(hostkey) + s(sid) + s(fake_sig) + b"\x00"
print("RAW-FORGED-BIND type=%d" % call(c, bind))

# A well-formed userauth request for that fake session, on the same connection.
ua = s(sid) + bytes([50]) + s(b"root") + s(b"ssh-connection") + s(b"publickey-hostbound-v00@openssh.com") + b"\x01" + s(alg) + s(key) + s(hostkey)
print("RAW-SIGN-AFTER-FORGED-BIND type=%d" % call(c, sign(ua)))
c.close()

# Fresh connection: userauth-shaped data without any binding of our own.
c = connect()
print("RAW-FAKE-USERAUTH type=%d" % call(c, sign(ua)))
"#;

/// Cross-validation of P-384 and P-521 host-key verification against real
/// OpenSSH: the destination sshd signs the session id with a P-384 / P-521
/// host key, the forwarded hop sends that session-bind through SigSieve, and
/// authentication to the allowed destination must succeed. (Unit tests only
/// check signatures produced by the same crates that verify them.)
#[test]
fn destination_binding_with_p384_and_p521_host_keys() {
    for bits in ["384", "521"] {
        let Some(env) = setup_with_dest_key(&["-t", "ecdsa", "-b", bits]) else {
            return;
        };
        let d = env.d();
        let hop = format!(
            "ssh {} 127.0.0.1 echo hop-ok-{bits}",
            env.ssh_opts(env.dest_port, "ci").join(" ")
        );
        fs::write(d.join("remote.sh"), format!("{hop}\necho \"HOP rc=$?\"\n")).unwrap();
        let o = sigsieve_connect_with(
            &env,
            &[
                "--allow-destination".to_string(),
                env.dest_hostkey_fp.clone(),
            ],
            &[],
            &format!("sh {}/remote.sh", d.display()),
        );
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert!(
            o.status.success(),
            "P-{bits}: stdout:\n{out}\nstderr:\n{err}"
        );
        assert_eq!(marker(&out, "HOP"), "0", "P-{bits}: {out}\n{err}");
        assert!(out.contains(&format!("hop-ok-{bits}")), "P-{bits}: {out}");
        assert!(!err.contains("rejected session-bind"), "P-{bits}: {err}");
    }
}

/// C-1 regression, positive side: a ProxyJump chain whose hop `connect` can
/// verify still works end to end. The hop (second sshd) is reached by its own
/// ssh, which reads only the `-F` file and authenticates with the filtered
/// agent; the destination still sees only the allowlisted key.
#[test]
fn verified_proxyjump_still_connects_and_filters() {
    let Some(env) = setup() else { return };
    let d = env.d();
    let (ci_fp, admin_fp) = (
        fingerprint(&env.pubkey("ci")),
        fingerprint(&env.pubkey("admin")),
    );
    let common = format!(
        "  HostName 127.0.0.1\n  UserKnownHostsFile {kh}\n  GlobalKnownHostsFile /dev/null\n\
         StrictHostKeyChecking yes\n  BatchMode yes\n  IdentitiesOnly yes\n",
        kh = env.known_hosts.display()
    );
    let cfg = d.join("jump_config");
    fs::write(
        &cfg,
        format!(
            "Host target\n  Port {login}\n  ProxyJump hop\n  IdentityFile {p}/admin.pub\n{common}\
             Host hop\n  Port {dest}\n  IdentityFile {p}/ci.pub\n{common}",
            login = env.login_port,
            dest = env.dest_port,
            p = d.join("p").display(),
        ),
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_sigsieve"))
        .env("SSH_AUTH_SOCK", &env.agent_sock)
        .env("TMPDIR", d.join("rt"))
        .args(["connect", "target", "--upstream"])
        .arg(&env.agent_sock)
        .args(["--allow-fingerprint", &ci_fp, "--", "-F"])
        .arg(&cfg)
        .arg("ssh-add -l; echo \"LIST rc=$?\"")
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert_eq!(marker(&out, "LIST"), "0", "{out}");
    assert!(out.contains(&ci_fp), "{out}");
    assert!(!out.contains(&admin_fp), "{out}");
}

// --- Destination-binding negative matrix (real OpenSSH) --------------------

/// An `ssh` command line, run on the remote side with the forwarded agent,
/// that logs in to `port` with the allowed `ci` key and prints `tag`.
fn remote_hop(env: &Env, port: u16, extra: &str, tag: &str) -> String {
    format!(
        "ssh {} {extra} 127.0.0.1 echo {tag}",
        env.ssh_opts(port, "ci").join(" ")
    )
}

/// Run `script` on the remote side through `sigsieve connect`, destination
/// binding enforced for `allowed` host key fingerprints. Returns stdout and
/// stderr after asserting that connect itself succeeded.
fn run_bound(env: &Env, allowed: &[&str], script: &str) -> (String, String) {
    let d = env.d();
    fs::write(d.join("remote.sh"), script).unwrap();
    let mut args = Vec::new();
    for fp in allowed {
        args.push("--allow-destination".to_string());
        args.push(fp.to_string());
    }
    let o = sigsieve_connect_with(env, &args, &[], &format!("sh {}/remote.sh", d.display()));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert!(
        err.contains("destination binding enforced") || err.contains("enforced: allowed keys"),
        "{err}"
    );
    (out, err)
}

/// A remote client that authenticates to an allowed destination with plain
/// `publickey` (`PubkeyAuthentication=unbound`, which is what a server
/// without `publickey-hostbound` support leads to) is refused, even though
/// the session is correctly bound to that destination. sshd has no option
/// to stop advertising hostbound, so the client-side setting stands in for
/// such a server. The same destination with hostbound authentication works.
#[test]
fn destination_binding_refuses_plain_publickey_to_allowed_destination() {
    let Some(env) = setup() else { return };
    let script = format!(
        "{} 2>/dev/null; echo \"HOSTBOUND rc=$?\"\n{} 2>/dev/null; echo \"UNBOUND rc=$?\"\n",
        remote_hop(&env, env.dest_port, "", "hostbound-ok"),
        remote_hop(
            &env,
            env.dest_port,
            "-o PubkeyAuthentication=unbound",
            "unbound-ok"
        ),
    );
    let (out, err) = run_bound(&env, &[&env.dest_hostkey_fp], &script);
    assert_eq!(marker(&out, "HOSTBOUND"), "0", "{out}\n{err}");
    assert!(out.contains("hostbound-ok"), "{out}");
    assert_ne!(marker(&out, "UNBOUND"), "0", "{out}\n{err}");
    assert!(!out.contains("unbound-ok"), "{out}");
    assert!(
        err.contains("destination binding requires publickey-hostbound authentication"),
        "{err}"
    );
}

/// An RSA host key cannot be bound, so the final hop fails closed even when
/// its fingerprint is explicitly an allowed destination: binding mode never
/// silently degrades to identity-only filtering.
#[test]
fn destination_binding_rsa_host_key_fails_closed_even_when_allowed() {
    let Some(env) = setup_with_dest_key(&["-t", "rsa", "-b", "3072"]) else {
        return;
    };
    let script = format!(
        "{} 2>/dev/null; echo \"HOP-RSA rc=$?\"\n",
        remote_hop(&env, env.dest_port, "", "rsa-ok")
    );
    let (out, err) = run_bound(&env, &[&env.dest_hostkey_fp], &script);
    assert_ne!(marker(&out, "HOP-RSA"), "0", "{out}\n{err}");
    assert!(!out.contains("rsa-ok"), "{out}");
    assert!(
        err.contains("rejected session-bind: unsupported host key type"),
        "{err}"
    );
    assert!(
        err.contains("(destination binding): sign attempted on a forwarding hop"),
        "{err}"
    );
}

/// Only the final (authentication) hop's host key counts. With only the
/// forwarding host's (Ed25519) key allowed, logging in to that host again
/// works, but a different final destination is refused although an allowed
/// host key is earlier in the binding chain.
#[test]
fn allowed_forwarding_hop_does_not_authorize_another_final_destination() {
    let Some(env) = setup() else { return };
    let script = format!(
        "{} 2>/dev/null; echo \"HOP-ALLOWED-ED25519 rc=$?\"\n{} 2>/dev/null; echo \"HOP-OTHER rc=$?\"\n",
        remote_hop(&env, env.hop_port, "", "ed25519-ok"),
        remote_hop(&env, env.dest_port, "", "other-ok"),
    );
    let (out, err) = run_bound(&env, &[&env.hostkey_fp], &script);
    assert_eq!(marker(&out, "HOP-ALLOWED-ED25519"), "0", "{out}\n{err}");
    assert!(out.contains("ed25519-ok"), "{out}");
    assert_ne!(marker(&out, "HOP-OTHER"), "0", "{out}\n{err}");
    assert!(!out.contains("other-ok"), "{out}");
    assert!(
        err.contains(&format!(
            "destination host key {} is not an allowed destination",
            env.dest_hostkey_fp
        )),
        "{err}"
    );
}

/// The agent forwarded on through an intermediate host: local -> login host
/// -> allowed destination (agent forwarded again) -> final hop. The binding
/// chain then has two forwarding entries; an allowed final destination still
/// works and a disallowed one is refused.
#[test]
fn destination_binding_across_two_forwarding_hops() {
    let Some(env) = setup() else { return };
    let d = env.d();
    let inner = format!(
        "{} 2>/dev/null; echo \"INNER-ALLOWED rc=$?\"\n{} 2>/dev/null; echo \"INNER-OTHER rc=$?\"\n",
        remote_hop(&env, env.dest_port, "", "inner-allowed-ok"),
        remote_hop(&env, env.hop_port, "", "inner-other-ok"),
    );
    fs::write(d.join("inner.sh"), inner).unwrap();
    let outer = format!(
        "ssh {} -o ForwardAgent=yes 127.0.0.1 sh {}/inner.sh 2>/dev/null; echo \"OUTER rc=$?\"\n",
        env.ssh_opts(env.dest_port, "ci").join(" "),
        d.display()
    );
    let (out, err) = run_bound(&env, &[&env.dest_hostkey_fp], &outer);
    assert_eq!(marker(&out, "OUTER"), "0", "{out}\n{err}");
    assert_eq!(marker(&out, "INNER-ALLOWED"), "0", "{out}\n{err}");
    assert!(out.contains("inner-allowed-ok"), "{out}");
    assert_ne!(marker(&out, "INNER-OTHER"), "0", "{out}\n{err}");
    assert!(!out.contains("inner-other-ok"), "{out}");
    assert!(
        err.contains(&format!(
            "destination host key {} is not an allowed destination",
            env.hostkey_fp
        )),
        "{err}"
    );
}

/// `git commit -S` with `gpg.format=ssh` on the remote host, using the
/// forwarded agent: it works and verifies in identity-filtering mode and is
/// refused in destination-binding mode (no commit is created). git's global
/// and system configuration are ignored, and the repository has no hooks.
#[test]
fn git_ssh_commit_signing_through_forwarded_agent() {
    let Some(env) = setup() else { return };
    if !have("git") {
        if std::env::var_os("SIGSIEVE_REQUIRE_SSHD").is_some_and(|v| v == "1") {
            panic!("git is required for the commit-signing test");
        }
        eprintln!("skipping git commit-signing test: git not installed");
        return;
    }
    let d = env.d();
    let ci_pub = env.pubkey("ci");
    fs::write(
        d.join("allowed_signers"),
        format!("e2e {}", fs::read_to_string(&ci_pub).unwrap()),
    )
    .unwrap();
    let script = |repo: &str| {
        format!(
            r#"export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
R={d}/{repo}
git init -q --template= "$R" || exit 1
cd "$R" || exit 1
git -c user.name=e2e -c user.email=e2e -c gpg.format=ssh -c user.signingkey={key} commit -q -S --allow-empty -m signed >/dev/null 2>&1; echo "GIT-COMMIT rc=$?"
git -c gpg.ssh.allowedSignersFile={d}/allowed_signers verify-commit HEAD >/dev/null 2>&1; echo "GIT-VERIFY rc=$?"
git rev-parse -q --verify HEAD >/dev/null 2>&1; echo "GIT-HEAD rc=$?"
"#,
            d = d.display(),
            key = ci_pub.display(),
        )
    };

    // Identity filtering: the allowed key signs the commit.
    fs::write(d.join("git_a.sh"), script("repo-a")).unwrap();
    let o = sigsieve_connect(&env, &[], &format!("sh {}/git_a.sh", d.display()));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert_eq!(marker(&out, "GIT-COMMIT"), "0", "{out}\n{err}");
    assert_eq!(marker(&out, "GIT-VERIFY"), "0", "{out}\n{err}");

    // Destination binding: commit signing is not SSH authentication.
    let (out, err) = run_bound(&env, &[&env.dest_hostkey_fp], &script("repo-b"));
    assert_ne!(marker(&out, "GIT-COMMIT"), "0", "{out}\n{err}");
    assert_ne!(
        marker(&out, "GIT-HEAD"),
        "0",
        "unsigned commit created: {out}"
    );
    assert!(
        err.contains("(destination binding): connection has no verified session binding")
            || err.contains("(destination binding): sign attempted on a forwarding hop"),
        "{err}"
    );
}

/// Stops every GnuPG daemon of a throwaway home directory on drop.
struct GpgHome(PathBuf);

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", &self.0)
            .arg("--homedir")
            .arg(&self.0)
            .args(["--kill", "all"])
            .output();
    }
}

/// Destination binding with gpg-agent as the upstream (and login) agent: a
/// throwaway GnuPG home with one unprotected synthetic ECDSA P-256
/// authentication key. Skipped when GnuPG is not installed, unless
/// `SIGSIEVE_REQUIRE_GPG_AGENT=1`.
#[test]
fn destination_binding_with_gpg_agent_upstream() {
    if !["gpg", "gpgconf", "gpg-agent"].iter().all(|c| have(c)) {
        if std::env::var_os("SIGSIEVE_REQUIRE_GPG_AGENT").is_some_and(|v| v == "1") {
            panic!("GnuPG tools required for the gpg-agent test");
        }
        eprintln!("skipping gpg-agent test: GnuPG tools not installed");
        return;
    }
    let Some(env) = setup() else { return };
    let d = env.d();
    let home = d.join("g");
    fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
    let gpg_home = GpgHome(home.clone());
    let gpg = |program: &str| {
        let mut c = Command::new(program);
        c.env("GNUPGHOME", &gpg_home.0)
            .arg("--homedir")
            .arg(&gpg_home.0);
        c
    };
    fs::write(home.join("gpg-agent.conf"), "enable-ssh-support\n").unwrap();
    // The daemon keeps inherited pipes open, so do not capture its output.
    let started = gpg("gpg-agent")
        .arg("--daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(started.success(), "gpg-agent did not start");
    ok(gpg("gpg").args([
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--quick-gen-key",
        "sigsieve test",
        "nistp256",
        "auth",
        "never",
    ]));
    let grips: String = ok(gpg("gpg").args(["--list-keys", "--with-keygrip", "--with-colons"]))
        .lines()
        .filter_map(|l| l.strip_prefix("grp:::::::::"))
        .map(|g| format!("{}\n", g.trim_end_matches(':')))
        .collect();
    fs::write(home.join("sshcontrol"), grips).unwrap();
    let sock = PathBuf::from(ok(gpg("gpgconf").args(["--list-dirs", "agent-ssh-socket"])).trim());
    let line = ok(Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &sock));
    assert_eq!(line.lines().count(), 1, "{line}");
    assert!(line.starts_with("ecdsa-sha2-nistp256 "), "{line}");
    fs::write(env.pubkey("gpg"), &line).unwrap();
    let gpg_fp = fingerprint(&env.pubkey("gpg"));
    // Both sshds accept the gpg key on every port (authorized_keys files are
    // read at authentication time).
    for ak in ["ak_login", "ak_hop"] {
        let mut keys = fs::read_to_string(d.join(ak)).unwrap();
        keys.push_str(&line);
        fs::write(d.join(ak), keys).unwrap();
    }

    let hop = |port: u16, tag: &str| {
        format!(
            "ssh {} 127.0.0.1 echo {tag} 2>/dev/null; echo \"{tag} rc=$?\"\n",
            env.ssh_opts(port, "gpg").join(" ")
        )
    };
    fs::write(
        d.join("remote.sh"),
        format!(
            "ssh-add -l; {}{}ssh-keygen -Y sign -n test -f {} {}/remote.sh >/dev/null 2>&1; echo \"SIGN rc=$?\"\n",
            hop(env.dest_port, "GPG-ALLOWED"),
            hop(env.hop_port, "GPG-OTHER"),
            env.pubkey("gpg").display(),
            d.display()
        ),
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_sigsieve"))
        .env("SSH_AUTH_SOCK", &sock)
        .env("TMPDIR", d.join("rt"))
        .args(["connect", "127.0.0.1", "--upstream"])
        .arg(&sock)
        .args(["--allow-fingerprint", &gpg_fp])
        .args(["--allow-destination", &env.dest_hostkey_fp, "--"])
        .args(env.ssh_opts(env.login_port, "gpg"))
        .arg(format!("sh {}/remote.sh", d.display()))
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(o.status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains(&gpg_fp), "{out}");
    assert_eq!(marker(&out, "GPG-ALLOWED"), "0", "{out}\n{err}");
    assert!(out.contains("\nGPG-ALLOWED\n"), "{out}");
    assert_ne!(marker(&out, "GPG-OTHER"), "0", "{out}\n{err}");
    assert_ne!(marker(&out, "SIGN"), "0", "{out}\n{err}");
    assert!(
        err.contains(&format!(
            "destination host key {} is not an allowed destination",
            env.hostkey_fp
        )),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Agent lifecycle and session interruption over real OpenSSH (alpha.4).
// A real `ssh` client logs in to the throwaway sshd through `sigsieve run`
// in destination-binding mode. Between SigSieve and the real ssh-agent a
// relay counts the sign requests that actually reach the agent.

mod lifecycle {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const SIGN_REQUEST: u8 = 13;
    const SIGN_RESPONSE: u8 = 14;
    const SUCCESS: u8 = 6;
    const EXTENSION: u8 = 27;

    fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        s.read_exact(&mut len).ok()?;
        let n = u32::from_be_bytes(len) as usize;
        if n > 256 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    fn write_frame(s: &mut UnixStream, payload: &[u8]) -> bool {
        let mut f = (payload.len() as u32).to_be_bytes().to_vec();
        f.extend_from_slice(payload);
        s.write_all(&f).is_ok()
    }

    /// Between SigSieve and the real ssh-agent. Connects to the agent path
    /// anew for each connection (so the agent can be restarted) and counts
    /// sign requests delivered to the agent. With `drop_signs` set it closes
    /// both sides when a sign request arrives, without delivering it: an
    /// upstream that goes away while the request is pending.
    struct CountingRelay {
        path: PathBuf,
        delivered: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        drop_signs: Arc<AtomicBool>,
    }

    impl CountingRelay {
        fn start(dir: &Path, agent: &Path) -> CountingRelay {
            let path = dir.join("relay.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let delivered = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let drop_signs = Arc::new(AtomicBool::new(false));
            let (dl, dr, ds, agent) = (
                Arc::clone(&delivered),
                Arc::clone(&dropped),
                Arc::clone(&drop_signs),
                agent.to_path_buf(),
            );
            thread::spawn(move || {
                for client in listener.incoming() {
                    let Ok(mut client) = client else { continue };
                    let (dl, dr, ds, agent) = (
                        Arc::clone(&dl),
                        Arc::clone(&dr),
                        Arc::clone(&ds),
                        agent.clone(),
                    );
                    thread::spawn(move || {
                        let Ok(mut up) = UnixStream::connect(&agent) else {
                            return;
                        };
                        while let Some(req) = read_frame(&mut client) {
                            let is_sign = req.first() == Some(&SIGN_REQUEST);
                            if is_sign && ds.load(Ordering::SeqCst) {
                                dr.fetch_add(1, Ordering::SeqCst);
                                return;
                            }
                            if !write_frame(&mut up, &req) {
                                return;
                            }
                            if is_sign {
                                dl.fetch_add(1, Ordering::SeqCst);
                            }
                            let Some(reply) = read_frame(&mut up) else {
                                return;
                            };
                            if !write_frame(&mut client, &reply) {
                                return;
                            }
                        }
                    });
                }
            });
            CountingRelay {
                path,
                delivered,
                dropped,
                drop_signs,
            }
        }

        fn delivered(&self) -> usize {
            self.delivered.load(Ordering::SeqCst)
        }
    }

    /// Between the ssh client and SigSieve: forwards and records what the
    /// client sends, so a real session's frames can be replayed later.
    fn capture_relay(dir: &Path, target: &Path) -> (PathBuf, Arc<Mutex<Vec<Vec<u8>>>>) {
        let path = dir.join("capture.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let (rec, target) = (Arc::clone(&frames), target.to_path_buf());
        thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(mut client) = client else { continue };
                let Ok(mut up) = UnixStream::connect(&target) else {
                    continue;
                };
                while let Some(req) = read_frame(&mut client) {
                    rec.lock().unwrap().push(req.clone());
                    if !write_frame(&mut up, &req) {
                        break;
                    }
                    let Some(reply) = read_frame(&mut up) else {
                        break;
                    };
                    if !write_frame(&mut client, &reply) {
                        break;
                    }
                }
            }
        });
        (path, frames)
    }

    struct Run(Child);

    impl Drop for Run {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl Run {
        fn alive(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }
    }

    /// `sigsieve run` allowing `ci` only towards the second sshd's host key.
    fn start_run(env: &Env, upstream: &Path, socket: &Path) -> Run {
        let ci = fingerprint(&env.pubkey("ci"));
        let run = Run(Command::new(env!("CARGO_BIN_EXE_sigsieve"))
            .args(["run", "--upstream"])
            .arg(upstream)
            .args(["--allow-fingerprint", &ci])
            .args(["--allow-destination", &env.dest_hostkey_fp, "--socket"])
            .arg(socket)
            .env_remove("SSH_AUTH_SOCK")
            .stdout(Stdio::null())
            .stderr(fs::File::create(socket.with_extension("err")).unwrap())
            .spawn()
            .unwrap());
        let start = Instant::now();
        while !socket.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "sigsieve run did not start"
            );
            thread::sleep(Duration::from_millis(20));
        }
        run
    }

    fn ssh_cmd(env: &Env, agent: &Path, port: u16, identity: &str, remote: &str) -> Command {
        let mut c = Command::new("ssh");
        c.args(env.ssh_opts(port, identity))
            .args(["-o", "ConnectTimeout=10"])
            .arg("-o")
            .arg(format!("IdentityAgent={}", agent.display()))
            .arg("127.0.0.1")
            .arg(remote)
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }

    fn login(env: &Env, agent: &Path, port: u16, identity: &str) -> Option<i32> {
        ssh_cmd(env, agent, port, identity, "true")
            .status()
            .unwrap()
            .code()
    }

    /// The forbidden requests: `ci` to a server that authorizes it but whose
    /// host key is not an allowed destination (refused by destination
    /// binding alone), and the hidden `admin` key (refused by identity
    /// filtering, the sign allowlist and the destination check together).
    fn assert_forbidden_fail(env: &Env, sock: &Path) {
        assert_ne!(
            login(env, sock, env.hop_port, "ci"),
            Some(0),
            "disallowed destination"
        );
        assert_ne!(
            login(env, sock, env.login_port, "admin"),
            Some(0),
            "hidden key"
        );
    }

    fn restart_agent(env: &mut Env) {
        let _ = fs::remove_file(&env.agent_sock); // a killed agent leaves its socket
        env._agent = Killer(
            Command::new("ssh-agent")
                .args(["-D", "-a"])
                .arg(&env.agent_sock)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        while !env.agent_sock.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "ssh-agent did not restart"
            );
            thread::sleep(Duration::from_millis(20));
        }
        ok(Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &env.agent_sock)
            .arg(env.d().join("restart").join("ci")));
    }

    #[test]
    fn real_agent_killed_and_restarted_under_a_running_proxy() {
        let Some(mut env) = setup() else { return };
        let d = env.d().to_path_buf();
        // Two proxies: one behind the counting relay (sign requests counted at
        // the agent), one configured with the agent's own path, so SigSieve
        // itself meets the stale socket, the missing path and the new agent.
        let relay = CountingRelay::start(&d, &env.agent_sock);
        let sock = d.join("f.sock");
        let mut run = start_run(&env, &relay.path, &sock);
        let direct = d.join("direct.sock");
        let mut run_direct = start_run(&env, &env.agent_sock, &direct);

        // Before: the allowed login is signed once; forbidden ones never are.
        assert_eq!(login(&env, &sock, env.dest_port, "ci"), Some(0));
        assert_eq!(relay.delivered(), 1);
        assert_forbidden_fail(&env, &sock);
        assert_eq!(relay.delivered(), 1);
        assert_eq!(login(&env, &direct, env.dest_port, "ci"), Some(0));
        assert_forbidden_fail(&env, &direct);
        assert_eq!(relay.delivered(), 1);

        // The agent dies and leaves its socket (connection refused), then the
        // socket is removed (no such path). Both proxies keep running and the
        // allowed login fails. (Forbidden logins would fail here anyway.)
        let _ = env._agent.0.kill();
        let _ = env._agent.0.wait();
        assert!(env.agent_sock.exists(), "expected a stale agent socket");
        assert_ne!(login(&env, &sock, env.dest_port, "ci"), Some(0));
        assert_ne!(login(&env, &direct, env.dest_port, "ci"), Some(0));
        fs::remove_file(&env.agent_sock).unwrap();
        assert_ne!(login(&env, &direct, env.dest_port, "ci"), Some(0));
        assert!(run.alive(), "sigsieve run exited when the agent died");
        assert!(
            run_direct.alive(),
            "sigsieve run exited when the agent died"
        );

        // A new agent on the same path holds only the allowed key. Each login
        // is a new connection with its own binding and signature; nothing
        // from before the restart is reused.
        restart_agent(&mut env);
        assert_eq!(login(&env, &sock, env.dest_port, "ci"), Some(0));
        assert_eq!(relay.delivered(), 2);
        assert_forbidden_fail(&env, &sock);
        assert_eq!(relay.delivered(), 2);
        assert_eq!(login(&env, &direct, env.dest_port, "ci"), Some(0));
        assert_forbidden_fail(&env, &direct);
        assert!(run.alive() && run_direct.alive());
    }

    #[test]
    fn concurrent_real_sessions_interruption_and_replay() {
        let Some(env) = setup() else { return };
        let d = env.d().to_path_buf();
        let relay = CountingRelay::start(&d, &env.agent_sock);
        let sock = d.join("f.sock");
        let mut run = start_run(&env, &relay.path, &sock);

        // Three allowed sessions that stay open, and forbidden attempts at the
        // same time.
        let mut allowed: Vec<Child> = (0..3)
            .map(|_| {
                ssh_cmd(&env, &sock, env.dest_port, "ci", "sleep 4")
                    .spawn()
                    .unwrap()
            })
            .collect();
        let mut forbidden: Vec<Child> = (0..3)
            .map(|_| {
                ssh_cmd(&env, &sock, env.hop_port, "ci", "true")
                    .spawn()
                    .unwrap()
            })
            .chain((0..2).map(|_| {
                ssh_cmd(&env, &sock, env.login_port, "admin", "true")
                    .spawn()
                    .unwrap()
            }))
            .collect();
        for c in &mut forbidden {
            assert_ne!(
                c.wait().unwrap().code(),
                Some(0),
                "a forbidden session logged in"
            );
        }
        // Wait until all three have been signed, then kill one client while
        // the other sessions are still running. (OpenSSH closes its agent
        // connection after authentication, so this ends an ssh session, not
        // an in-flight agent request; see the pending-request case below.)
        let start = Instant::now();
        while relay.delivered() < 3 {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "allowed logins were not signed"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let _ = allowed[0].kill();
        let _ = allowed[0].wait();
        for c in allowed.iter_mut().skip(1) {
            assert_eq!(
                c.wait().unwrap().code(),
                Some(0),
                "an allowed session failed"
            );
        }
        assert_eq!(
            relay.delivered(),
            3,
            "exactly one signature per allowed login"
        );

        // Upstream goes away while a sign request is pending: the login fails
        // and the request is not delivered (it was in flight, not processed).
        relay.drop_signs.store(true, Ordering::SeqCst);
        assert_ne!(login(&env, &sock, env.dest_port, "ci"), Some(0));
        assert_eq!(relay.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(relay.delivered(), 3);
        relay.drop_signs.store(false, Ordering::SeqCst);

        // A real session through a capturing relay, then replayed after it
        // has disconnected.
        let (cap, frames) = capture_relay(&d, &sock);
        assert_eq!(login(&env, &cap, env.dest_port, "ci"), Some(0));
        assert_eq!(relay.delivered(), 4);
        let frames = frames.lock().unwrap().clone();
        let binds: Vec<&Vec<u8>> = frames.iter().filter(|f| f[0] == EXTENSION).collect();
        let sign = frames
            .iter()
            .find(|f| f[0] == SIGN_REQUEST)
            .expect("captured sign request");
        assert!(!binds.is_empty(), "the real session sent no session-bind");

        // Replaying the session's own binds and signature request on a new
        // connection: the bind is accepted, the signature is not (the
        // duplicate-attempt cache, F-22), and nothing reaches the agent.
        let mut c = UnixStream::connect(&sock).unwrap();
        for b in &binds {
            assert!(write_frame(&mut c, b));
            assert_eq!(read_frame(&mut c).unwrap(), vec![SUCCESS]);
        }
        assert!(write_frame(&mut c, sign));
        assert_ne!(
            read_frame(&mut c).unwrap()[0],
            SIGN_RESPONSE,
            "replayed signature"
        );
        // Another connection reusing only the signature request, without
        // binds: refused by destination binding before the cache is reached.
        let mut c2 = UnixStream::connect(&sock).unwrap();
        assert!(write_frame(&mut c2, sign));
        assert_ne!(
            read_frame(&mut c2).unwrap()[0],
            SIGN_RESPONSE,
            "unbound reuse signed"
        );
        assert_eq!(relay.delivered(), 4, "a replay reached the agent");

        // And the proxy still serves a fresh, legitimate login.
        assert_eq!(login(&env, &sock, env.dest_port, "ci"), Some(0));
        assert_eq!(relay.delivered(), 5);
        assert!(run.alive());
    }
}
