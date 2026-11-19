class Sigsieve < Formula
  desc "SSH agent proxy that forwards only allowlisted keys"
  homepage "https://github.com/semihbugrasezer/sigsieve"
  url "https://github.com/semihbugrasezer/sigsieve/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "a2aabcaf89148179cc9aaf56270cbeae8c6d7acb9a617a7495c09e1367e6a04c"
  license "MIT"

  depends_on "rust" => :build

  on_linux do
    depends_on "openssh"
  end

  deny_network_access!

  def fetch
    system "cargo", "fetch", *std_cargo_fetch_args
  end

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    ENV.delete "SSH_AUTH_SOCK"
    ENV.delete "SIGSIEVE_UPSTREAM"
    ENV.delete "SIGSIEVE_ALLOW"
    ENV.delete "SIGSIEVE_DESTINATIONS"

    assert_match "sigsieve #{version}", shell_output("#{bin}/sigsieve --version")

    # No real agent: an unreachable upstream must fail (exit 1), not pass.
    output = shell_output("#{bin}/sigsieve doctor --upstream #{testpath}/missing.sock", 1)
    assert_match "Upstream agent:     FAIL", output

    # A malformed allowlist entry is a configuration error (exit 2).
    output = shell_output("#{bin}/sigsieve doctor --upstream #{testpath}/missing.sock " \
                          "--allow-fingerprint not-a-fingerprint", 2)
    assert_match "Configuration:      INVALID", output

    # Filtering against a throwaway ssh-agent holding a synthetic key.
    if OS.linux?
      ENV.prepend_path "PATH", formula_opt_bin("openssh")
      assert_equal formula_opt_bin("openssh")/"ssh-agent", which("ssh-agent")
    end
    # `doctor` binds its temporary filtered socket under $TMPDIR; keep it inside testpath, where the macOS
    # sandbox allows Unix sockets. Short names keep socket paths well under the 104-byte sun_path limit.
    ENV["TMPDIR"] = testpath
    agent_dir = testpath/"a"
    agent_dir.mkpath
    agent_dir.chmod 0700
    sock = agent_dir/"s"
    agent = spawn("ssh-agent", "-D", "-a", sock.to_s, [:out, :err] => File::NULL)
    begin
      60.times do
        break if sock.socket?

        sleep 0.1
      end
      assert_predicate sock, :socket?, "throwaway ssh-agent did not start"
      system "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sigsieve-brew-test", "-f", agent_dir/"key"
      with_env(SSH_AUTH_SOCK: sock.to_s) do
        system "ssh-add", "-q", agent_dir/"key"
      end
      fingerprint = Utils.safe_popen_read("ssh-keygen", "-lf", agent_dir/"key.pub").split[1]
      output = shell_output("#{bin}/sigsieve doctor --upstream #{sock} --allow-fingerprint #{fingerprint}")
      assert_match(/Filtering: +verified/, output)
    ensure
      Process.kill("TERM", agent)
      Process.wait(agent)
    end
  end
end
