# Formula for the maintainer-owned tap semihbugrasezer/homebrew-sigsieve.
# Not in homebrew-core. SigSieve is experimental and not independently
# audited. See packaging/homebrew/README.md before changing url/sha256.
class Sigsieve < Formula
  desc "SSH agent filtering proxy that exposes only allowlisted identities"
  homepage "https://github.com/semihbugrasezer/sigsieve"
  # Source archive of the immutable tag (commit 5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751).
  url "https://github.com/semihbugrasezer/sigsieve/archive/refs/tags/v0.1.0-alpha.4.tar.gz"
  sha256 "dfea4d33371a7d429c1cbc7e293e5345db7b69c9ad2cbc225f7ebd9d354e8ae7"
  license "MIT"

  # No `head` block on purpose: it would build untagged `main`.

  depends_on "rust" => :build

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
    agent_dir = testpath/"agent"
    agent_dir.mkpath
    agent_dir.chmod 0700
    sock = agent_dir/"agent.sock"
    agent = spawn("ssh-agent", "-D", "-a", sock.to_s, [:out, :err] => File::NULL)
    begin
      60.times do
        break if sock.socket?

        sleep 0.1
      end
      assert_predicate sock, :socket?, "throwaway ssh-agent did not start"
      system "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sigsieve-brew-test",
             "-f", (agent_dir/"key").to_s
      with_env(SSH_AUTH_SOCK: sock.to_s) do
        system "ssh-add", "-q", (agent_dir/"key").to_s
      end
      fingerprint = Utils.safe_popen_read("ssh-keygen", "-lf", (agent_dir/"key.pub").to_s).split[1]
      output = shell_output("#{bin}/sigsieve doctor --upstream #{sock} --allow-fingerprint #{fingerprint}")
      assert_match(/Filtering: +verified/, output)
    ensure
      Process.kill("TERM", agent)
      Process.wait(agent)
    end
  end
end
