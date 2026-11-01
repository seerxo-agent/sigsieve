#!/usr/bin/env python3
"""Turn cargo-cyclonedx output into a release SBOM sidecar, or fail.

Used unchanged by release.yml and release-rehearsal.yml. It:
- rewrites the checkout path to /sigsieve (bom-refs embed it);
- checks CycloneDX 1.5 and that the root component is sigsieve at VERSION;
- checks every crate name in DEPS (`cargo tree` for the target) is listed;
- adds a serialNumber derived only from repository, commit, version and
  target, so generating twice gives identical bytes;
- checks the result is accepted by the pinned actions/attest, then writes
  DST (which must not exist).

actions/attest 1e69f48 (v4.2.2) treats a JSON file as CycloneDX only if
bomFormat, serialNumber and specVersion are all truthy (src/sbom.ts,
checkIsCycloneDX); otherwise sbom-path fails with "Unsupported SBOM format".
cargo-cyclonedx 0.5.9 writes no serialNumber.
"""

import argparse
import json
import re
import sys
import uuid

SERIAL = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TARGET = re.compile(r"^[a-z0-9_]+(-[a-z0-9_]+){2,3}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$")


class Rejected(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Rejected(message)


def serial_number(repo, sha, version, target):
    name = f"https://github.com/{repo}/commit/{sha}#sbom/sigsieve/{version}/{target}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, name)}"


def attest_accepts(bom):
    """Mirror of the pinned actions/attest format detection (see docstring)."""
    spdx = bool(bom.get("spdxVersion") and bom.get("SPDXID"))
    cyclonedx = bool(bom.get("bomFormat") and bom.get("serialNumber") and bom.get("specVersion"))
    return not spdx and cyclonedx


def check_output(bom, serial):
    """Checks on the SBOM about to be written; also run by the tests."""
    require(isinstance(bom, dict), "SBOM is not a JSON object")
    require(bom.get("bomFormat") == "CycloneDX", "bomFormat is not CycloneDX")
    require(bom.get("specVersion") == "1.5", "specVersion is not 1.5")
    sn = bom.get("serialNumber")
    require(isinstance(sn, str) and SERIAL.match(sn), f"serialNumber {sn!r} is not urn:uuid:<RFC 4122 UUID>")
    require(sn == serial, "serialNumber is not the one derived from the release inputs")
    require(attest_accepts(bom), "actions/attest would reject this SBOM")


def finalize(text, workspace, repo, sha, version, target, deps):
    require(REPO.match(repo), f"bad repository {repo!r}")
    require(SHA.match(sha), f"bad commit {sha!r}")
    require(VERSION.match(version), f"bad version {version!r}")
    require(TARGET.match(target), f"bad target {target!r}")
    require(workspace.startswith("/") and len(workspace) > 1, f"bad workspace {workspace!r}")

    bom = json.loads(text.replace(workspace, "/sigsieve"))
    require(isinstance(bom, dict), "SBOM is not a JSON object")
    require(bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion") == "1.5", "unexpected SBOM format")
    # A generator-supplied serial would be random per run (not reproducible).
    require("serialNumber" not in bom, "generator already set a serialNumber")
    root = bom.get("metadata", {}).get("component", {})
    require((root.get("name"), root.get("version")) == ("sigsieve", version), "SBOM describes the wrong package")
    components = bom.get("components")
    require(isinstance(components, list) and components, "SBOM lists no dependencies")
    listed = {c.get("name") for c in components if isinstance(c, dict)} | {"sigsieve"}
    require(deps, "dependency list is empty")
    missing = set(deps) - listed
    require(not missing, f"SBOM misses dependencies: {sorted(missing)}")

    serial = serial_number(repo, sha, version, target)
    out = {}
    for key, value in bom.items():
        out[key] = value
        if key == "specVersion":
            out["serialNumber"] = serial
    check_output(out, serial)
    return json.dumps(out, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--workspace", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--deps", required=True, help="file with one crate name per line (cargo tree)")
    p.add_argument("src")
    p.add_argument("dst")
    a = p.parse_args(argv)
    with open(a.deps) as f:
        deps = f.read().split()
    with open(a.src) as f:
        text = f.read()
    try:
        result = finalize(text, a.workspace, a.repo, a.sha, a.version, a.target, deps)
    except Rejected as e:
        print(f"::error::{a.target}: {e}", file=sys.stderr)
        return 1
    with open(a.dst, "x") as f:
        f.write(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
