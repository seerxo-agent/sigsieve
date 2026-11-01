#!/usr/bin/env python3
"""Check scripts/finalize-sbom.py with synthetic SBOMs (no cargo needed)."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # no scripts/__pycache__ from the import below
script =Path(__file__).with_name("finalize-sbom.py").resolve()
spec = importlib.util.spec_from_file_location("finalize_sbom", script)
fs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fs)

WS = "/home/runner/work/sigsieve/sigsieve"
ARGS = dict(
    workspace=WS,
    repo="semihbugrasezer/sigsieve",
    sha="0123456789abcdef0123456789abcdef01234567",
    version="0.1.0-alpha.3",
    target="x86_64-unknown-linux-gnu",
)
DEPS = ["sigsieve", "base64", "libc"]
BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"name": "sigsieve", "version": "0.1.0-alpha.3",
                               "bom-ref": f"path+file://{WS}#sigsieve@0.1.0-alpha.3"}},
    "components": [{"name": "base64", "version": "0.23.0"}, {"name": "libc", "version": "0.2.0",
                                                               "author": "Sørensen"}],
}
passed = 0


def run(bom=BOM, deps=DEPS, **override):
    return fs.finalize(json.dumps(bom), deps=deps, **{**ARGS, **override})


def rejects(label, fn):
    global passed
    try:
        fn()
    except fs.Rejected:
        passed += 1
        return
    raise AssertionError(f"accepted: {label}")


def mutated(edit):
    bom = copy.deepcopy(BOM)
    edit(bom)
    return bom


# Positive: format, deterministic serial, attest compatibility, path rewrite.
out = run()
bom = json.loads(out)
serial = fs.serial_number(ARGS["repo"], ARGS["sha"], ARGS["version"], ARGS["target"])
assert bom["serialNumber"] == serial and fs.SERIAL.match(serial), serial
assert serial.split(":")[2][14] == "5", "expected a name-based (version 5) UUID"
assert list(bom)[:3] == ["bomFormat", "specVersion", "serialNumber"], list(bom)
assert fs.attest_accepts(bom)
assert WS not in out and "path+file:///sigsieve#" in out
# scripts/verify-release.sh greps for this exact text.
assert '"bomFormat": "CycloneDX"' in out
# Fixed layout: two-space indent, non-ASCII kept as UTF-8.
assert out.startswith('{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5",\n  "serialNumber": "'), out[:80]
assert '"author": "Sørensen"' in out and out.endswith("}\n")
assert run() == out, "same inputs must give identical bytes"
passed += 1

# SemVer pre-release and build metadata are accepted versions.
for v in ("0.1.0-rc-1", "1.2.3+build.5", "1.0.0-alpha.1+x-y"):
    run(bom=mutated(lambda b: b["metadata"]["component"].update(version=v)), version=v)
    passed += 1

# Each release input changes the serial; nothing else does.
for key, value in [("repo", "other/sigsieve"), ("sha", "f" * 40),
                   ("version", "0.1.0-alpha.4"), ("target", "aarch64-apple-darwin")]:
    other = json.loads(run(**{key: value}) if key != "version" else run(
        bom=mutated(lambda b: b["metadata"]["component"].update(version=value)), version=value))
    assert other["serialNumber"] != serial, key
    passed += 1

# Invalid input SBOMs and metadata.
rejects("dependency missing", lambda: run(deps=DEPS + ["ring"]))
rejects("empty dependency list", lambda: run(deps=[]))
rejects("wrong package", lambda: run(bom=mutated(lambda b: b["metadata"]["component"].update(name="other"))))
rejects("wrong version", lambda: run(bom=mutated(lambda b: b["metadata"]["component"].update(version="0.1.0"))))
rejects("no root component", lambda: run(bom=mutated(lambda b: b.pop("metadata"))))
rejects("bomFormat", lambda: run(bom=mutated(lambda b: b.update(bomFormat="SPDX"))))
rejects("specVersion", lambda: run(bom=mutated(lambda b: b.update(specVersion="1.4"))))
# deps=["sigsieve"] so only the components guard, not completeness, can reject.
rejects("no components", lambda: run(deps=["sigsieve"], bom=mutated(lambda b: b.update(components=[]))))
rejects("components not a list", lambda: run(deps=["sigsieve"], bom=mutated(lambda b: b.update(components={}))))
rejects("metadata not an object", lambda: run(bom=mutated(lambda b: b.update(metadata=[]))))
rejects("root component not an object", lambda: run(bom=mutated(lambda b: b["metadata"].update(component="sigsieve"))))
raw = json.dumps(BOM)
rejects("NaN", lambda: fs.finalize(raw.replace('"version": 1,', '"version": NaN,'), deps=DEPS, **ARGS))
rejects("Infinity", lambda: fs.finalize(raw.replace('"version": 1,', '"version": Infinity,'), deps=DEPS, **ARGS))
rejects("duplicate key", lambda: fs.finalize(raw.replace('"version": 1,', '"version": 1, "version": 2,'), deps=DEPS, **ARGS))
rejects("duplicate nested key", lambda: fs.finalize(
    raw.replace('"name": "base64",', '"name": "base64", "name": "ring",'), deps=DEPS, **ARGS))
rejects("invalid JSON", lambda: fs.finalize(raw[:-1], deps=DEPS, **ARGS))
rejects("generator serial", lambda: run(bom=mutated(lambda b: b.update(serialNumber=serial))))
rejects("not an object", lambda: run(bom=[BOM]))
for key, bad in [("sha", "269cf91"), ("sha", "G" * 40), ("repo", "a/b/c"), ("repo", "a b/c"),
                 ("target", "x86_64"), ("target", "../etc-x-y"), ("version", "v0.1.0"),
                 ("version", "0.1"), ("version", "0.1.0-a b"),
                 ("workspace", "/"), ("workspace", "relative")]:
    rejects(f"bad {key} {bad!r}", lambda: run(**{key: bad}))

# Output checks: absent, malformed or incompatible serialNumber.
good = json.loads(out)
for label, edit in [
    ("serial absent", lambda b: b.pop("serialNumber")),
    ("serial empty", lambda b: b.update(serialNumber="")),
    ("serial without urn", lambda b: b.update(serialNumber=serial.removeprefix("urn:uuid:"))),
    ("serial uppercase", lambda b: b.update(serialNumber=serial.upper().replace("URN:UUID:", "urn:uuid:"))),
    ("serial not a uuid", lambda b: b.update(serialNumber="urn:uuid:sigsieve")),
    ("serial other uuid", lambda b: b.update(serialNumber="urn:uuid:00000000-0000-5000-8000-000000000000")),
    ("serial not a string", lambda b: b.update(serialNumber=1)),
    ("also looks like SPDX", lambda b: b.update(spdxVersion="SPDX-2.3", SPDXID="SPDXRef-DOCUMENT")),
]:
    bad = copy.deepcopy(good)
    edit(bad)
    rejects(label, lambda: fs.check_output(bad, serial))

# The mirror matches actions/attest: no serialNumber means unsupported.
assert not fs.attest_accepts({k: v for k, v in good.items() if k != "serialNumber"})

# Command line: exit status, nothing written on rejection, no overwrite.
with tempfile.TemporaryDirectory(prefix="sigsieve-sbom-") as tmp:
    t = Path(tmp)
    (t / "in.json").write_text(json.dumps(BOM, ensure_ascii=False).replace(WS, ARGS["workspace"]), encoding="utf-8")
    (t / "deps.txt").write_text("\n".join(DEPS) + "\n")
    cli = [sys.executable, "-I", str(script)] + [f"--{k}={v}" for k, v in ARGS.items()]

    def call(deps, dst):
        (t / "deps.txt").write_text("\n".join(deps) + "\n")
        return subprocess.run(cli + [f"--deps={t / 'deps.txt'}", str(t / "in.json"), str(t / dst)],
                              capture_output=True, text=True)

    r = call(DEPS, "ok.json")
    assert r.returncode == 0 and (t / "ok.json").read_text(encoding="utf-8") == out, r.stderr
    r = call(DEPS + ["ring"], "missing.json")
    assert r.returncode == 1 and "misses dependencies: ['ring']" in r.stderr, r
    assert not (t / "missing.json").exists()
    r = call(DEPS, "ok.json")
    assert r.returncode != 0 and (t / "ok.json").read_text(encoding="utf-8") == out, "must not overwrite"
    passed += 3

print(f"finalize-sbom: {passed} checks passed")
