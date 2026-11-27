"""Guards for the deployment fixes of the 0.41.0 audit round.

Each group of tests names the register entry it holds closed: TD-09 (console
assets), R-06 (service account), R-27 (nginx headers), R-19/R-28 (container
stack), R-22 and TD-41 (test isolation), TD-34 (backup check), TD-43 (atomic
site publish and versioned vhosts).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")

# --------------------------------------------------------------------------
# nginx: parsing helpers (no nginx binary needed)
# --------------------------------------------------------------------------
VHOST_FILES = [
    ROOT / "infrastructure" / "nginx-veyrs-console.conf",
    ROOT / "infrastructure" / "nginx-veyrs-docs.conf",
    ROOT / "infrastructure" / "nginx-veyrs-web.conf",
    ROOT / "docker" / "console.conf",
]


def _install_vhost() -> str:
    m = re.search(r'cat > "\$NGINX_SITE" <<NGEOF\n(.*?)\nNGEOF', INSTALL, re.S)
    assert m, "install.sh no longer generates a vhost in a heredoc"
    return m.group(1)


def _strip_comments(text: str) -> str:
    return re.sub(r"(?m)^\s*#.*$", "", text)


def _blocks(text: str, head: str) -> list[str]:
    """Bodies of every `head ... { ... }` block (brace matched), comments removed."""
    text = _strip_comments(text)
    out = []
    for m in re.finditer(head, text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append(text[m.end():i - 1])
    return out


def _header_names(body: str) -> set[str]:
    return {m.lower() for m in re.findall(r"^\s*add_header\s+(\S+)", body, re.M)}


def _server_level(server_body: str) -> str:
    """The server block without its location blocks."""
    return re.sub(r"location\s[^{]*\{[^{}]*\}", "", server_body)


VHOST_SOURCES = [(p.name, p.read_text(encoding="utf-8")) for p in VHOST_FILES]
VHOST_SOURCES.append(("install.sh heredoc", _install_vhost()))


@pytest.mark.parametrize("name,text", VHOST_SOURCES, ids=[n for n, _ in VHOST_SOURCES])
def test_a_location_with_add_header_repeats_the_server_security_headers(name, text):
    """R-27: add_header in a location REPLACES every inherited add_header."""
    servers = _blocks(text, r"\bserver\s*\{")
    assert servers, f"{name}: no server block found"
    checked = 0
    for server in servers:
        inherited = _header_names(_server_level(server)) - {"cache-control"}
        assert inherited, f"{name}: the server block declares no security headers"
        for body in _blocks(server, r"location\s+[^{]+\{"):
            own = _header_names(body)
            if own:
                checked += 1
                assert inherited <= own, (
                    f"{name}: a location sets {sorted(own)} and so drops "
                    f"{sorted(inherited - own)}; repeat them or use `expires`")
    assert checked or name == "nginx-veyrs-web.conf", f"{name}: expected at least one location with add_header"


# --------------------------------------------------------------------------
# TD-43: every node's server names are in the versioned vhosts
# --------------------------------------------------------------------------
def _server_names(path: Path) -> set[str]:
    m = re.search(r"^\s*server_name\s+(.*?);", path.read_text(), re.M | re.S)
    assert m, f"{path.name} declares no server_name"
    return set(m.group(1).split())


def test_docs_and_product_vhosts_are_versioned_with_their_server_names():
    docs = ROOT / "infrastructure" / "nginx-veyrs-docs.conf"
    web = ROOT / "infrastructure" / "nginx-veyrs-web.conf"
    assert re.search(r"listen\s+80\s+default_server", docs.read_text()), \
        "the docs vhost must stay the default server: unclaimed host names land there"
    assert _server_names(docs) == {"_"}
    assert "veyrs-web.example.com" in _server_names(web)
    assert "root /var/www/veyrs;" in docs.read_text()
    assert "root /var/www/veyrs-web;" in web.read_text()


def test_no_host_name_is_claimed_by_two_vhosts():
    seen: dict[str, str] = {}
    for p in sorted((ROOT / "infrastructure").glob("nginx-veyrs-*.conf")):
        for n in _server_names(p) - {"_"}:
            assert n not in seen, f"{n} is in both {seen[n]} and {p.name}"
            seen[n] = p.name


# --------------------------------------------------------------------------
# TD-09: a fresh install serves the brand assets
# --------------------------------------------------------------------------
def test_installer_copies_the_tokens_and_brand_files_under_static():
    assert 'frontend/brand/veyrs-tokens.css" "$CONSOLE_DIR/static/"' in INSTALL
    assert "frontend/brand/logo/*.png" in INSTALL
    assert re.search(r"location /static/ \{\s*expires 1h;", _install_vhost())


def test_every_asset_the_console_html_loads_from_static_exists_in_the_brand_dir():
    html = (ROOT / "frontend" / "console" / "index.html").read_text()
    brand = ROOT / "frontend" / "brand"
    refs = set(re.findall(r'(?:href|src)="/static/([^"?]+)', html))
    assert "veyrs-tokens.css" in refs
    for ref in refs:
        assert (brand / ref).is_file() or (brand / "logo" / ref).is_file(), \
            f"/static/{ref} is loaded by the console but not shipped in frontend/brand"


# --------------------------------------------------------------------------
# R-06: the API runs unprivileged, the updater stays root
# --------------------------------------------------------------------------
def _unit(name: str) -> str:
    return (ROOT / "infrastructure" / "systemd" / name).read_text()


def test_api_unit_runs_as_the_service_account_with_no_capabilities():
    u = _unit("veyrs-api.service")
    assert re.search(r"(?m)^User=veyrs$", u) and re.search(r"(?m)^Group=veyrs$", u)
    assert not re.search(r"(?m)^User=root", u)
    assert re.search(r"(?m)^CapabilityBoundingSet=$", u)
    assert re.search(r"(?m)^RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX$", u)
    assert "ProtectSystem=strict" in u and "NoNewPrivileges=yes" in u


def test_updater_stays_a_separate_root_unit():
    assert re.search(r"(?m)^User=root$", _unit("veyrs-updater.service"))


def test_installer_creates_the_account_and_hands_over_exactly_var():
    assert "useradd --system" in INSTALL
    assert 'root:"$SERVICE_USER" "$VEYRS_DIR/.env"' in INSTALL and 'chmod 640 "$VEYRS_DIR/.env"' in INSTALL
    assert 'root:root "$VEYRS_DIR/var/backups"' in INSTALL
    assert 'install -d -m 770 -o root -g "$SERVICE_USER" "$UPD_SPOOL"' in INSTALL


def test_installer_no_longer_puts_the_test_database_in_the_production_env():
    env_block = INSTALL[INSTALL.index('cat > "$VEYRS_DIR/.env"'):INSTALL.index("ENVEOF\n        chmod 600")]
    assert "VEYRS_TEST_DATABASE_URL" not in env_block
    assert ".env.test" in INSTALL


def test_migration_script_is_idempotent_and_documents_its_rollback():
    path = ROOT / "scripts" / "migrate-service-user.sh"
    subprocess.run(["bash", "-n", str(path)], check=True)
    sh = path.read_text()
    assert "--rollback" in sh and "ROLLBACK" in sh and "do_rollback" in sh
    assert "id -u" in sh                      # account creation is conditional
    assert "grep -q '^User=root'" in sh        # backup only when there is something to change


# --------------------------------------------------------------------------
# R-19 / R-28: container stack
# --------------------------------------------------------------------------
COMPOSE = (ROOT / "docker" / "compose.yaml").read_text()


def test_container_stack_defaults_to_production():
    assert "VEYRS_ENVIRONMENT: ${VEYRS_ENVIRONMENT:-production}" in COMPOSE
    assert "VEYRS_ENVIRONMENT:-development" not in COMPOSE


def test_container_stack_redis_requires_a_password():
    assert "--requirepass" in COMPOSE
    assert "VEYRS_REDIS_URL: redis://:${VEYRS_REDIS_PASSWORD:?" in COMPOSE
    assert "REDISCLI_AUTH" in COMPOSE
    assert re.search(r"(?m)^VEYRS_REDIS_PASSWORD=$", (ROOT / "docker" / "env.example").read_text())
    for script in ("docker/veyrs-docker.sh", "veyrs-setup.sh"):
        assert "VEYRS_REDIS_PASSWORD" in (ROOT / script).read_text(), script


# --------------------------------------------------------------------------
# R-22 / TD-41: the suite never touches production configuration
# --------------------------------------------------------------------------
def _redis_guard():
    """The guard function, compiled from conftest source (importing conftest again would re-run it)."""
    src = (ROOT / "tests" / "conftest.py").read_text()
    start = src.index("def _assert_is_test_redis")
    end = src.index("\n\n\n_default = ", start)
    ns: dict = {"os": os, "urlsplit": urlsplit}
    exec(src[start:end], ns)  # noqa: S102 - our own source
    return ns["_assert_is_test_redis"]


@pytest.mark.parametrize("url", ["redis://127.0.0.1:6379/0", "redis://:pw@198.19.1.1:6379", ""])
def test_conftest_refuses_a_redis_that_could_be_production(url, monkeypatch):
    monkeypatch.delenv("VEYRS_REDIS_URL", raising=False)
    with pytest.raises(RuntimeError):
        _redis_guard()(url)


def test_conftest_accepts_a_test_redis_and_refuses_a_mismatching_app_url(monkeypatch):
    guard = _redis_guard()
    monkeypatch.delenv("VEYRS_REDIS_URL", raising=False)
    guard("redis://127.0.0.1:6379/15")
    monkeypatch.setenv("VEYRS_REDIS_URL", "redis://127.0.0.1:6379/15")
    guard("redis://127.0.0.1:6379/15")
    monkeypatch.setenv("VEYRS_REDIS_URL", "redis://prod.example.com:6379/1")
    with pytest.raises(RuntimeError, match="differs"):
        guard("redis://127.0.0.1:6379/15")


def test_test_script_loads_env_test_after_env_and_points_redis_at_a_test_url():
    sh = (ROOT / "scripts" / "test.sh").read_text()
    assert sh.index(". ./.env\n") < sh.index(". ./.env.test")
    assert 'VEYRS_TEST_REDIS_URL="${VEYRS_TEST_REDIS_URL:-redis://127.0.0.1:6379/15}"' in sh
    assert 'export VEYRS_REDIS_URL="$VEYRS_TEST_REDIS_URL"' in sh
    assert re.search(r"(?m)^\.env\.test$", (ROOT / ".gitignore").read_text())


def test_the_application_never_reads_the_test_settings():
    for py in (ROOT / "backend" / "veyrs").rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        assert "TEST_DATABASE_URL" not in text and "TEST_REDIS_URL" not in text, py


# --------------------------------------------------------------------------
# TD-34: the data-section check in backup.sh
# --------------------------------------------------------------------------
TOC_OK = """\
200; 1259 16400 TABLE public assets veyrs
201; 1259 16410 TABLE public findings veyrs
300; 0 16400 TABLE DATA public assets veyrs
301; 0 16410 TABLE DATA public findings veyrs
"""
TOC_SHORT = TOC_OK.replace("301; 0 16410 TABLE DATA public findings veyrs\n", "")


def _count(toc: str, data: bool) -> int:
    sh = (ROOT / "scripts" / "backup.sh").read_text()
    awk = re.search(r"N_%s=\$\(awk '([^']+)'" % ("DATA" if data else "TABLES"), sh)
    assert awk, "backup.sh lost its table/data count"
    out = subprocess.run(["awk", awk.group(1)], input=toc, capture_output=True, text=True, check=True).stdout
    return len(out.splitlines())


def test_backup_counts_tables_and_data_sections_from_the_toc():
    assert (_count(TOC_OK, False), _count(TOC_OK, True)) == (2, 2)
    assert (_count(TOC_SHORT, False), _count(TOC_SHORT, True)) == (2, 1)
    sh = (ROOT / "scripts" / "backup.sh").read_text()
    assert '[ "$N_DATA" -lt "$N_TABLES" ]' in sh


def test_backup_timers_are_installable_by_the_installer():
    assert "--with-backup-timers" in INSTALL
    for unit in ("veyrs-pgdump", "veyrs-pgverify", "veyrs-replcheck"):
        assert unit in INSTALL
        svc = (ROOT / "infrastructure" / "backup" / f"{unit}.service").read_text()
        assert re.search(r"(?m)^OnFailure=veyrs-alert@%n\.service$", svc), unit
    assert (ROOT / "infrastructure" / "backup" / "veyrs-alert@.service").is_file()


# --------------------------------------------------------------------------
# TD-43: atomic publish
# --------------------------------------------------------------------------
def _atomic_swap():
    sys.path.insert(0, str(ROOT / "site"))
    try:
        import atomic_swap
    finally:
        sys.path.pop(0)
    return atomic_swap


def test_atomic_swap_replaces_the_tree_and_keeps_one_previous_generation(tmp_path):
    atomic_swap = _atomic_swap()
    live, new = tmp_path / "live", tmp_path / "live.new"
    live.mkdir()
    (live / "index.html").write_text("old")
    new.mkdir()
    (new / "index.html").write_text("new")
    (new / "extra.html").write_text("x")
    atomic_swap.swap(str(new), str(live))
    assert (live / "index.html").read_text() == "new" and (live / "extra.html").exists()
    assert (tmp_path / "live.prev" / "index.html").read_text() == "old"
    assert not new.exists()
    # a second publish replaces .prev, never accumulates
    n2 = tmp_path / "live.new2"
    n2.mkdir()
    (n2 / "index.html").write_text("newer")
    atomic_swap.swap(str(n2), str(live))
    assert (tmp_path / "live.prev" / "index.html").read_text() == "new"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["live", "live.prev"]


def test_atomic_swap_first_publish(tmp_path):
    atomic_swap = _atomic_swap()
    new = tmp_path / "x.new"
    new.mkdir()
    (new / "a").write_text("1")
    atomic_swap.swap(str(new), str(tmp_path / "x"))
    assert (tmp_path / "x" / "a").read_text() == "1"


def test_build_py_publishes_through_the_swap_not_in_place():
    src = (ROOT / "site" / "build.py").read_text()
    assert "atomic_swap.swap(tmp, out)" in src


def test_publish_script_builds_all_three_trees_and_reports_fingerprints():
    sh = ROOT / "scripts" / "publish-sites.sh"
    subprocess.run(["bash", "-n", str(sh)], check=True)
    text = sh.read_text()
    for needle in ("site/build.py", "site/web/build_web.py", "frontend/console", "fingerprint", "atomic_swap.py"):
        assert needle in text, needle


# --------------------------------------------------------------------------
# TD-58: path:line references in the documentation
# --------------------------------------------------------------------------
CHECKER = ROOT / "scripts" / "check-docs-refs.py"


def _check(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CHECKER), "--root", str(root), *extra],
                          capture_output=True, text=True)


def test_docs_refs_checker_flags_missing_files_and_out_of_range_lines(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "mod.py").write_text("def alpha():\n    pass\n\n\ndef beta():\n    pass\n")
    (tmp_path / "docs" / "good.md").write_text("See `backend/mod.py:1-2` and `mod.py:5`.\n")
    assert _check(tmp_path).returncode == 0
    (tmp_path / "docs" / "bad.md").write_text(
        "Gone: `backend/nope.py:3`. Too far: `backend/mod.py:99`.\n")
    r = _check(tmp_path)
    assert r.returncode == 1
    assert "no such file" in r.stdout and "outside the file (6 lines)" in r.stdout
    # the ratchet: recorded rot passes, new rot fails
    base = tmp_path / "baseline.txt"
    assert _check(tmp_path, "--write-baseline", str(base)).returncode == 0
    assert _check(tmp_path, "--baseline", str(base)).returncode == 0
    (tmp_path / "docs" / "worse.md").write_text("`backend/mod.py:500`\n")
    assert _check(tmp_path, "--baseline", str(base)).returncode == 1


def test_docs_refs_checker_reports_symbol_drift_without_failing(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "mod.py").write_text("\n".join(f"x{i} = {i}" for i in range(80)) + "\n\ndef late():\n    pass\n")
    (tmp_path / "docs" / "d.md").write_text("`late()` is at `backend/mod.py:2`.\n")
    r = _check(tmp_path)
    assert r.returncode == 0 and "WARN" in r.stdout and "drift" in r.stdout


def test_documentation_references_do_not_rot_further():
    r = _check(ROOT, "--baseline", str(ROOT / "tests" / "docs_refs_baseline.txt"))
    assert r.returncode == 0, "new broken path:line references in the docs:\n" + r.stdout[-3000:]


# --------------------------------------------------------------------------
# TD-42 / TD-44 / R-02: smaller items
# --------------------------------------------------------------------------
def test_install_md_copies_the_console_directory_whole():
    text = (ROOT / "INSTALL.md").read_text()
    assert text.count("cp -a frontend/console/.") >= 2          # install section and upgrade section
    assert "install -m 644 frontend/console/app.js" not in text  # the three-file copy that dropped fonts/


def test_the_export_script_does_not_claim_a_dirty_history():
    sh = (ROOT / "scripts" / "public-export.sh").read_text()
    assert "carries a plaintext administrator password and a full production database dump" not in sh


def test_ci_entrypoint_exists_and_coverage_config_is_optional():
    assert (ROOT / "scripts" / "ci.sh").is_file()
    cov = (ROOT / ".coveragerc").read_text()
    assert "source" in cov and "veyrs" in cov
    # coverage is on demand: it must not be a runtime requirement
    assert "pytest-cov" not in (ROOT / "requirements.txt").read_text().lower()
