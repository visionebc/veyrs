"""The worked example in DOCKER_COMPOSE_MANUAL.md §5.D stays true to the files.

§5.D prints two things a reader copies verbatim: the whole `docker/compose.yaml`
and the complete `docker/.env`. A copy in a manual is the version that drifts,
because nobody runs it. These guards fail the moment either one stops matching
what ships.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANUAL = REPO / "docs" / "DOCKER_COMPOSE_MANUAL.md"
COMPOSE = REPO / "docker" / "compose.yaml"
ENV_EXAMPLE = REPO / "docker" / "env.example"

SECRETS = ("POSTGRES_PASSWORD", "VEYRS_DB_PASSWORD", "VEYRS_SECRET_KEY",
           "VEYRS_ENCRYPTION_KEY", "VEYRS_ADMIN_PASSWORD")


def _section() -> str:
    text = MANUAL.read_text()
    start = text.index("### 5.D Worked example")
    end = text.index("\n## 6. Configuration reference", start)
    return text[start:end]


def _fence_after(text: str, marker: str, lang: str) -> str:
    """The body of the first ```lang fence after `marker`."""
    at = text.index(marker)
    m = re.compile(rf"^```{lang}\n(.*?)^```$", re.S | re.M).search(text, at)
    assert m, f"no ```{lang} block after {marker!r}"
    return m.group(1)


def test_section_exists_and_is_linked() -> None:
    text = MANUAL.read_text()
    assert "### 5.D Worked example" in text
    # Reachable from the quick start and from the §5 introduction.
    assert text.count("§5.D") >= 2


def test_embedded_compose_yaml_is_byte_identical() -> None:
    embedded = _fence_after(_section(), "#### The complete `docker/compose.yaml`", "yaml")
    assert embedded == COMPOSE.read_text(), (
        "§5.D's copy of docker/compose.yaml differs from the file: re-embed it")


def _env_listing() -> dict[str, str]:
    body = _fence_after(_section(), "This is the complete file without its comments", "ini")
    pairs = {}
    for line in body.splitlines():
        if line.strip():
            key, _, value = line.partition("=")
            pairs[key] = value
    return pairs


def test_env_listing_has_every_variable_of_the_template() -> None:
    template = {line.split("=", 1)[0] for line in ENV_EXAMPLE.read_text().splitlines()
                if re.match(r"^[A-Z_]+=", line)}
    missing = template - set(_env_listing())
    assert not missing, f"§5.D's .env listing lacks {sorted(missing)}"


def test_env_listing_shows_placeholders_not_secrets() -> None:
    listing = _env_listing()
    for key in SECRETS:
        assert listing[key].startswith("<"), (
            f"{key} in §5.D must be a <placeholder>, not a value that looks real")
