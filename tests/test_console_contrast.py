"""TD-40: the console's two themes must keep WCAG AA contrast (4.5:1 for text).

`docs/design/accessibility.md` once recorded `--text-muted` at 3.3 to 4.3:1 and
light-theme pills at 3.2 to 4.3:1, computed by hand. This guard computes the
same ratios from the token values in `console.css` (plus the shared
`veyrs-tokens.css` for the colours console.css does not redefine), so a colour
edit that breaks AA fails here instead of in an audit.

Method: WCAG 2.x relative luminance. A tinted pill is its text colour over a
fill of `p x colour + (1 - p) x surface`, with `p` and the dark-theme text
mixes read from the stylesheet rules themselves, so the numbers stay tied to
what the browser draws.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "frontend" / "console" / "console.css").read_text(encoding="utf-8")
TOKENS = (ROOT / "site" / "static" / "veyrs-tokens.css").read_text(encoding="utf-8")

AA = 4.5


def _block(text: str, header: str) -> str:
    """The body of the first `header { ... }` rule (no nesting in token blocks)."""
    i = text.index(header)
    start = text.index("{", i)
    return text[start + 1:text.index("}", start)]


def _vars(body: str) -> dict[str, str]:
    return {m.group(1): m.group(2).strip() for m in re.finditer(r"(--[\w-]+)\s*:\s*([^;]+);", body)}


def _resolve(value: str, env: dict[str, str]) -> str:
    m = re.fullmatch(r"var\((--[\w-]+)\)", value)
    return _resolve(env[m.group(1)], env) if m else value


def theme(name: str) -> dict[str, tuple[float, float, float]]:
    env = _vars(_block(TOKENS, ":root"))
    if name == "dark":
        env.update(_vars(_block(TOKENS, '[data-theme="dark"]')))
        env.update(_vars(_block(CSS, ':root[data-theme="dark"]')))
    else:
        env.update(_vars(_block(CSS, '[data-theme="light"] {')))
    out = {}
    for key, value in env.items():
        value = _resolve(value, env)
        if re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
            out[key] = tuple(int(value[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return out


def lum(rgb) -> float:
    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b) -> float:
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def mix(fg, p: float, bg):
    return tuple(p * f + (1 - p) * b for f, b in zip(fg, bg))


THEMES = ["dark", "light"]

# (selector class, token the text uses, share of the tint in the fill)
def _tints() -> list[tuple[str, str, float]]:
    rules = []
    for m in re.finditer(r"^\.((?:sev|st|pill)-[\w-]+(?:,\s*\.(?:sev|st|pill)-[\w-]+)*)\s*\{([^}]*)\}", CSS, re.M):
        body = m.group(2)
        tint = re.search(r"background:\s*color-mix\(in srgb,\s*var\((--[\w-]+)\)\s*(\d+)%", body)
        text = re.search(r"(?<![-\w])color:\s*var\((--[\w-]+)\)", body)
        if tint and text and tint.group(1) == text.group(1):
            for sel in re.findall(r"(?:sev|st|pill)-[\w-]+", m.group(1)):
                rules.append((sel, tint.group(1), int(tint.group(2)) / 100))
    return rules


def _dark_text_overrides() -> dict[str, float]:
    """`[data-theme="dark"] .pill:is(.sev-critical, ...) { color: color-mix(... NN%, white) }`."""
    out = {}
    for m in re.finditer(r'\[data-theme="dark"\]\s*\.pill:is\(([^)]*)\)\s*\{\s*color:\s*color-mix\(in srgb,\s*var\(--[\w-]+\)\s*(\d+)%', CSS):
        for sel in re.findall(r"(?:sev|st|pill)-[\w-]+", m.group(1)):
            out[sel] = int(m.group(2)) / 100
    return out


def test_the_pill_rules_were_found():
    sels = {t[0] for t in _tints()}
    assert {"sev-critical", "sev-high", "sev-medium", "sev-low", "sev-informational",
            "st-remediated", "st-accepted_risk", "st-warn", "st-failed", "st-running", "pill-ai"} <= sels


@pytest.mark.parametrize("name", THEMES)
@pytest.mark.parametrize("fg", ["--text", "--text-secondary", "--text-muted", "--link"])
@pytest.mark.parametrize("bg", ["--background", "--surface", "--surface-2", "--surface-raised"])
def test_text_tokens_meet_AA(name, fg, bg):
    t = theme(name)
    r = ratio(t[fg], t[bg])
    assert r >= AA, f"{name}: {fg} on {bg} is {r:.2f}:1, below {AA}:1 (WCAG 1.4.3)"


@pytest.mark.parametrize("name", THEMES)
@pytest.mark.parametrize("bg", ["--primary", "--primary-hover"])
def test_primary_button_text_meets_AA(name, bg):
    t = theme(name)
    r = ratio(t["--primary-contrast"], t[bg])
    assert r >= AA, f"{name}: white on {bg} is {r:.2f}:1"


@pytest.mark.parametrize("name", THEMES)
@pytest.mark.parametrize("fill", ["--surface", "--surface-2"])
def test_every_tinted_pill_meets_AA(name, fill):
    t = theme(name)
    overrides = _dark_text_overrides() if name == "dark" else {}
    failures = []
    for sel, token, p in _tints():
        text = t[token]
        if sel in overrides:
            text = mix(text, overrides[sel], t["--veyrs-white"])
        r = ratio(text, mix(t[token], p, t[fill]))
        if r < AA:
            failures.append(f"{sel} {r:.2f}")
    assert not failures, f"{name} pills on {fill} below {AA}:1: {failures}"


@pytest.mark.parametrize("name", THEMES)
def test_known_exploited_pill_meets_AA(name):
    t = theme(name)
    solid = t["--veyrs-critical"]
    if name == "dark" and re.search(r'\[data-theme="dark"\]\s*\.pill-kev\s*\{[^}]*72%', CSS):
        solid = mix(t["--veyrs-critical"], 0.72, t["--veyrs-navy"])
    assert ratio(t["--veyrs-white"], solid) >= AA


def test_queued_and_cancelled_pills_are_styled():
    """Jobs show `st-queued` and `st-cancelled`; without a rule they render as bare text."""
    assert re.search(r"\.st-queued\b", CSS) and re.search(r"\.st-cancelled\b", CSS)
