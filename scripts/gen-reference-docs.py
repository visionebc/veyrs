#!/usr/bin/env python3
"""Generate the machine-derived reference documentation from the code.

Hand-written manuals explain; these files enumerate. They are generated
because an enumeration written by hand drifts silently (docs/DATABASE.md once
claimed 67 tables while the models carried 87) - see gen-schema-doc.py, which
does the same for the table reference.

    python3 scripts/gen-reference-docs.py            # (re)write every file below
    python3 scripts/gen-reference-docs.py --check    # exit 1 if a CODE-DERIVED file is stale

Code-derived (guarded by --check, tests/test_docs_reference_is_current.py):

    docs/api/openapi.json               the OpenAPI document of create_app()
    docs/api/reference/README.md        endpoint index, authentication classes
    docs/api/reference/<tag>.md         every endpoint of one OpenAPI tag
    docs/reference/configuration.md     every Settings field / VEYRS_* variable
    docs/reference/permissions.md       resources x actions, built-in roles
    docs/reference/inventory.md         every repository file and what it is

Documentation-derived (rewritten by a normal run, checked for PRESENCE only):

    docs/reference/traceability.md      component -> docs -> tests matrix
    docs/reference/coverage.md          documentation coverage index

The last two measure the hand-written documents, so they change whenever a
manual changes. Byte-checking them would fail a test on every documentation
edit, which teaches people to regenerate without reading. They carry their
measurement date instead and are regenerated before each documentation commit.

Needs the project's Python environment (it imports veyrs) and, for the
inventory, a git checkout (`git ls-files --cached --others --exclude-standard`:
tracked plus not-yet-committed files, so the output is the same before and
after the commit that adds a file). No database connection is made.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# Importing the app needs these to exist; the values are never used to connect.
os.environ.setdefault("VEYRS_DATABASE_URL", "postgresql+psycopg://docs:docs@127.0.0.1:1/docs")
os.environ.setdefault("VEYRS_SECRET_KEY", "d" * 64)

DOCS = ROOT / "docs"
GEN = "scripts/gen-reference-docs.py"
VERIFIED = "2026-11-17"  # bumped by hand when the generator's output contract changes
# Front matter says `version: current`: the files are regenerated from whatever
# checkout runs the generator, and a version bump alone must not make a guarded
# file stale. The docs portal prints the checkout's version in its place.

SECRETISH = ("secret", "password", "token", "key", "dsn", "_url", "credential")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def front_matter(title, purpose, scope, sources, related, version):
    return "\n".join([
        "---",
        f"title: {title}",
        f"purpose: {purpose}",
        f"scope: {scope}",
        "version: current",
        f"verified: {VERIFIED}",
        "status: Verified",
        f"sources: [{', '.join(sources)}]",
        f"related: [{', '.join(related)}]",
        "---",
        "",
    ])


def generated_note(extra=""):
    note = (f"> [!NOTE]\n> GENERATED from the code by `{GEN}` - do not edit by hand. "
            f"Regenerate with `python3 {GEN}`.")
    if extra:
        note += "\n> " + extra
    return note + "\n"


def cell(text) -> str:
    """One Markdown table cell: single line, pipes escaped."""
    if text is None:
        return ""
    s = " ".join(str(text).split())
    return s.replace("|", "\\|")


def slug(text: str) -> str:
    """File-name slug for a tag page."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "untagged"


def anchor(text: str) -> str:
    """Heading anchor as GitHub, Gitea and the docs portal compute it."""
    t = re.sub(r"[`*]", "", text).strip().lower()
    return re.sub(r"[^\w\- ]", "", t).replace(" ", "-")


def first_paragraph(doc: str | None) -> str:
    if not doc:
        return ""
    return " ".join(doc.strip().split("\n\n")[0].split())


def version_of() -> str:
    from veyrs.config import Settings
    return Settings.model_fields["version"].default


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
def _dep_names(dependant):
    names, closures = set(), []
    stack = list(dependant.dependencies)
    while stack:
        d = stack.pop()
        call = d.call
        names.add(getattr(call, "__qualname__", repr(call)))
        for c in getattr(call, "__closure__", None) or ():
            try:
                closures.append(c.cell_contents)
            except ValueError:
                pass
        stack.extend(d.dependencies)
    perms = sorted({p for v in closures if isinstance(v, tuple) and v
                    and all(isinstance(x, str) for x in v) for p in v})
    return names, perms


def auth_class(names, params) -> str:
    joined = " ".join(names)
    if "get_agent" in joined or "agent_session" in joined:
        return "Agent credential"
    if "platform_admin" in joined:
        return "Platform admin"
    if "get_principal" in joined:
        return "Authenticated"
    if any(p.get("in") == "header" and p.get("name", "").lower() == "x-veyrs-signature" for p in params):
        return "Signed webhook"
    return "Public"


AUTH_EXPLAINED = [
    ("Public", "No credential. Reachable before sign-in (login, refresh, SSO, health)."),
    ("Authenticated", "`Authorization: Bearer <access token>` or `X-API-Key: veyrs_...`. "
     "Binds the caller's tenant (RLS) and applies its team scope. Permissions listed "
     "are additionally required; an empty list means any signed-in principal."),
    ("Platform admin", "Authenticated **and** a platform administrator user "
     "(`veyrs platform-admin`). Installation-wide pages, not one organization."),
    ("Agent credential", "A scan agent's own key, not a user token (`/agents/self/*`)."),
    ("Signed webhook", "No session; the body must carry a valid `X-VEYRS-Signature` "
     "HMAC-SHA256 made with the connector's inbound secret."),
]


class SchemaBook:
    """Resolves OpenAPI schemas into compact field tables."""

    def __init__(self, components):
        self.schemas = components.get("schemas", {})

    def type_of(self, s) -> str:
        if not s:
            return "any"
        if "$ref" in s:
            return "`" + s["$ref"].rsplit("/", 1)[-1] + "`"
        if "anyOf" in s or "oneOf" in s:
            parts = [self.type_of(x) for x in s.get("anyOf", s.get("oneOf", []))]
            nul = "null" in parts
            parts = [p for p in parts if p != "null"]
            t = " \\| ".join(dict.fromkeys(parts)) or "null"
            return t + (" (nullable)" if nul else "")
        if "allOf" in s:
            return " & ".join(self.type_of(x) for x in s["allOf"])
        t = s.get("type", "object")
        if t == "array":
            return f"array of {self.type_of(s.get('items', {}))}"
        if "enum" in s:
            return f"{t} enum"
        fmt = s.get("format")
        return f"{t} ({fmt})" if fmt else t

    @staticmethod
    def constraints(s) -> str:
        out = []
        for k, label in (("minLength", "min length"), ("maxLength", "max length"),
                         ("minimum", "≥"), ("maximum", "≤"), ("exclusiveMinimum", ">"),
                         ("exclusiveMaximum", "<"), ("pattern", "pattern"),
                         ("minItems", "min items"), ("maxItems", "max items")):
            for src in [s] + list(s.get("anyOf", [])):
                if k in src:
                    out.append(f"{label} {src[k]}" if label not in ("≥", "≤", ">", "<") else f"{label} {src[k]}")
                    break
        enum = s.get("enum") or next((x.get("enum") for x in s.get("anyOf", []) if x.get("enum")), None)
        if enum:
            out.append("one of " + ", ".join(f"`{e}`" for e in enum))
        if "default" in s and s["default"] not in (None, [], {}):
            out.append(f"default `{json.dumps(s['default'])}`")
        return "; ".join(out)

    def refs_in(self, s, seen=None):
        """Every schema name referenced (transitively) from s."""
        seen = set() if seen is None else seen
        if isinstance(s, dict):
            if "$ref" in s:
                name = s["$ref"].rsplit("/", 1)[-1]
                if name not in seen:
                    seen.add(name)
                    self.refs_in(self.schemas.get(name, {}), seen)
            for v in s.values():
                self.refs_in(v, seen)
        elif isinstance(s, list):
            for v in s:
                self.refs_in(v, seen)
        return seen

    def table(self, name) -> list[str]:
        s = self.schemas.get(name, {})
        props = s.get("properties", {})
        req = set(s.get("required", []))
        lines = [f"#### `{name}`", ""]
        desc = first_paragraph(s.get("description"))
        if desc:
            lines += [cell(desc), ""]
        if s.get("enum"):
            lines += ["Enumeration: " + ", ".join(f"`{e}`" for e in s["enum"]), ""]
            return lines
        if not props:
            lines += [f"Type: {self.type_of(s)}" + ("" if s.get("type") != "object" else " (free-form)"), ""]
            return lines
        lines += ["| Field | Type | Required | Constraints | Description |", "|---|---|---|---|---|"]
        for fname in props:
            p = props[fname]
            lines.append(f"| `{fname}` | {self.type_of(p)} | {'yes' if fname in req else 'no'} | "
                         f"{cell(self.constraints(p))} | {cell(p.get('description', ''))} |")
        lines.append("")
        return lines


def collect_routes(app):
    """[(path, method, route, auth, perms)] for every documented HTTP route."""
    out = []
    spec_paths = app.openapi()["paths"]
    for r in app.routes:
        if not hasattr(r, "methods") or not getattr(r, "include_in_schema", True):
            continue
        if r.path not in spec_paths:
            continue
        names, perms = _dep_names(r.dependant)
        for m in sorted(r.methods - {"HEAD"}):
            op = spec_paths[r.path].get(m.lower())
            if op is None:
                continue
            out.append((r.path, m, r, op, auth_class(names, op.get("parameters", [])), perms))
    return out


def source_of(fn) -> str:
    import inspect
    try:
        path = Path(inspect.getsourcefile(fn)).resolve().relative_to(ROOT)
        return f"{path}:{inspect.getsourcelines(fn)[1]}"
    except (TypeError, OSError, ValueError):
        return ""


def gen_api(version) -> dict[str, str]:
    from veyrs.main import create_app
    app = create_app()
    spec = app.openapi()
    book = SchemaBook(spec.get("components", {}))
    files: dict[str, str] = {}
    # The version is normalised so a version bump alone does not make the
    # guarded copy stale; the live /api/v1/openapi.json carries the real one.
    spec = json.loads(json.dumps(spec))
    spec["info"]["version"] = "current"
    files["docs/api/openapi.json"] = json.dumps(spec, indent=1, sort_keys=True, ensure_ascii=False) + "\n"

    by_tag: dict[str, list] = defaultdict(list)
    for item in collect_routes(app):
        op = item[3]
        tag = (op.get("tags") or ["untagged"])[0]
        by_tag[tag].append(item)

    index_rows = []
    auth_counts: dict[str, int] = defaultdict(int)
    for tag in sorted(by_tag):
        items = sorted(by_tag[tag], key=lambda x: (x[0], x[1]))
        tslug = slug(tag)
        title = f"API reference: {tag}"
        lines = [front_matter(
            title, f"Every HTTP endpoint tagged `{tag}`, generated from the running application's routes.",
            "Method, path, authentication, permissions, parameters, request and response schemas. "
            "Behaviour is explained in the functional docs.",
            [GEN, "backend/veyrs/main.py", "backend/veyrs/api/v1"], ["api/reference/README.md", "API.md"], version),
            f"# {title}", "", generated_note(), ""]
        lines += [f"{len(items)} operations. Authentication classes are explained in the "
                  "[reference index](README.md#authentication-classes).", ""]
        lines += ["| Method | Path | Summary | Auth | Permissions |", "|---|---|---|---|---|"]
        for path, m, r, op, auth, perms in items:
            lines.append(f"| `{m}` | [`{path}`](#{anchor(m + ' ' + path)}) | {cell(op.get('summary', ''))} | {auth} | "
                         f"{cell(', '.join(f'`{p}`' for p in perms)) or '-'} |")
        lines.append("")
        used_schemas: set[str] = set()
        for path, m, r, op, auth, perms in items:
            auth_counts[auth] += 1
            index_rows.append((tag, tslug, m, path, auth))
            lines += [f"## {m} {path}", ""]
            if op.get("summary"):
                lines += [f"**{cell(op['summary'])}**", ""]
            desc = (op.get("description") or "").strip()
            if desc and desc != op.get("summary"):
                # Docstrings are prose; keep paragraphs, flatten wrapping.
                for para in desc.split("\n\n"):
                    p = " ".join(para.split())
                    if p:
                        lines += [p, ""]
            meta = [("Authentication", auth),
                    ("Permissions", ", ".join(f"`{p}`" for p in perms) or "none beyond authentication"
                     if auth in ("Authenticated", "Platform admin") else "-"),
                    ("Success status", str(r.status_code or 200)),
                    ("Handler", f"`{source_of(r.endpoint)}`")]
            lines += ["| | |", "|---|---|"] + [f"| {k} | {cell(v)} |" for k, v in meta] + [""]
            # X-API-Key is the alternative credential of every authenticated route
            # (explained once in the index); listing it 300 times is noise.
            params = [p for p in op.get("parameters", [])
                      if not (p.get("in") == "header" and p.get("name") == "X-API-Key")]
            if params:
                lines += ["**Parameters**", "", "| Name | In | Type | Required | Constraints | Description |",
                          "|---|---|---|---|---|---|"]
                for p in params:
                    s = p.get("schema", {})
                    lines.append(f"| `{p['name']}` | {p['in']} | {book.type_of(s)} | "
                                 f"{'yes' if p.get('required') else 'no'} | {cell(book.constraints(s))} | "
                                 f"{cell(p.get('description', ''))} |")
                lines.append("")
            body = op.get("requestBody")
            if body:
                for ctype, content in sorted(body.get("content", {}).items()):
                    sch = content.get("schema", {})
                    lines += [f"**Request body** (`{ctype}`{', required' if body.get('required') else ''}): "
                              f"{book.type_of(sch)}", ""]
                    used_schemas |= book.refs_in(sch)
            resp = op.get("responses", {})
            if resp:
                lines += ["**Responses**", "", "| Status | Meaning | Body |", "|---|---|---|"]
                for code in sorted(resp):
                    rr = resp[code]
                    sch = rr.get("content", {}).get("application/json", {}).get("schema")
                    used_schemas |= book.refs_in(sch or {})
                    other = [c for c in rr.get("content", {}) if c != "application/json"]
                    body_t = book.type_of(sch) if sch else (", ".join(f"`{c}`" for c in other) or "-")
                    lines.append(f"| `{code}` | {cell(rr.get('description', ''))} | {body_t} |")
                if auth != "Public" and "401" not in resp:
                    lines.append("| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |")
                if perms and "403" not in resp:
                    lines.append("| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |")
                lines.append("")
        if used_schemas:
            lines += ["## Schemas", "", "Request and response models used on this page.", ""]
            for name in sorted(used_schemas):
                lines += book.table(name)
        files[f"docs/api/reference/{tslug}.md"] = "\n".join(lines).rstrip() + "\n"

    # index
    lines = [front_matter(
        "API reference", "Index of every HTTP operation VEYRS exposes, generated from the application.",
        "Machine-derived endpoint catalogue. Conventions, examples and error handling are in the API guide.",
        [GEN, "backend/veyrs/main.py", "backend/veyrs/security/deps.py"], ["API.md", "reference/permissions.md"], version),
        "# API reference", "", generated_note(), ""]
    lines += [f"**{len(index_rows)} operations** on **{len({r[3] for r in index_rows})} paths** in "
              f"**{len(by_tag)} tags**. The OpenAPI document is "
              "[openapi.json](../openapi.json) (also served live at `/api/v1/openapi.json`).", ""]
    lines += ["## Authentication classes", "", "| Class | Operations | Meaning |", "|---|---|---|"]
    for name, meaning in AUTH_EXPLAINED:
        lines.append(f"| {name} | {auth_counts.get(name, 0)} | {meaning} |")
    lines += ["", "> [!IMPORTANT]",
              "> Permissions are read from each route's `require(...)` dependency. A few handlers "
              "check permissions inside the function body as well (for example per-report "
              "permissions); those checks are not visible here - read the handler.", ""]
    lines += ["## Tags", "", "| Tag | Operations | Page |", "|---|---|---|"]
    for tag in sorted(by_tag):
        lines.append(f"| {cell(tag)} | {len(by_tag[tag])} | [{slug(tag)}.md]({slug(tag)}.md) |")
    lines += ["", "## Every operation", "", "| Method | Path | Tag | Auth |", "|---|---|---|---|"]
    for tag, tslug, m, path, auth in sorted(index_rows, key=lambda x: (x[3], x[2])):
        lines.append(f"| `{m}` | [`{path}`]({tslug}.md#{anchor(m + ' ' + path)}) | {cell(tag)} | {auth} |")
    files["docs/api/reference/README.md"] = "\n".join(lines).rstrip() + "\n"
    return files


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
def _config_comments() -> dict[str, str]:
    """`#:` comment blocks directly above each field in config.py."""
    src = (ROOT / "backend/veyrs/config.py").read_text(encoding="utf-8").splitlines()
    out, buf, section = {}, [], ""
    for line in src:
        s = line.strip()
        if s.startswith("# ---"):
            section = s.lstrip("# -").strip()
            buf = []
            continue
        if s.startswith("#:"):
            buf.append(s[2:].strip())
            continue
        m = re.match(r"^\s{4}([a-z_][a-z0-9_]*)\s*:", line)
        if m:
            out[m.group(1)] = (" ".join(buf), section)
            buf = []
        elif not s.startswith("#"):
            buf = []
    return out


def _usages(name) -> list[str]:
    pat = re.compile(r"\bsettings\(\)\." + name + r"\b|\bsettings\." + name + r"\b|\bs\." + name + r"\b|"
                     r"get_settings\(\)\." + name + r"\b|\bcfg\." + name + r"\b")
    hits = []
    for p in sorted((ROOT / "backend/veyrs").rglob("*.py")):
        if p.name == "config.py":
            continue
        if pat.search(p.read_text(encoding="utf-8")):
            hits.append(str(p.relative_to(ROOT / "backend")))
    return hits


def gen_configuration(version) -> dict[str, str]:
    from veyrs.config import Settings
    comments = _config_comments()
    prefix = Settings.model_config.get("env_prefix", "")
    rows_by_section: dict[str, list[str]] = defaultdict(list)
    order: list[str] = []
    for name, f in Settings.model_fields.items():
        desc, section = comments.get(name, ("", "other"))
        desc = f.description or desc
        d = f.default
        # Choices (Literal), numbers and booleans are never secrets, whatever the name.
        plain = isinstance(d, (bool, int, float)) or "Literal" in str(f.annotation)
        secret = not plain and any(k in name for k in SECRETISH) and d not in (None, "")
        if name == "version":
            dflt = "the release version (kept equal to `pyproject.toml`)"
        elif secret:
            dflt = "*(redacted)*"
        elif d in (None, ""):
            dflt = "empty"
        elif isinstance(d, (str, int, float, bool)):
            dflt = f"`{d}`"
        else:
            dflt = f"`{d!r}`" if not callable(d) else "computed"
        t = str(f.annotation).replace("typing.", "").replace("<class '", "").replace("'>", "")
        used = _usages(name)
        if section not in order:
            order.append(section)
        rows_by_section[section].append(
            f"| `{(prefix + name).upper()}` | `{cell(t)}` | {cell(dflt)} | {cell(desc) or '-'} | "
            f"{cell(', '.join(f'`{u}`' for u in used)) or '-'} |")
    n = len(Settings.model_fields)
    lines = [front_matter(
        "Configuration reference", "Every environment variable the VEYRS process reads, generated from `Settings`.",
        "Names, types, defaults and the modules that read each value. How to choose values is in the "
        "deployment and system manuals.",
        [GEN, "backend/veyrs/config.py"], ["SYSTEM_MANUAL.md", "DEPLOYMENT.md", "DOCKER_COMPOSE_MANUAL.md"], version),
        "# Configuration reference", "", generated_note(), "",
        f"**{n} settings.** Each is read from the environment as `VEYRS_<NAME>` (case-insensitive) "
        "or from a `.env` file in the working directory; unknown variables are ignored "
        "(`extra=\"ignore\"`). Secret-like defaults are shown as *(redacted)*. "
        "\"Read by\" lists the backend modules that reference the setting by name "
        "(a static scan: a value read through another name is missed).", "",
        "> [!WARNING]",
        "> `VEYRS_SECRET_KEY` and `VEYRS_ENCRYPTION_KEY` have no usable default: production refuses to "
        "start without them, and losing the encryption key makes stored third-party credentials unreadable.", ""]
    for section in order:
        lines += [f"## {section[:1].upper() + section[1:] if section else 'Other'}", "",
                  "| Variable | Type | Default | Description | Read by |", "|---|---|---|---|---|"]
        lines += rows_by_section[section] + [""]
    return {"docs/reference/configuration.md": "\n".join(lines).rstrip() + "\n"}


# --------------------------------------------------------------------------
# permissions
# --------------------------------------------------------------------------
def gen_permissions(version) -> dict[str, str]:
    from veyrs.security import permissions as P
    roles = P.BUILTIN_ROLES
    lines = [front_matter(
        "Permissions and built-in roles", "The RBAC vocabulary and what each built-in role grants, generated from the code.",
        "Permission strings, wildcard expansion and the role matrix. Team scope (row filtering) is in the security docs.",
        [GEN, "backend/veyrs/security/permissions.py"], ["SECURITY.md", "api/reference/README.md"], version),
        "# Permissions and built-in roles", "", generated_note(), "",
        f"A permission is `<resource>:<action>`. **{len(P.RESOURCES)} resources** × "
        f"**{len(P.ACTIONS)} actions** = {len(P.ALL_PERMISSIONS)} permissions, plus the wildcard "
        f"`{P.WILDCARD}`. Routes declare what they need with `require(\"resource:action\")`; an "
        "unknown string raises at import time (`backend/veyrs/security/deps.py`).", "",
        "## Resources", "", "| Resource | Permissions |", "|---|---|"]
    for r in P.RESOURCES:
        lines.append(f"| `{r}` | " + ", ".join(f"`{r}:{a}`" for a in P.ACTIONS) + " |")
    lines += ["", "## Built-in roles", "", "| Slug | Name | Description | Grants |", "|---|---|---|---|"]
    for slug_, role in roles.items():
        grants = role["permissions"]
        lines.append(f"| `{slug_}` | {cell(role['name'])} | {cell(role.get('description', ''))} | {len(P.expand(grants)) if grants != [P.WILDCARD] else 'all'} |")
    lines += ["", "## Role × permission matrix", "",
              "`✓` = granted (after wildcard expansion). Columns are the built-in role slugs.", ""]
    head = "| Permission | " + " | ".join(f"`{s}`" for s in roles) + " |"
    lines += [head, "|---|" + "---|" * len(roles)]
    expanded = {s: P.expand(r["permissions"]) for s, r in roles.items()}
    for perm in sorted(P.ALL_PERMISSIONS):
        lines.append(f"| `{perm}` | " + " | ".join("✓" if perm in expanded[s] else "" for s in roles) + " |")
    return {"docs/reference/permissions.md": "\n".join(lines).rstrip() + "\n"}


# --------------------------------------------------------------------------
# inventory
# --------------------------------------------------------------------------
def repo_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"the inventory needs a git checkout: {exc}")
    files = sorted({f for f in out.splitlines() if f and (ROOT / f).exists()})
    return files


def py_doc(path: Path) -> str:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return ""
    return first_paragraph(ast.get_docstring(tree))[:200]


def file_purpose(rel: str) -> str:
    p = ROOT / rel
    if rel.endswith(".py"):
        return py_doc(p)
    if rel.endswith((".sh", ".service", ".timer", ".path", ".conf", ".yaml", ".yml", ".toml", ".ini")) or "Dockerfile" in rel:
        try:
            for line in p.read_text(encoding="utf-8").splitlines()[:12]:
                s = line.strip()
                if s.startswith("Description="):
                    return s.split("=", 1)[1]
                if s.startswith("#") and not s.startswith("#!") and len(s) > 3 and not set(s) <= set("#-= "):
                    return s.lstrip("# ").strip()[:200]
        except UnicodeDecodeError:
            return ""
    if rel.endswith(".md"):
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.startswith("# "):
                    return line[2:].strip()
        except UnicodeDecodeError:
            pass
    return ""


AREAS = [
    ("backend/veyrs/api", "API routers"), ("backend/veyrs/services", "Services (business logic)"),
    ("backend/veyrs/models", "Models (schema)"), ("backend/veyrs/security", "Security"),
    ("backend/veyrs/engines", "Engines"), ("backend/veyrs/intel", "Intelligence feeds"),
    ("backend/veyrs", "Backend core"), ("backend", "Backend other"),
    ("frontend/console", "Console (web UI)"), ("frontend", "Frontend other"),
    ("integrations", "Integrations and agent"), ("infrastructure", "Infrastructure (systemd, nginx, backup)"),
    ("docker", "Container deployment"), ("scripts", "Scripts"), ("site", "Site builders"),
    ("tests", "Tests"), ("migrations", "Migrations placeholder"), ("release", "Release signing"),
    ("var", "Runtime directory"), ("", "Repository root"),
]


def area_of(rel: str) -> str:
    for prefix, name in AREAS:
        if prefix == "" or rel.startswith(prefix + "/"):
            return name
    return "Repository root"


def cli_commands() -> list[tuple[str, str]]:
    import argparse as ap
    from veyrs import cli
    captured = []
    real = ap.ArgumentParser.parse_args

    def grab(self, *a, **k):
        captured.append(self)
        raise SystemExit(0)

    ap.ArgumentParser.parse_args = grab
    try:
        try:
            cli.main([])
        except SystemExit:
            pass
        except TypeError:
            try:
                sys.argv = ["veyrs"]
                cli.main()
            except SystemExit:
                pass
    finally:
        ap.ArgumentParser.parse_args = real
    if not captured:
        return []
    out = []

    def walk(parser, prefix):
        for act in parser._actions:
            if isinstance(act, ap._SubParsersAction):
                helps = {c.dest: c.help for c in act._choices_actions}
                for name, sub in act.choices.items():
                    full = f"{prefix} {name}".strip()
                    nested = any(isinstance(a, ap._SubParsersAction) for a in sub._actions)
                    if nested:
                        walk(sub, full)
                    else:
                        out.append((full, helps.get(name) or ""))
    walk(captured[0], "")
    return sorted(out)


def gen_inventory(version) -> dict[str, str]:
    files = [f for f in repo_files() if not f.startswith("docs/")]
    by_area: dict[str, list[str]] = defaultdict(list)
    for f in files:
        by_area[area_of(f)].append(f)
    dirs = sorted({str(Path(f).parent) for f in files if str(Path(f).parent) != "."})
    from veyrs.main import create_app
    from veyrs.models import Base
    app = create_app()
    tags: dict[str, int] = defaultdict(int)
    for path, m, r, op, auth, perms in collect_routes(app):
        tags[(op.get("tags") or ["untagged"])[0]] += 1
    units = [f for f in files if f.endswith((".service", ".timer", ".path"))]
    lines = [front_matter(
        "Component inventory", "Every file in the repository (outside docs/) and what it is, generated from the checkout.",
        "Files, directories, CLI commands, shipped units, route and table counts. Sizes, test counts "
        "and documentation links are in the traceability matrix.",
        [GEN, "git ls-files"], ["reference/traceability.md", "reference/coverage.md", "ARCHITECTURE.md"], version),
        "# Component inventory", "", generated_note("Documentation files are not listed: the portal navigation is their index."), "",
        "## Totals", "", "| Item | Count |", "|---|---|",
        f"| Files (outside docs/) | {len(files)} |", f"| Directories | {len(dirs)} |",
        f"| HTTP operations (documented in OpenAPI) | {sum(tags.values())} |",
        f"| OpenAPI tags | {len(tags)} |", f"| Database tables | {len(Base.metadata.tables)} |",
        f"| Shipped systemd units | {len(units)} |", ""]
    cmds = cli_commands()
    lines += ["## CLI commands", "",
              "`python -m veyrs <command>` (with the venv and `.env` loaded). Source: `backend/veyrs/cli.py`"
              + (", `backend/veyrs/services/mfa_admin.py`." if any("mfa" in c for c, _ in cmds) else "."), "",
              "| Command | Purpose |", "|---|---|"]
    lines += [f"| `{c}` | {cell(h)} |" for c, h in cmds] + [""]
    lines += ["## Routes per tag", "", "| Tag | Operations |", "|---|---|"]
    lines += [f"| [{cell(t)}](../api/reference/{slug(t)}.md) | {n} |" for t, n in sorted(tags.items())] + [""]
    lines += ["## Shipped systemd units", "", "| Unit file | Description |", "|---|---|"]
    lines += [f"| `{u}` | {cell(file_purpose(u))} |" for u in units] + [""]
    lines += ["## Files by area", ""]
    for _prefix, area in AREAS:
        if area not in by_area:
            continue
        lines += [f"### {area}", "", f"{len(by_area[area])} files.", "", "| File | Purpose |", "|---|---|"]
        lines += [f"| `{f}` | {cell(file_purpose(f))} |" for f in by_area[area]] + [""]
    return {"docs/reference/inventory.md": "\n".join(lines).rstrip() + "\n"}


# --------------------------------------------------------------------------
# traceability + coverage (documentation-derived)
# --------------------------------------------------------------------------
GENERATED_DOCS = ("docs/api/reference/", "docs/reference/", "docs/DATABASE_SCHEMA.md", "docs/CHANGELOG.md",
                  "docs/api/openapi.json")


def handwritten_docs() -> dict[str, str]:
    out = {}
    for p in sorted(DOCS.rglob("*.md")):
        rel = str(p.relative_to(ROOT))
        if rel.startswith(GENERATED_DOCS) or "/rendered/" in rel:
            continue
        out[rel] = p.read_text(encoding="utf-8")
    return out


FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)
FM_KEYS = ("title", "purpose", "scope", "version", "verified", "status", "sources", "related")


def has_front_matter(text: str) -> bool:
    m = FM.match(text)
    if not m:
        return False
    keys = {ln.split(":", 1)[0].strip() for ln in m.group(1).splitlines() if ":" in ln}
    return all(k in keys for k in FM_KEYS)


def imports_of(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            base = node.module
            if node.level:
                pkg = ".".join(path.relative_to(ROOT / "backend").with_suffix("").parts[:-node.level])
                base = f"{pkg}.{base}" if base else pkg
            if base.startswith("veyrs"):
                mods.add(base)
        elif isinstance(node, ast.Import):
            mods |= {a.name for a in node.names if a.name.startswith("veyrs")}
    return sorted(mods)


def gen_traceability_and_coverage(version) -> dict[str, str]:
    docs = handwritten_docs()
    alltext = "\n".join(docs.values())
    tests = {str(p.relative_to(ROOT)): p.read_text(encoding="utf-8") for p in sorted((ROOT / "tests").glob("test_*.py"))}
    testtext = "\n".join(tests.values())
    modules = sorted(p for p in (ROOT / "backend/veyrs").rglob("*.py") if "__pycache__" not in p.parts)

    # Documents the public export leaves out (scripts/public-export.sh
    # EXCLUDE_GLOBS) still count for coverage, but are never linked from the
    # traceability table: the public tree would carry links to missing files.
    private = ("docs/internal/", "docs/IMPLEMENTATION_PLAN.md")

    def doc_hits(needles):
        return sorted({d for d, t in docs.items()
                       if not d.startswith(private) and any(n in t for n in needles)})

    rows, mod_documented, mod_tested = [], 0, 0
    for p in modules:
        rel = str(p.relative_to(ROOT))
        dotted = ".".join(p.relative_to(ROOT / "backend").with_suffix("").parts)
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]
        short = rel.split("backend/veyrs/", 1)[1]
        needles = [rel, short, dotted] if not short.endswith("__init__.py") else [dotted + "/", rel]
        dh = doc_hits(needles)
        parent, leaf = dotted.rsplit(".", 1) if "." in dotted else ("", dotted)
        tested = (dotted in testtext) or bool(re.search(rf"from {re.escape(parent)} import [^\n]*\b{re.escape(leaf)}\b", testtext))
        mod_documented += bool(dh)
        mod_tested += tested
        state = "Tested + documented" if tested and dh else "Tested" if tested else "Documented" if dh else "Neither"
        deps = [d.replace("veyrs.", "") for d in imports_of(p)]
        n_lines = len(p.read_text(encoding="utf-8").splitlines())
        rows.append(f"| `{short}` | {n_lines} | {cell(py_doc(p)[:120])} | {cell(', '.join(deps[:8]) + (' …' if len(deps) > 8 else ''))} | "
                    f"{cell(', '.join(f'[{Path(d).name}](../{d[5:]})' for d in dh[:4]) + (f' +{len(dh) - 4}' if len(dh) > 4 else '')) or '-'} | {state} |")

    # frontend/scripts/infra components
    other = []
    for rel in sorted(str(p.relative_to(ROOT)) for pat in ("frontend/console/*.js", "frontend/console/*.html",
                      "frontend/console/*.css", "scripts/*", "infrastructure/**/*", "docker/*", "site/*.py",
                      "site/web/*.py", "integrations/**/*.py", "install.sh", "veyrs-setup.sh")
                      for p in ROOT.glob(pat) if p.is_file() and "__pycache__" not in p.parts):
        name = Path(rel).name
        dh = doc_hits([rel, name])
        tested = rel in testtext or name in testtext
        state = "Tested + documented" if tested and dh else "Tested" if tested else "Documented" if dh else "Neither"
        other.append((rel, dh, state))

    test_counts = {t: len(re.findall(r"^\s*(?:async\s+)?def test_", s, flags=re.M)) for t, s in tests.items()}

    trace = [front_matter(
        "Traceability matrix", "Links every code component to the documents that describe it and the tests that exercise it.",
        "Backend modules, console files, scripts, infrastructure and site builders. Measured by text search, "
        "so it shows mentions, not quality.",
        [GEN], ["reference/coverage.md", "reference/inventory.md"], version),
        "# Traceability matrix", "",
        generated_note("Documentation-derived: rewritten by every run, not byte-checked by tests (it would fail on any doc edit)."), "",
        "**Method.** *Documentation* = hand-written docs (generated references excluded) that mention the "
        "module's repo path, its path under `backend/veyrs/`, or its dotted name. *Tested* = a test file "
        "mentions the dotted module name or imports it (`from veyrs.x import module`). A module "
        "exercised only indirectly (through the HTTP API) shows as not tested even when it is: treat "
        "*Neither* as \"look here first\", not as \"untested\".", "",
        "## Backend modules", "",
        f"{len(modules)} modules: {mod_documented} mentioned in documentation, {mod_tested} referenced by tests.", "",
        "| Module | Lines | Responsibility | Depends on (veyrs.*) | Documentation | State |",
        "|---|---|---|---|---|---|"] + rows + ["",
        "## Console, scripts, infrastructure and builders", "", "| Component | Documentation | State |", "|---|---|---|"]
    trace += [f"| `{rel}` | {cell(', '.join(f'[{Path(d).name}](../{d[5:]})' for d in dh[:4]) + (f' +{len(dh) - 4}' if len(dh) > 4 else '')) or '-'} | {state} |"
              for rel, dh, state in other]
    trace += ["", "## Test files", "", f"{len(tests)} files, {sum(test_counts.values())} test functions "
              "(parametrised cases count once).", "", "| Test file | Tests |", "|---|---|"]
    trace += [f"| `{t}` | {n} |" for t, n in test_counts.items()]

    # coverage
    from veyrs.main import create_app
    from veyrs.config import Settings
    from veyrs.models import Base
    app = create_app()
    routes = collect_routes(app)
    paths = sorted({r[0] for r in routes})
    path_hits = sum(1 for p in paths if p in alltext or p.replace("/api/v1", "") in alltext)
    tags = sorted({(r[3].get("tags") or ["untagged"])[0] for r in routes})
    functional = {d: t for d, t in docs.items() if d.startswith(("docs/functional/", "docs/USER_MANUAL", "docs/ADMIN_GUIDE", "docs/USER_GUIDE", "docs/API.md"))}
    ftext = "\n".join(functional.values()).lower()
    tag_hits = sum(1 for t in tags if t.lower() in ftext)
    er = docs.get("docs/database/er-diagrams.md", "")
    tables = sorted(Base.metadata.tables)
    table_er = sum(1 for t in tables if re.search(rf"\b{re.escape(t)}\b", er))
    table_any = sum(1 for t in tables if re.search(rf"\b{re.escape(t)}\b", alltext))
    settings = [("VEYRS_" + n).upper() for n in Settings.model_fields]
    set_hits = sum(1 for s in settings if s in alltext)
    cmds = [c for c, _ in cli_commands()]
    cmd_hits = sum(1 for c in cmds if re.search(rf"\b{re.escape(c)}\b", alltext))
    units = sorted({Path(f).name for f in repo_files() if f.endswith((".service", ".timer", ".path"))})
    unit_hits = sum(1 for u in units if u in alltext)
    fm_total = len(docs)
    fm_ok = sum(1 for t in docs.values() if has_front_matter(t))

    def pct(a, b):
        return f"{(100 * a / b):.0f}%" if b else "n/a"

    cov = [front_matter(
        "Documentation coverage index", "Measures how much of the system the hand-written documentation covers.",
        "Routes, tags, tables, settings, modules, CLI commands, units and front matter. Each figure "
        "states how it was counted.",
        [GEN], ["reference/traceability.md", "audit/README.md"], version),
        "# Documentation coverage index", "",
        generated_note("Documentation-derived: rewritten by every run, not byte-checked by tests."), "",
        "> [!IMPORTANT]",
        "> The generated references (API, configuration, permissions, schema, inventory) cover 100% of "
        "their items **by construction** - they are produced from the code. The percentages below measure "
        "the **hand-written** documents only, by text search: a mention is counted, its quality is not. "
        "Read them as \"where is nothing written\", not as a quality score.", "",
        "| Domain | Measure | Covered | Total | Coverage |", "|---|---|---|---|---|",
        f"| API | Paths mentioned verbatim in hand-written docs | {path_hits} | {len(paths)} | {pct(path_hits, len(paths))} |",
        f"| API | Tags named in functional docs / manuals | {tag_hits} | {len(tags)} | {pct(tag_hits, len(tags))} |",
        f"| API | Operations in the generated reference | {len(routes)} | {len(routes)} | 100% (generated) |",
        f"| Database | Tables drawn in `database/er-diagrams.md` | {table_er} | {len(tables)} | {pct(table_er, len(tables))} |",
        f"| Database | Tables named anywhere in hand-written docs | {table_any} | {len(tables)} | {pct(table_any, len(tables))} |",
        f"| Database | Tables in the generated schema reference | {len(tables)} | {len(tables)} | 100% (generated) |",
        f"| Configuration | `VEYRS_*` settings named in hand-written docs | {set_hits} | {len(settings)} | {pct(set_hits, len(settings))} |",
        f"| Backend | Modules mentioned by path or dotted name | {mod_documented} | {len(modules)} | {pct(mod_documented, len(modules))} |",
        f"| Backend | Modules referenced by a test file | {mod_tested} | {len(modules)} | {pct(mod_tested, len(modules))} |",
        f"| Operations | CLI commands named in hand-written docs | {cmd_hits} | {len(cmds)} | {pct(cmd_hits, len(cmds))} |",
        f"| Operations | Shipped systemd units named in hand-written docs | {unit_hits} | {len(units)} | {pct(unit_hits, len(units))} |",
        f"| Quality | Hand-written docs with complete front matter | {fm_ok} | {fm_total} | {pct(fm_ok, fm_total)} |",
        "", "## Gaps", ""]
    gaps = []
    miss_t = [t for t in tables if not re.search(rf"\b{re.escape(t)}\b", alltext)]
    if miss_t:
        gaps.append(f"- **Tables never named in hand-written docs** ({len(miss_t)}): " + ", ".join(f"`{t}`" for t in miss_t))
    miss_s = [s for s in settings if s not in alltext]
    if miss_s:
        gaps.append(f"- **Settings never named** ({len(miss_s)}): " + ", ".join(f"`{s}`" for s in miss_s))
    miss_c = [c for c in cmds if not re.search(rf"\b{re.escape(c)}\b", alltext)]
    if miss_c:
        gaps.append(f"- **CLI commands never named** ({len(miss_c)}): " + ", ".join(f"`{c}`" for c in miss_c))
    miss_u = [u for u in units if u not in alltext]
    if miss_u:
        gaps.append(f"- **Units never named** ({len(miss_u)}): " + ", ".join(f"`{u}`" for u in miss_u))
    miss_fm = [d for d, t in docs.items() if not has_front_matter(t)]
    if miss_fm:
        gaps.append(f"- **Docs without complete front matter** ({len(miss_fm)}): " + ", ".join(f"`{d[5:]}`" for d in miss_fm))
    miss_tag = [t for t in tags if t.lower() not in ftext]
    if miss_tag:
        gaps.append(f"- **API tags not named in functional docs** ({len(miss_tag)}): " + ", ".join(f"`{t}`" for t in miss_tag))
    cov += gaps or ["None found by these measures."]
    return {
        "docs/reference/traceability.md": "\n".join(trace).rstrip() + "\n",
        "docs/reference/coverage.md": "\n".join(cov).rstrip() + "\n",
    }


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if a code-derived file is stale")
    args = ap.parse_args()
    version = version_of()
    code_derived: dict[str, str] = {}
    for fn in (gen_api, gen_configuration, gen_permissions, gen_inventory):
        code_derived.update(fn(version))
    if args.check:
        stale = [rel for rel, text in sorted(code_derived.items())
                 if not (ROOT / rel).exists() or (ROOT / rel).read_text(encoding="utf-8") != text]
        orphans = sorted(str(p.relative_to(ROOT)) for p in (DOCS / "api/reference").glob("*.md")
                         if str(p.relative_to(ROOT)) not in code_derived)
        missing_doc_derived = [r for r in ("docs/reference/traceability.md", "docs/reference/coverage.md")
                               if not (ROOT / r).exists()]
        if stale or orphans or missing_doc_derived:
            for rel in stale:
                print(f"stale: {rel}", file=sys.stderr)
            for rel in orphans:
                print(f"orphan (tag no longer exists): {rel}", file=sys.stderr)
            for rel in missing_doc_derived:
                print(f"missing: {rel}", file=sys.stderr)
            print(f"Regenerate: python3 {GEN}", file=sys.stderr)
            return 1
        print(f"{len(code_derived)} code-derived reference files match the code")
        return 0
    for rel in (DOCS / "api/reference").glob("*.md") if (DOCS / "api/reference").is_dir() else []:
        if str(rel.relative_to(ROOT)) not in code_derived:
            rel.unlink()
    all_files = dict(code_derived)
    all_files.update(gen_traceability_and_coverage(version))
    for rel, text in sorted(all_files.items()):
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(all_files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
