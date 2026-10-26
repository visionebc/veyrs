#!/usr/bin/env python3
"""VEYRS product site generator (veyrs-web.example.com).

Separate from site/build.py, which renders the *documentation* site at
veyrs-a. This one builds the product site: what VEYRS is, what it does, how it
is put together, and the user manual.

Zero third-party dependencies, same as the docs builder: the public-facing
host must stay trivially reproducible and auditable. Markdown rendering is
imported from the docs builder rather than copied, so the two sites cannot
drift into rendering the same file differently.

Usage:  python3 site/web/build_web.py [--out /var/www/veyrs-web]
"""
import argparse
import hashlib
import html
import math
import os
import posixpath
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "site"))

from build import render as render_markdown  # noqa: E402  (docs builder)

DOCS = os.path.join(ROOT, "docs")
BRAND = os.path.join(ROOT, "site", "static")

NAV = [
    ("index.html", "Overview"),
    ("features.html", "Capabilities"),
    ("architecture.html", "Architecture"),
    ("security.html", "Security"),
    ("manual.html", "Manual"),
    ("download.html", "Download"),
    ("install.html", "Install"),
    ("docs.html", "Docs"),
]

# Defaults point at the A environment. They are MODULE GLOBALS, reassigned by
# main() from --console-url / --docs-url, because the same source builds the
# site for more than one environment: veyrs-web-p must not send a production
# visitor to the pre-production console. page() reads them at call time, so
# rebinding before the build loop is enough.
CONSOLE_URL = "https://veyrs-app-1.example.com"
DOCS_URL = "https://veyrs-docs.example.com"

# Links inside a rendered doc are relative to docs/ in the repository
# (`../INSTALL.md`, `../docker/compose.yaml`, `ARCHITECTURE.md`). On this site
# they would resolve against the site root and 404 — and the public site cannot
# fall back to DOCS_URL, which only resolves on the LAN. They point at the
# public mirror instead, where every one of those paths exists.
REPO_URL = "https://github.com/visionebc/veyrs/blob/main"

# Set by --public. The public site is reached from the internet, where DOCS_URL
# does not resolve, so every documentation link goes to the Markdown on the
# public mirror instead. Without it (the LAN site) links go to DOCS_URL.
PUBLIC_DOCS = False


def doc_href(slug):
    """Where a link to the doc `slug` (docs/<slug>.md) points on this site."""
    if slug in LOCAL_DOCS:
        return LOCAL_DOCS[slug]
    if PUBLIC_DOCS:
        return f"{REPO_URL}/docs/{slug}.md"
    return f"{DOCS_URL}/{slug}.html"


def _doc_links(body):
    # Page bodies that are plain strings (not f-strings) name a doc as
    # href="doc:SLUG"; it is resolved here, at build time, like any other link.
    return re.sub(r'href="doc:(\w+)"', lambda m: f'href="{doc_href(m.group(1))}"', body)


def docs_home():
    # A directory is served under /tree/; /blob/ answers with a redirect.
    return f"{REPO_URL.replace('/blob/', '/tree/')}/docs" if PUBLIC_DOCS else DOCS_URL


def adr_index():
    # The docs site has no /adr/ index page (403); the ADR README is the index.
    return f"{REPO_URL}/docs/ADRs/README.md" if PUBLIC_DOCS else f"{DOCS_URL}/adr/README.html"


# ---------------------------------------------------------------------------
def page(slug, title, subtitle, body, *, hero=False):
    body = _doc_links(body)
    links = "".join(
        '<a href="%s"%s>%s</a>' % (href, ' class="active"' if href == slug else "", label)
        for href, label in NAV
    )
    hero_html = ""
    if hero:
        hero_html = f"""
<header class="hero">
  <div class="wrap">
    <img class="hero-lockup" src="assets/veyrs-logo-on-dark-gradient.png"
         alt="VEYRS — Unified Cybersecurity Risk Management" width="520">
    <p class="chain"><b>Visibility</b> → <b>Exposure</b> → <b>Risk</b> → <b>Action</b> → <b>Security</b></p>
    <h1>Not a list of vulnerabilities.<br><span class="grad">A list of decisions.</span></h1>
    <p class="sub">
      VEYRS connects CVE, CVSS, EPSS and CISA KEV to <b>your</b> assets, exposure
      and business impact — then carries the result through ticketing, SLA,
      remediation and verification. A 9.8 on an isolated lab box ranked below a
      6.5 on your payment gateway is the system working correctly.
    </p>
    <div class="cta">
      <a class="btn btn-primary" href="{CONSOLE_URL}">Open the console</a>
      <a class="btn btn-ghost" href="manual.html">Read the manual</a>
    </div>
  </div>
</header>"""
    else:
        hero_html = f"""
<header class="pagehead">
  <div class="wrap">
    <h1>{html.escape(title)}</h1>
    <p class="sub">{subtitle}</p>
  </div>
</header>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} — VEYRS</title>
<meta name="description" content="{html.escape(subtitle)}">
<link rel="icon" href="assets/veyrs-favicon.ico" sizes="any">
<link rel="icon" type="image/png" href="assets/veyrs-favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/web.css?v={ASSET_HASH}">
</head>
<body>
<nav>
  <div class="wrap nav-inner">
    <a class="brand" href="index.html">
      <img src="assets/veyrs-mark-gradient.png" alt=""> <span>VEYRS</span>
    </a>
    <input type="checkbox" id="navtoggle" hidden>
    <label class="navburger" for="navtoggle" aria-label="Menu">☰</label>
    <div class="nav-links">{links}
      <a class="nav-cta" href="{CONSOLE_URL}">Console ↗</a>
    </div>
  </div>
</nav>
{hero_html}
<main class="wrap">
{body}
</main>
<footer>
  <div class="wrap foot-inner">
    <div>
      <img src="assets/veyrs-logo-on-dark-gradient.png" alt="VEYRS" width="180">
      <p class="muted">Unified Cybersecurity Risk Management<br>Vision EBC · internal platform</p>
    </div>
    <div class="foot-links">
      <a href="{docs_home()}">Documentation</a>
      <a href="{doc_href("SECURITY")}">Security</a>
      <a href="{doc_href("HIGH_AVAILABILITY")}">Availability</a>
      <a href="{CONSOLE_URL}">Console</a>
    </div>
  </div>
</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
CSS = """
:root{
  --blue:#0064D8; --electric:#0080FF; --navy:#001030; --navy2:#002056;
  --steel:#7080A0; --steel-l:#A0B0C8;
  --bg:#F5F7FA; --border:#D9E0EA; --text:#0B1220; --text2:#526070; --white:#fff;
  --crit:#B91C1C; --high:#EA580C; --med:#D97706; --ok:#15803D;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;
     color:var(--text);background:var(--white);line-height:1.65;
     -webkit-font-smoothing:antialiased}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
a{color:var(--blue);text-decoration:none}
a:hover{color:var(--electric)}

/* ---- nav ---- */
nav{position:sticky;top:0;z-index:50;background:rgba(0,16,48,.92);
    backdrop-filter:blur(10px);border-bottom:1px solid rgba(255,255,255,.08)}
.nav-inner{display:flex;align-items:center;gap:24px;height:64px}
.brand{display:flex;align-items:center;gap:10px;color:#fff;font-weight:800;
       letter-spacing:.04em;font-size:1.05rem}
.brand img{width:26px;height:auto;display:block}
.nav-links{margin-left:auto;display:flex;align-items:center;gap:22px}
.nav-links a{color:var(--steel-l);font-size:.925rem;font-weight:500}
.nav-links a:hover,.nav-links a.active{color:#fff}
.nav-links a.active{position:relative}
.nav-links a.active::after{content:"";position:absolute;left:0;right:0;bottom:-21px;
  height:2px;background:linear-gradient(90deg,var(--blue),var(--electric))}
.nav-cta{border:1px solid rgba(255,255,255,.25);padding:7px 14px;border-radius:8px}
.nav-cta:hover{background:rgba(255,255,255,.08)}
.navburger{display:none;color:#fff;font-size:1.4rem;cursor:pointer;margin-left:auto}

/* ---- hero ---- */
.hero{background:linear-gradient(160deg,#000B22 0%,#002056 100%);color:#fff;
      padding:84px 0 76px;text-align:center;
      border-bottom:2px solid transparent;
      border-image:linear-gradient(90deg,var(--navy),var(--blue),var(--electric)) 1}
.hero-lockup{max-width:min(520px,86vw);height:auto;margin-bottom:26px}
.chain{color:var(--electric);font-size:.9rem;letter-spacing:.14em;
       text-transform:uppercase;font-weight:600;margin:0 0 18px}
.chain b{color:#fff;font-weight:700}
.hero h1{font-size:clamp(2rem,4.6vw,3.15rem);line-height:1.15;margin:0 0 20px;
         font-weight:800;letter-spacing:-.02em}
.grad{background:linear-gradient(90deg,var(--electric),#7EC2FF);
      -webkit-background-clip:text;background-clip:text;color:transparent}
.hero .sub{max-width:74ch;margin:0 auto 30px;color:#C9D6E8;font-size:1.075rem}
.hero .sub b{color:#fff}
.cta{display:flex;gap:14px;justify-content:center;flex-wrap:wrap}
.btn{display:inline-block;padding:12px 24px;border-radius:10px;font-weight:600;
     font-size:.975rem;transition:.15s}
.btn-primary{background:linear-gradient(90deg,var(--blue),var(--electric));color:#fff}
.btn-primary:hover{color:#fff;transform:translateY(-1px);box-shadow:0 8px 24px rgba(0,128,255,.32)}
.btn-ghost{border:1px solid rgba(255,255,255,.3);color:#fff}
.btn-ghost:hover{background:rgba(255,255,255,.1);color:#fff}

.pagehead{background:linear-gradient(160deg,#000B22,#002056);color:#fff;padding:56px 0 46px}
.pagehead h1{margin:0 0 10px;font-size:clamp(1.7rem,3.4vw,2.4rem);font-weight:800;
             letter-spacing:-.015em}
.pagehead .sub{margin:0;color:#C9D6E8;max-width:80ch}

/* ---- content ---- */
main{padding:56px 0 72px}
h2{font-size:1.6rem;font-weight:750;margin:52px 0 14px;letter-spacing:-.01em}
h2:first-child{margin-top:0}
h3{font-size:1.15rem;font-weight:700;margin:32px 0 8px}
p{margin:0 0 16px;max-width:82ch}
.lead{font-size:1.1rem;color:var(--text2);max-width:78ch}
.muted{color:var(--text2);font-size:.9rem}
code{background:#EEF2F7;border:1px solid var(--border);border-radius:5px;
     padding:1px 5px;font-size:.875em;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre.code{background:var(--navy);color:#DCE7F5;padding:18px 20px;border-radius:12px;
     overflow-x:auto;font-size:.875rem;line-height:1.6;margin:0 0 20px}
pre.code code{background:none;border:0;padding:0;color:inherit}
table{width:100%;border-collapse:collapse;margin:0 0 24px;font-size:.94rem}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}
th{background:#EEF2F7;font-weight:650;font-size:.85rem;letter-spacing:.02em}
tbody tr:hover{background:#F8FAFC}
blockquote{margin:0 0 20px;padding:14px 20px;border-left:3px solid var(--blue);
           background:#F5F9FF;border-radius:0 8px 8px 0}
blockquote p{margin:0}
ul,ol{max-width:82ch}
.tablewrap{overflow-x:auto;margin:0 0 24px}
.tablewrap table{margin:0}
li{margin-bottom:7px}
hr{border:0;border-top:1px solid var(--border);margin:44px 0}

/* ---- cards ---- */
.grid{display:grid;gap:20px;margin:0 0 12px}
.g2{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(258px,1fr))}
.card{border:1px solid var(--border);border-radius:14px;padding:22px 24px;
      background:var(--white);transition:.15s}
.card:hover{border-color:var(--blue);box-shadow:0 6px 24px rgba(0,16,48,.07);
            transform:translateY(-2px)}
.card h3{margin:0 0 8px;font-size:1.05rem}
.card p{margin:0;font-size:.94rem;color:var(--text2)}
.card .ico{font-size:1.5rem;display:block;margin-bottom:10px}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
       gap:18px;margin:0 0 12px}
.stat{border:1px solid var(--border);border-radius:14px;padding:20px;text-align:center;
      background:linear-gradient(180deg,#fff,#F7FAFE)}
.stat b{display:block;font-size:1.85rem;font-weight:800;letter-spacing:-.02em;
        background:linear-gradient(90deg,var(--blue),var(--electric));
        -webkit-background-clip:text;background-clip:text;color:transparent}
.stat span{font-size:.83rem;color:var(--text2)}

.note{border:1px solid var(--border);border-left:3px solid var(--blue);
      background:#F5F9FF;border-radius:0 10px 10px 0;padding:16px 20px;margin:0 0 22px}
.note.warn{border-left-color:var(--high);background:#FFF7ED}
.note.crit{border-left-color:var(--crit);background:#FEF2F2}
.note p:last-child{margin:0}
.note strong{font-weight:700}

.pill{display:inline-block;padding:3px 11px;border-radius:999px;font-size:.76rem;
      font-weight:650;letter-spacing:.03em}
.pill-ok{background:#DCFCE7;color:#166534}
.pill-info{background:#DBEAFE;color:#1E40AF}

/* ---- doc body (rendered markdown) ---- */
.doc h2{border-top:1px solid var(--border);padding-top:34px}
.doc h2:first-child{border-top:0;padding-top:0}
.toc{border:1px solid var(--border);border-radius:14px;padding:20px 24px;
     background:#F8FAFC;margin:0 0 36px}
.toc h3{margin:0 0 10px;font-size:.83rem;text-transform:uppercase;
        letter-spacing:.09em;color:var(--text2)}
.toc ul{list-style:none;padding:0;margin:0;columns:2;column-gap:32px}
.toc li{margin-bottom:5px;font-size:.93rem;break-inside:avoid}

/* ---- footer ---- */
footer{background:var(--navy);color:var(--steel-l);padding:44px 0;margin-top:40px}
.foot-inner{display:flex;justify-content:space-between;gap:32px;flex-wrap:wrap}
.foot-inner img{opacity:.95}
.foot-links{display:flex;flex-direction:column;gap:8px}
.foot-links a{color:var(--steel-l);font-size:.92rem}
.foot-links a:hover{color:#fff}
footer .muted{color:var(--steel);margin:12px 0 0}

@media(max-width:860px){
  .navburger{display:block}
  .nav-links{display:none;position:absolute;top:64px;left:0;right:0;
    background:var(--navy);flex-direction:column;align-items:flex-start;
    padding:18px 24px;gap:14px;border-bottom:1px solid rgba(255,255,255,.1)}
  #navtoggle:checked ~ .nav-links{display:flex}
  .nav-links a.active::after{display:none}
  .toc ul{columns:1}
  /* A wide table scrolls inside itself; without this it widened the whole
     page on a phone (install.html rendered 1125px wide in a 375px viewport). */
  .doc table{display:block;overflow-x:auto}
  .doc code{overflow-wrap:anywhere}
}
"""

ASSET_HASH = hashlib.sha256(CSS.encode()).hexdigest()[:10]


# ---------------------------------------------------------------------------
def build_index():
    return """
<h2>The problem VEYRS exists to solve</h2>
<p class="lead">
  Scanners answer "what is wrong with this host?". Nobody has a shortage of that
  answer. The shortage is in "of everything wrong across the estate, what should
  this team fix this week, and what happens if they don't?" — and that question
  cannot be answered from a scanner's output alone, because the scanner does not
  know which of your hosts faces the internet or which one takes payments.
</p>

<div class="stats">
  <div class="stat"><b>353k+</b><span>CVE records correlated</span></div>
  <div class="stat"><b>3.0M</b><span>CPE applicability matches</span></div>
  <div class="stat"><b>20</b><span>scanner formats ingested</span></div>
  <div class="stat"><b>5,090</b><span>automated tests, green</span></div>
</div>

<h2>How the chain works</h2>
<div class="grid g3">
  <div class="card"><span class="ico">👁️</span><h3>Visibility</h3>
    <p>Assets and the software on them, resolved against the CPE dictionary —
    with an explicit signal when something <em>cannot</em> be matched, because
    "nothing is vulnerable" and "nothing is matchable" look identical
    everywhere else.</p></div>
  <div class="card"><span class="ico">🌐</span><h3>Exposure</h3>
    <p>Internet-facing, internal or isolated. The same flaw is not the same
    problem in two different places, and the ranking reflects that.</p></div>
  <div class="card"><span class="ico">📊</span><h3>Risk</h3>
    <p>CVSS v2/v3/v4 combined with EPSS probability, CISA KEV observation,
    exposure and business impact. EPSS is a forecast; KEV is a sighting.</p></div>
  <div class="card"><span class="ico">🎯</span><h3>Action</h3>
    <p>A ticket with an owner, a due date and an escalation path, synchronised
    with Jira or ServiceNow — advisory by default in both directions.</p></div>
  <div class="card"><span class="ico">✅</span><h3>Security</h3>
    <p><code>resolved</code> is a claim. <code>verified</code> is a subsequent
    scan that did not see the finding. Only a machine assigns the second one.</p></div>
  <div class="card"><span class="ico">📁</span><h3>Evidence</h3>
    <p>Immutable audit log, tenant isolation enforced in PostgreSQL itself, and
    reports that carry the numbers which say whether to believe them.</p></div>
</div>

<h2>The opinion behind the product</h2>
<div class="note">
  <p><strong>Every number has a matching number that tells you whether to
  believe it.</strong> A finding count means nothing without a rejected-records
  count. A clean estate means nothing without inventory coverage. A successful
  scan means nothing without coverage statistics. Those pairs are not defensive
  engineering — they are the product.</p>
</div>

<p>
  This is not abstract. A scan of an internal host once "succeeded" in nine
  seconds with zero findings, while the identical scan of its twin ran ten
  minutes and produced twenty-two. Both exited zero. Both wrote zero bytes.
  The scanner had never reached the first host at all — it does not use the
  system resolver, and on a split-horizon network it resolved an internal name
  to a public address it could not route to. <b>Payload size cannot tell a blind
  scan from a clean one. Coverage can</b>, so VEYRS measures coverage and fails
  the job below 80%, whatever the exit code says.
</p>

<h2>Where to go next</h2>
<div class="grid g3">
  <div class="card"><h3><a href="manual.html">User manual →</a></h3>
    <p>Triage, imports, inventory, agents, MFA, and the specific places where
    this system will hand you a plausible wrong answer if you don't look.</p></div>
  <div class="card"><h3><a href="install.html">Install with Docker Compose →</a></h3>
    <p>The guided installer and the container stack: bundled or external
    PostgreSQL, TLS, upgrades, backups you can prove are complete.</p></div>
  <div class="card"><h3><a href="architecture.html">Architecture →</a></h3>
    <p>Two stateless app nodes, one database node, a hot standby on a different
    physical host, and what each failure actually costs.</p></div>
  <div class="card"><h3><a href="security.html">Security →</a></h3>
    <p>Tenant isolation, authentication, secrets, the agent authorisation model
    and the platform's own threat model.</p></div>
</div>
"""


def build_features():
    return """
<h2>Ingestion</h2>
<p class="lead">Twenty parsers, written from each tool's documented schema.</p>
<table>
<thead><tr><th>Category</th><th>Tools</th><th>Note</th></tr></thead>
<tbody>
<tr><td>Network / infrastructure</td><td>Nessus, Qualys, Greenbone/OpenVAS, Nmap output</td><td>Host-anchored, dedup defaults to the legacy key</td></tr>
<tr><td>Web application</td><td>OWASP ZAP, Nuclei, Burp</td><td>Granularity preserved: ZAP = 1 alert/N endpoints, Nuclei = 1 per URL</td></tr>
<tr><td>Container / image</td><td>Trivy, Grype</td><td>The "host" is an image reference — <code>registry/api:2.4.1</code> is a tag, not a port</td></tr>
<tr><td>Code / dependencies</td><td>Semgrep, Dependabot, SCA exports</td><td>Requires <code>target_asset</code>; VEYRS never infers the asset</td></tr>
<tr><td>Cloud posture</td><td>Prowler, cloud config exports</td><td>Artifact identity, same as containers</td></tr>
<tr><td>Generic</td><td>CSV, JSON</td><td>Mapped explicitly, not sniffed</td></tr>
</tbody></table>

<div class="note warn">
  <p><strong>Deduplication is per scanner and configurable</strong> — four
  algorithms, inspectable live at
  <code>GET /engagements/dedupe-registry</code>. Changing one re-keys existing
  findings, which creates duplicates rather than updates: the estate appears to
  double overnight. Treat it as a migration, not a setting.</p>
</div>

<h2>Execution — VEYRS runs scanners, not just imports them</h2>
<p>
  Agents are single-file stdlib runners you place on a jump host. Enrolment
  grants nothing: an agent is inert until an operator enables the specific tool
  <em>and</em> gives it a non-empty target allow-list. Deny by default means an
  agent enrolled and forgotten cannot scan anything.
</p>
<table>
<thead><tr><th>Control</th><th>Behaviour</th></tr></thead>
<tbody>
<tr><td>Tool authorisation</td><td><code>AgentTool.enabled</code>, default false. A declared tool is not an authorised tool.</td></tr>
<tr><td>Target policy</td><td>Empty <code>allowed_targets</code> = inert. Checked twice: at queue time and against the claiming agent.</td></tr>
<tr><td>DNS-rebinding guard</td><td>A hostname target never matches a CIDR rule.</td></tr>
<tr><td>Metadata addresses</td><td>Loopback, link-local and multicast (incl. <code>169.254.169.254</code>) need an exact literal entry.</td></tr>
<tr><td>Asset match</td><td><code>require_asset_match</code> (default true) demands the host exist in the register.</td></tr>
<tr><td>Coverage policy</td><td>Below 80% completion or above a 50% error rate, the job fails — whatever the exit code.</td></tr>
</tbody></table>

<h2>Intelligence</h2>
<table>
<thead><tr><th>Feed</th><th>Source</th><th>Effect</th></tr></thead>
<tbody>
<tr><td>NVD</td><td>nvd.nist.gov</td><td>CVE records and CPE applicability. <b>Can create findings.</b></td></tr>
<tr><td>EPSS</td><td>FIRST</td><td>Exploitation probability. <b>Rescores only.</b></td></tr>
<tr><td>KEV</td><td>CISA</td><td>Known exploited. <b>Rescores only.</b></td></tr>
</tbody></table>
<p>
  EPSS and KEV never create findings. A probability or an exploitation flag does
  not change <em>what</em> is affected, so correlating over them would mean a
  quarter of a million inventory queries a night to learn nothing.
</p>

<h2>Ticketing, SLA and compliance</h2>
<div class="grid g2">
  <div class="card"><h3>SLA clocks</h3><p>Driven by severity and exposure, with
    escalation paths and breach reporting. A due date nobody owns is not an SLA.</p></div>
  <div class="card"><h3>ITSM, both directions</h3><p>Jira and ServiceNow push and
    pull. Inbound webhooks are HMAC-authenticated and <b>advisory by default</b>:
    an external system does not close a security finding unless someone wrote a
    transition map saying it may.</p></div>
  <div class="card"><h3>Compliance mapping</h3><p>Findings map to control
    frameworks so posture is derived from evidence rather than asserted in a
    spreadsheet.</p></div>
  <div class="card"><h3>Reporting</h3><p>Executive summary, technical detail,
    compliance posture, SLA performance, remediation trend. PDF and XLSX.</p></div>
</div>

<h2>Risk-based prioritisation</h2>
<p>
  Findings rank by computed risk, not CVSS. The inputs are severity (CVSS
  v2/v3/v4), EPSS probability, KEV presence, asset exposure and business impact.
  <code>risk_accepted</code> requires an expiry and an accepting party — an
  acceptance with no expiry is not a decision, it is an abandonment, and the
  platform will not record one.
</p>
"""


def build_architecture():
    return """
<h2>Topology</h2>
<p class="lead">
  Two interchangeable application nodes, one node holding all the state, and a
  hot standby of that state. The standby belongs on a <b>different physical
  host</b> from the primary: on the same host it covers the loss of the
  database node, not the loss of the machine.
</p>

<pre class="code"><code>                         console / API / sites
                                   |
                            reverse proxy
                     TLS termination + upstream pool
                          /                     \\
               app node 1                        app node 2
               + scheduled jobs                  singletons disabled
                          \\                     /
                           database node
                        PostgreSQL 15 + Redis
                                   |
                        streaming replication
                                   v
                           standby node
                   hot standby, on another physical host</code></pre>

<table>
<thead><tr><th>Node</th><th>Role</th></tr></thead>
<tbody>
<tr><td>App node 1</td><td>Application + the scheduled jobs (scan runner, intelligence sync, digest)</td></tr>
<tr><td>App node 2</td><td>Application. Singleton units installed but disabled.</td></tr>
<tr><td>Database node</td><td>PostgreSQL 15 + Redis. <b>The only node with state.</b></td></tr>
<tr><td>Standby node</td><td>Hot standby, streaming replication. Promoted by hand, never automatically.</td></tr>
</tbody></table>

<h2>Why the application nodes hold no state</h2>
<p>
  Because the failure that actually happens is a process dying, not a datacentre
  burning. A cold-standby clone covers the second and not the first: it needs a
  human to notice and act. Two stateless nodes behind an upstream cover the
  first automatically — nginx marks the dead backend and serves from the other,
  with nobody looking at a phone at 03:40.
</p>
<p>
  Verified in production, not assumed: killing the API on one node served
  <b>20 of 20</b> requests; stopping the entire container served <b>25 of 25 in
  six seconds</b>.
</p>

<div class="note">
  <p><strong>Failover does not happen in DNS.</strong> Every name resolves
  to the reverse proxy, which chooses the backend. No bookmark ever changes, and
  no TTL is ever waited on.</p>
</div>

<h2>Singletons run on exactly one node</h2>
<p>
  The scan runner and the intelligence sync are enabled on app node 1 and
  <code>disabled</code> on app node 2, with the units and configuration present
  so node 2 can take over in one command. Two runners claiming the same jobs is
  corruption, not redundancy.
</p>

<h2>What each failure costs</h2>
<table>
<thead><tr><th>Failure</th><th>Impact</th><th>Recovery</th></tr></thead>
<tbody>
<tr><td>One node's API dies</td><td><span class="pill pill-ok">none</span></td><td>Automatic</td></tr>
<tr><td>One node stops entirely</td><td><span class="pill pill-ok">none</span></td><td>Automatic, ~6 s</td></tr>
<tr><td>App node 1 down</td><td>Batch jobs pause; console unaffected</td><td>Operator enables the units on node 2</td></tr>
<tr><td>Database node lost</td><td>Full outage</td><td>Promote the standby (manual, deliberate)</td></tr>
<tr><td>Physical host of the database lost</td><td>Full outage</td><td>Promote the standby <b>if it runs on another host</b>; otherwise restore the off-host logical dump</td></tr>
</tbody></table>

<h2>Data protection</h2>
<table>
<thead><tr><th>Layer</th><th>What it covers</th><th>What it does not</th></tr></thead>
<tbody>
<tr><td>Streaming replica</td><td>Loss of the database node — and of its host, when the standby lives elsewhere. RPO ≈ seconds.</td><td>Logical damage — it replicates a <code>DROP</code> faithfully.</td></tr>
<tr><td>Nightly logical dump</td><td><code>DROP</code>, bad migration, corruption. Selective restore.</td><td>Up to 24 h of changes.</td></tr>
<tr><td>Hypervisor snapshot</td><td>Container-level rollback, crash-consistent.</td><td>Loss of the host — <b>unless the datastore lives on another machine</b>.</td></tr>
</tbody></table>

<div class="note warn">
  <p><strong>The dump is copied off the database node and its restorability
  is proven weekly.</strong> Not by checking the archive parses — a dump taken under
  row-level security is a well-formed archive whose tables are empty, and it
  lists perfectly. It is proven by restoring it into a scratch database and
  comparing row counts and RLS policy counts against production.</p>
</div>

<h2>Promotion is manual on purpose</h2>
<p>
  Automatic promotion without a fencing mechanism produces two primaries, and
  two primaries produce divergent security data that cannot be reconciled
  afterwards. The runbook is in
  <a href="doc:HIGH_AVAILABILITY">HIGH_AVAILABILITY</a>.
</p>

<h2>Stack</h2>
<table>
<thead><tr><th>Layer</th><th>Choice</th></tr></thead>
<tbody>
<tr><td>API</td><td>FastAPI, uvicorn, 4 workers</td></tr>
<tr><td>Data</td><td>PostgreSQL 15 with row-level security FORCEd on every tenant table</td></tr>
<tr><td>Cache / rate limiting</td><td>Redis, password-protected</td></tr>
<tr><td>ORM</td><td>SQLAlchemy 2</td></tr>
<tr><td>Auth</td><td>Argon2id, JWT with rotating refresh families, TOTP</td></tr>
<tr><td>Secrets at rest</td><td>Fernet envelope, versioned ciphertext</td></tr>
<tr><td>Schema evolution</td><td><code>veyrs sync-schema</code> — additive reconciler, no Alembic</td></tr>
<tr><td>Dependencies</td><td>{packages} packages, pinned, locked, guarded by tests</td></tr>
</tbody></table>
""".replace("{packages}", str(_pinned_packages()))


def _pinned_packages():
    # Counted at build time: the page said 52 while requirements.txt pinned 53.
    with open(os.path.join(ROOT, "requirements.txt")) as fh:
        return sum(1 for line in fh if line.strip() and not line.lstrip().startswith(("#", "-")))


def build_security():
    return """
<h2>Tenant isolation lives in the database</h2>
<p class="lead">
  Every tenant table is protected by PostgreSQL row-level security with
  <b>FORCE</b> enabled — 61 policies. Isolation is not a <code>WHERE</code>
  clause the application remembers to add, so a bug in a query cannot leak
  across tenants.
</p>
<div class="note">
  <p>The practical consequence, and it has cost real hours: a script that reads
  production without setting the tenant sees <strong>zero rows</strong>. Empty is
  the correct, safe answer to an unscoped query — not evidence that the data is
  gone.</p>
</div>

<h2>Authentication</h2>
<table>
<thead><tr><th>Control</th><th>Behaviour</th></tr></thead>
<tbody>
<tr><td>Password storage</td><td>Argon2id, transparently rehashed when parameters change</td></tr>
<tr><td>Account enumeration</td><td>Wrong password, unknown email, disabled user and disabled organization all return an identical 401</td></tr>
<tr><td>Lockout</td><td>10 failures → 15 minutes, per user rather than per IP</td></tr>
<tr><td>Refresh tokens</td><td>Rotate on every use; replaying a rotated token revokes the whole family</td></tr>
<tr><td>MFA</td><td>TOTP (RFC 6238). Secret encrypted at rest, codes single-use, failures share the password lockout budget</td></tr>
<tr><td>Federated accounts</td><td>No local password to brute force — that is the point</td></tr>
</tbody></table>

<h3>MFA is a control, not a checkbox</h3>
<p>
  Enrolment is three steps — <code>enroll</code>, then <code>activate</code>
  with a working code, and only then is MFA enforced — because enabling in one
  step is how administrators lock themselves out of the console they administer.
  Disabling requires the password <em>and</em> a code, so a stolen access token
  cannot strip the second factor off the account it was stolen from. An account
  flagged for MFA whose secret is unreadable <b>fails closed</b>: falling back to
  password-only would silently downgrade exactly the account that asked for more.
</p>

<h2>Secrets</h2>
<p>
  Third-party credentials (AI providers, ITSM connectors, threat sources,
  webhook secrets, MFA seeds) are stored under a Fernet envelope with versioned
  ciphertext, so key rotation is possible without guessing at the payload. They
  cannot be hashed — VEYRS has to replay them. The production key is explicit:
  the application <b>refuses to boot in production</b> with a key derived from
  the app secret.
</p>
<p>
  The audit log redacts passwords, key hashes and MFA secrets at the recording
  layer, not at display time. A redaction applied on the way out is a redaction
  someone will forget to apply to the next view.
</p>

<h2>Untrusted input</h2>
<p>
  Every scanner report is attacker-influenced data — anyone who can get a
  finding into a scan can get a string into VEYRS.
</p>
<ul>
  <li><b>XML entity declarations are refused</b> at the parser (Nessus, Qualys,
      Greenbone). XXE against a vulnerability platform would be a very good
      trade for an attacker.</li>
  <li><b>Metric labels are escaped by the emitter, never by callers.</b> An
      unrouted request path with a quote in it once emitted a line no scraper
      could parse, silently dropping every metric. Unmatched routes now
      contribute a constant, and series are capped with an overflow bucket.</li>
  <li><b>Uploads are size-bounded</b> and land in a scoped engagement; an import
      that names no engagement is still scoped, never global.</li>
</ul>

<h2>The agent authorisation model</h2>
<p>
  Agents execute scanners, so they are the most dangerous component in the
  product. They are deliberately the least trusted.
</p>
<ul>
  <li>An agent authenticates with <code>X-Agent-Token</code> and is <b>not a
      Principal</b>: it reaches <code>/agents/self/*</code> and nothing else.</li>
  <li>Two independent switches must both be on before anything runs — tool
      enabled, and a non-empty target allow-list.</li>
  <li>Targets are authorised twice: at queue time and again against the claiming
      agent's policy.</li>
  <li>Inventory collection is held to the <b>same</b> target policy as scanning.
      An agent that could rewrite any asset's software could make a host look
      clean without running a scanner at all.</li>
</ul>

<h2>Observability endpoints</h2>
<p>
  <code>/metrics</code> is gated by a bearer token and answers <b>404</b>, not
  401, when the token is wrong or absent. An IP allow-list was tried and did not
  work: every request arrives from the fleet reverse proxy, so
  <code>$remote_addr</code> matched the proxy rather than the caller. Any
  address-based rule on this platform has that flaw.
</p>

<h2>Supply chain</h2>
<p>
  Dependencies are declared, pinned and locked, and the lock is generated rather
  than hand-edited. The set is 52 packages; 21 were removed once it was written
  down, all with zero imports in the tree. A test enforces that they stay
  removed and that every declared package is present, pinned and importable.
</p>
<p>
  Parsers were written from each tool's documented schema. No code was copied
  from DefectDojo (BSD-3) or Faraday (GPL-3.0) — copying the latter would have
  forced VEYRS to GPL.
</p>

<p class="muted">
  Full threat model:
  <a href="doc:THREAT_MODEL">THREAT_MODEL</a> ·
  <a href="doc:SECURITY">SECURITY</a> ·
  <a href="doc:AI_SECURITY">AI_SECURITY</a>
</p>
"""


def build_docs():
    groups = [
        ("Start here", [
            ("README", "What VEYRS is and how the pieces fit"),
            ("USER_GUIDE", "The short version, for people already working in it"),
            ("USER_MANUAL", "The long version — triage, imports, agents, the traps"),
            ("ADMIN_GUIDE", "Tenants, roles, connectors, day-two operations"),
            ("DOCKER_COMPOSE_MANUAL", "Installing and running the container stack"),
        ]),
        ("Architecture", [
            ("ARCHITECTURE", "Services, data flow, module boundaries"),
            ("DATABASE", "Schema, RLS model, sync-schema"),
            ("API", "Endpoint reference and conventions"),
            ("HIGH_AVAILABILITY", "Node topology, failover, promotion runbook"),
            ("DEPLOYMENT", "Building a node from nothing"),
            ("DEVELOPMENT", "Local setup, tests, contribution flow"),
        ]),
        ("Security", [
            ("SECURITY", "Controls, authentication, secrets, hardening"),
            ("THREAT_MODEL", "What we assume the attacker can do"),
            ("AI_SECURITY", "Prompt handling, provider isolation, data boundaries"),
        ]),
        ("Operations", [
            ("INTEGRATIONS", "Scanners, ITSM, feeds, agents"),
            ("DISASTER_RECOVERY", "Backups, restore procedure, verification"),
            ("CHANGELOG", "Every release and why it happened"),
            ("CONTRIBUTING", "House rules for changes"),
        ]),
    ]
    out = ['<h2>Documentation</h2>',
           '<p class="lead">The full technical documentation lives at '
           f'<a href="{docs_home()}">{docs_home().split("://", 1)[1]}</a>. '
           'It is generated from the Markdown in the repository, so it cannot '
           'drift from what was reviewed in a pull request.</p>']
    for title, items in groups:
        out.append(f"<h2>{title}</h2>")
        out.append('<div class="grid g2">')
        for slug, desc in items:
            href = doc_href(slug)
            out.append(
                f'<div class="card"><h3><a href="{href}">{slug.replace("_", " ").title()} →</a></h3>'
                f'<p>{desc}</p></div>'
            )
        out.append("</div>")
    out.append('<h2>Architecture decision records</h2>'
               f'<p>Each ADR states the decision, the alternatives and the cost of '
               f'reversing it: <a href="{adr_index()}">the ADR index</a>.</p>')
    return "\n".join(out)


def _repo_links(body):
    def fix(m):
        href = m.group(1)
        if re.match(r"^(?:[a-z][a-z0-9+.-]*:|#|/)", href):
            return m.group(0)
        path = posixpath.normpath(posixpath.join("docs", href))
        if path.startswith(".."):
            return m.group(0)
        return f'href="{REPO_URL}/{path}"'
    return re.sub(r'href="([^"]+)"', fix, body)


def _doc_page(name):
    md = open(os.path.join(DOCS, name + ".md")).read()
    body, toc = render_markdown(md)
    items = "".join('<li><a href="#%s">%s</a></li>' % (slug, html.escape(text))
                    for level, text, slug in toc if level == 2)
    return (f'<div class="toc"><h3>On this page</h3><ul>{items}</ul></div>'
            f'<div class="doc">{_repo_links(body)}</div>')


def build_manual():
    return _doc_page("USER_MANUAL")


def build_install():
    return _doc_page("DOCKER_COMPOSE_MANUAL")



# The thresholds check_requirements() in veyrs-setup.sh applies. They are
# restated here because the page explains them; tests/test_site_render.py reads
# them back out of the installer, so the page cannot quietly drift from it.
SETUP_CPU_WARN_BELOW = 2          # cores: warn below this, never refuse
SETUP_RAM_OK_MB = 3800            # MemTotal at or above: ok
SETUP_RAM_MIN_MB = 1900           # below this: refuse; between: warn
SETUP_DISK_OK_MB = 12000          # free MB on /: ok
SETUP_DISK_MIN_MB = 5000          # below this: refuse; between: warn

RELEASES_URL = "https://github.com/visionebc/veyrs/releases/latest"


def _table(head, rows):
    # Wrapped so a wide table scrolls inside itself on a phone instead of
    # widening the page (the same failure install.html had).
    th = "".join(f"<th>{h}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tablewrap"><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def build_download():
    # Nominal size plus the exact gate: a "4 GB" machine reports a MemTotal
    # below 4096 MB, which is why the installer compares against 3800.
    def gb(mb):
        return f'{math.ceil(mb / 1000)} GB <span class="muted">({mb:,} MB)</span>'

    out = [f"""
<h2>Get the release</h2>
<p class="lead">Every release is published on GitHub and <b>signed</b>. Check the
signature first, then every file against it, and only then run anything as root.</p>
<pre class="code"><code>B=https://github.com/visionebc/veyrs/releases/latest/download
curl -fL -O $B/veyrs-setup.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.sig
# The key comes from the REPOSITORY, not from the release it vouches for:
curl -fLo allowed_signers https://raw.githubusercontent.com/visionebc/veyrs/main/release/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I release@veyrs -n veyrs-release \\
    -s SHA256SUMS.sig &lt; SHA256SUMS        # must print: Good "veyrs-release" signature
sha256sum -c --ignore-missing SHA256SUMS  # must print "veyrs-setup.sh: OK"
sudo bash veyrs-setup.sh --check          # inspect this host, change nothing
sudo bash veyrs-setup.sh                  # native or Docker, bundled or external PostgreSQL</code></pre>
<p><code>--check</code> runs the same requirement checks described below and changes
nothing, so run it on the target host before you size anything by hand.</p>
""",
           _table(["Asset", "What it is"], [
               ["<code>veyrs-setup.sh</code>", "the guided installer: native or Docker, online or offline"],
               ["<code>SHA256SUMS</code>, <code>SHA256SUMS.sig</code>",
                "the SHA-256 of every asset and its OpenSSH signature (principal "
                "<code>release@veyrs</code>, namespace <code>veyrs-release</code>)"],
               ["<code>veyrs-&lt;v&gt;-src.tar.gz</code>",
                "the release tree; the installer downloads it itself unless you pass <code>--source</code>"],
               ["<code>veyrs-images-&lt;v&gt;-amd64.tar.gz</code>",
                "offline image bundle (<code>--images</code>) for hosts with no network; "
                "check it against its own <code>.sha256</code> (it is not in <code>SHA256SUMS</code> yet)"],
           ]),
           f'<p><a href="{RELEASES_URL}">All assets of the latest release →</a> · '
           '<a href="install.html">Docker Compose manual →</a></p>',

           """
<h2>Permissions the installation needs</h2>
<div class="note"><p><strong>The installer must run as root</strong> (<code>sudo</code>).
It refuses to start otherwise: it installs distribution packages, writes systemd
units and, in Docker mode, installs Docker itself. There is no reduced-privilege
mode. Every step that needs more than the install directory is listed here,
with the flag that removes it when your site policy reserves that step for
someone else.</p></div>
<h3>Native install</h3>
""",
           _table(["Step", "Privilege", "Why", "Avoid with"], [
               ["System packages", "<b>root</b>",
                "<code>apt-get</code> / <code>zypper</code> / <code>dnf</code>, <code>systemctl enable --now</code>",
                "<code>--skip-system-packages</code>"],
               ["Database role and databases",
                "<b>PostgreSQL superuser</b>, through the local <code>postgres</code> account",
                "<code>CREATE ROLE</code>, <code>CREATE DATABASE</code>; one scoped "
                "<code>pg_hba.conf</code> block only if a password login actually fails "
                "(SUSE and RHEL default to <code>ident</code>)",
                "<code>--skip-postgres</code> — a DBA creates them first"],
               ["Redis", "<b>root</b>", "sets <code>requirepass</code>, starts the service",
                "<code>--skip-redis</code>"],
               ["Python packages", "write access to the install root",
                "builds <code>/opt/veyrs/venv</code>", "—"],
               ["Schema", "the <b>owner</b> of the database, not a superuser",
                "<code>init-db</code>: tables, row-level security policies, built-in roles", "—"],
               ["systemd unit", "<b>root</b>", "writes <code>/etc/systemd/system/veyrs-api.service</code>", "—"],
               ["Console and nginx", "<b>root</b>", "writes the console directory and the vhost, reloads nginx",
                "<code>--skip-nginx</code>"],
           ]),
           """
<p>The superuser is needed <b>only to create</b> the role and the databases. The
application's own role is deliberately unprivileged —
<code>NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS</code> — and owns its
database and nothing else. An external PostgreSQL whose role is superuser or has
<code>BYPASSRLS</code> is <b>refused</b>, because either one switches tenant
isolation off.</p>
<h3>Docker mode</h3>
""",
           _table(["Who", "Runs as", "Notes"], [
               ["<code>veyrs-setup.sh</code>", "<b>root</b>",
                "installs Docker Engine and the Compose plugin from Docker's repository when missing, "
                "writes <code>/opt/veyrs-docker</code> (env file <code>0600</code>), "
                "<code>/usr/local/sbin/veyrs-docker</code> and <code>/etc/veyrs-setup.conf</code>"],
               ["Driving the stack by hand", "root, or a member of the <code>docker</code> group",
                "membership of <code>docker</code> is <b>root-equivalent</b> on that host: grant it as you would grant root"],
               ["<code>api</code>, workers, <code>agent</code>", "uid <code>10001</code>",
                "<code>cap_drop: ALL</code>, <code>no-new-privileges</code>, read-only image filesystem"],
               ["<code>console</code>", "uid <code>101</code>", "nginx on container port 8080, same hardening"],
               ["<code>init</code>", "root, briefly",
                "only <code>CHOWN DAC_OVERRIDE FOWNER SETUID SETGID</code>; chowns the data volume, "
                "then drops to uid 10001 before it touches the database"],
               ["<code>agent</code> (optional scanner)", "uid <code>10001</code>",
                "<b>no</b> <code>NET_RAW</code>: no SYN scanning unless you grant it deliberately"],
           ]),
           """
<p><b>Docker inside an LXC container</b> needs <code>nesting=1</code>, plus
<code>keyctl=1</code> when the container is unprivileged. Without them the
daemon installs but never answers, and the installer stops and says so.</p>
<h3>What the installer will not do unasked</h3>
<ul>
  <li><b>Open the firewall.</b> With firewalld or ufw active it warns and continues;
  <code>--open-firewall</code> is opt-in.</li>
  <li><b>Overwrite</b> an existing <code>.env</code>, nginx vhost, database role password or
  administrator password. A re-run leaves all four alone.</li>
  <li><b>Pass the administrator password in argv.</b> It is handed over through the
  environment, never on a command line another user could read with <code>ps</code>.</li>
</ul>
<p><b>SELinux:</b> where it is <code>Enforcing</code>, the installer sets
<code>httpd_can_network_connect</code> (without it nginx answers 502 on
<code>/api/</code>) and restores labels on the console directory.</p>
<p><b>Known limitation:</b> the native <code>veyrs-api</code> service runs as root.
What compensates today is the unit's hardening — <code>ProtectSystem=strict</code>
with <code>/opt/veyrs/var</code> as the only writable path,
<code>NoNewPrivileges</code>, <code>PrivateTmp</code>, <code>ProtectHome</code>,
<code>MemoryDenyWriteExecute</code> — and an API bound to loopback only. The
Docker stack does not have this limitation.</p>
<h3>Network</h3>
""",
           _table(["Direction", "Port / destination", "When"], [
               ["inbound", "80, or 443 where TLS terminates on the host (native); "
                "<code>VEYRS_HTTP_BIND</code>, default <code>127.0.0.1:8080</code> (Docker)", "always"],
               ["loopback", "8000", "the API; nginx proxies it, it is never exposed"],
               ["outbound", "5432 · 6379", "to the database and cache — localhost unless you split them"],
               ["outbound", "443: distribution repositories, PyPI, <code>github.com</code>, "
                "<code>ghcr.io</code> / Docker Hub", "<b>during the install only</b>; an offline install needs none"],
               ["outbound", "443: <code>services.nvd.nist.gov</code>, <code>epss.empiricalsecurity.com</code>, "
                "<code>www.cisa.gov</code>, <code>cwe.mitre.org</code>",
                "at runtime, optional: vulnerability intelligence. Without it VEYRS keeps running on stale data"],
           ]),

           f"""
<h2>Hardware: CPU, memory and disk</h2>
<h3>What the installer checks</h3>
<p>These are the gates of <code>veyrs-setup.sh --check</code>. They decide whether
the installation <b>starts</b>; they are not a size for a system that pulls
vulnerability intelligence.</p>
""",
           _table(["Resource", "Refused below", "Warning below", "Notes"], [
               ["CPU", "never", f"{SETUP_CPU_WARN_BELOW} cores",
                "the API runs 4 worker processes; building images is the heaviest moment"],
               ["RAM", gb(SETUP_RAM_MIN_MB), gb(SETUP_RAM_OK_MB),
                "the running stack fits in 2 GB; building images needs the 4"],
               ["Free disk on <code>/</code>", gb(SETUP_DISK_MIN_MB), gb(SETUP_DISK_OK_MB),
                "on <code>/</code> because that is Docker's default data root"],
               ["Architecture", "—", "—", "x86-64. arm64 is not verified"],
           ]),
           """
<div class="note warn"><p><strong>Disk is driven by threat intelligence, not by your
findings.</strong> On the reference deployment the database is <b>5.3 GB with
1,615 findings</b>: about 5.2 GB of it is the NVD corpus, the CPE dictionary and
EPSS scores. EPSS history keeps one row per CVE per scored day — about
370,000 rows, roughly <b>80 MB a day</b> — for <code>VEYRS_EPSS_HISTORY_DAYS</code>
days (default <b>365, about 30 GB</b>; 90 days is about 7 GB). Releases before
0.33.2 never pruned it. The 5 GB / 12 GB gates above are therefore only true for
an installation that never turns the intelligence workers on.</p></div>
<h3>Recommended sizing</h3>
""",
           _table(["Deployment", "vCPU", "RAM", "Disk", "Notes"], [
               ["Evaluation — Docker, intelligence workers off", "2", "4 GB", "20 GB",
                "images, a small database, the optional 84 MB scanner template corpus"],
               ["Single node with intelligence (native or Docker)", "2–4", "4 GB (8 GB from ~50k findings)",
                "<b>60 GB</b> (30 GB with 90 days of EPSS history)",
                "~6 GB of database on day one, growing ~80 MB a day until the EPSS "
                "retention is reached; WAL; local backups (~0.9 GB each, growing with it)"],
               ["Split deployment — each application node", "4", "4 GB", "20 GB",
                "stateless; two of them behind a proxy for failover"],
               ["Split deployment — database node (and its standby)", "4–6", "6–8 GB", "100 GB",
                "a streaming standby's replication slot can hold WAL up to "
                "<code>max_slot_wal_keep_size</code> while the standby is down — budget it"],
           ]),
           """
<p>CPU and RAM follow the number of findings; disk follows the intelligence feeds.</p>
""",
           _table(["Findings", "vCPU", "RAM", "Notes"], [
               ["&lt; 50k", "2", "4 GB", "single node"],
               ["50k – 500k", "4", "8 GB", "separate database host recommended"],
               ["500k – 5M", "8", "16 GB", "separate the database host"],
               ["&gt; 5M", "—", "—", "separate workers; partition <code>findings</code> by organization"],
           ]),
           """
<h3>What the reference deployment actually uses</h3>
<p>Measured on 2026-10-26 on the split deployment VEYRS itself runs on (two
application nodes, one database node with a hot standby), with the intelligence
feeds on.</p>
""",
           _table(["Node", "Allocated", "In use"], [
               ["Application node", "4 vCPU · 4 GB RAM · 60 GB",
                "0.9 GB RAM (the API with 4 workers ≈ 750 MB) · 6.3 GB disk, OS and scanner templates included"],
               ["Database node", "6 vCPU · 6 GB RAM · 100 GB",
                "1.6 GB RAM plus page cache · 18 GB disk: 7.9 GB of PostgreSQL data "
                "(2.7 GB of it WAL), the rest backups and the OS"],
           ]),
           ]
    return "\n".join(out)


LOCAL_DOCS = {"USER_MANUAL": "manual.html", "DOCKER_COMPOSE_MANUAL": "install.html"}


# ---------------------------------------------------------------------------
PAGES = [
    ("index.html", "VEYRS", "Unified Cybersecurity Risk Management", build_index, True),
    ("features.html", "Capabilities",
     "Ingestion, execution, intelligence, ticketing and reporting — and the controls that keep each honest.",
     build_features, False),
    ("architecture.html", "Architecture",
     "Two stateless application nodes, one database node, a hot standby on another physical host, and what every failure actually costs.",
     build_architecture, False),
    ("security.html", "Security",
     "Tenant isolation in the database, authentication, secrets, untrusted input, and the agent authorisation model.",
     build_security, False),
    ("manual.html", "User manual",
     "The operator's manual: triage, imports, inventory, agents, MFA, and the places this system will hand you a plausible wrong answer.",
     build_manual, False),
    ("download.html", "Download",
     "The signed release, the permissions an installation needs, and the CPU, memory and disk to give it.",
     build_download, False),
    ("install.html", "Install with Docker Compose",
     "The guided installer, bundled or external PostgreSQL, TLS, upgrades, backups, and what each optional service costs to leave off.",
     build_install, False),
    ("docs.html", "Documentation",
     "The full technical documentation set, generated from the repository.",
     build_docs, False),
]

BRAND_FILES = [
    "veyrs-logo-on-dark-gradient.png", "veyrs-mark-gradient.png",
    "veyrs-favicon.ico", "veyrs-favicon.png", "veyrs-tokens.css",
]


def main():
    # `global` must precede every use of the name in this scope, including
    # the argparse defaults that read the current values.
    global CONSOLE_URL, DOCS_URL, PUBLIC_DOCS

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/www/veyrs-web")
    ap.add_argument("--console-url",
                    default=os.environ.get("VEYRS_SITE_CONSOLE_URL", CONSOLE_URL))
    ap.add_argument("--docs-url",
                    default=os.environ.get("VEYRS_SITE_DOCS_URL", DOCS_URL))
    ap.add_argument("--public", action="store_true",
                    help="internet-facing build: link docs to the public mirror, "
                         "not to --docs-url (which only resolves on the LAN)")
    args = ap.parse_args()

    CONSOLE_URL = args.console_url.rstrip("/")
    DOCS_URL = args.docs_url.rstrip("/")
    PUBLIC_DOCS = args.public

    assets = os.path.join(args.out, "assets")
    os.makedirs(assets, exist_ok=True)

    with open(os.path.join(assets, "web.css"), "w") as fh:
        fh.write(CSS)
    for name in BRAND_FILES:
        src = os.path.join(BRAND, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(assets, name))
        else:
            print(f"  ! missing brand asset: {name}")

    for slug, title, subtitle, builder, hero in PAGES:
        with open(os.path.join(args.out, slug), "w") as fh:
            fh.write(page(slug, title, subtitle, builder(), hero=hero))
        print(f"  {slug}")

    print(f"built {len(PAGES)} pages -> {args.out} (css {ASSET_HASH})")
    print(f"  console -> {CONSOLE_URL}")
    print(f"  docs    -> {docs_home()}")


if __name__ == "__main__":
    main()
