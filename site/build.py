#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render the CPB site Markdown (site/*.md) into a static HTML site (site/dist/).

Self-contained: no framework, no JS, no analytics — one template + inline CSS,
spec-first and minimal by design. Requires `markdown` (pip install markdown).

Usage:
    python3 site/build.py            # writes site/dist/*.html
    python3 site/build.py --serve    # build, then serve site/dist on :8000
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import markdown
except ImportError:
    print("error: the 'markdown' package is required (pip install markdown)", file=sys.stderr)
    sys.exit(2)

SITE = Path(__file__).resolve().parent
DIST = SITE / "dist"

# Pages in nav order. (source .md, output .html, nav label)
PAGES = [
    ("index.md", "index.html", "Home"),
    ("registry.md", "registry.html", "Registry"),
    ("vectors.md", "vectors.html", "Vectors"),
    ("implementations.md", "implementations.html", "Implementations"),
    ("governance.md", "governance.html", "Governance"),
]

CSS = """
:root { --ink:#111; --mut:#555; --line:#e2e2e2; --accent:#0b5; --bg:#fff; --code:#f6f8fa; }
* { box-sizing:border-box; }
body { margin:0; color:var(--ink); background:var(--bg);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif; }
.wrap { max-width:820px; margin:0 auto; padding:0 20px 80px; }
header.site { border-bottom:1px solid var(--line); margin-bottom:2rem; }
header.site .wrap { padding-top:22px; padding-bottom:0; }
.brand { font-weight:700; letter-spacing:-.02em; font-size:1.05rem; text-decoration:none; color:var(--ink); }
.brand small { color:var(--mut); font-weight:500; }
nav { margin:14px 0 0; display:flex; gap:20px; flex-wrap:wrap; }
nav a { text-decoration:none; color:var(--mut); padding-bottom:10px; border-bottom:2px solid transparent; }
nav a:hover { color:var(--ink); }
nav a.active { color:var(--ink); border-bottom-color:var(--accent); font-weight:600; }
h1,h2,h3 { line-height:1.25; letter-spacing:-.01em; }
h1 { font-size:1.9rem; margin:.2rem 0 1rem; }
h2 { margin-top:2.2rem; padding-top:.4rem; border-top:1px solid var(--line); }
a { color:#0645ad; }
code { background:var(--code); padding:.1em .35em; border-radius:4px;
  font:.9em ui-monospace,"IBM Plex Mono",SFMono-Regular,Menlo,monospace; }
pre { background:var(--code); padding:14px 16px; border-radius:8px; overflow:auto; }
pre code { background:none; padding:0; }
table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.93rem; }
th,td { border:1px solid var(--line); padding:8px 10px; text-align:left; vertical-align:top; }
th { background:#fafafa; }
blockquote { margin:1rem 0; padding:.4rem 1rem; border-left:3px solid var(--accent);
  color:var(--mut); background:#fbfffb; }
footer.site { border-top:1px solid var(--line); margin-top:3rem; color:var(--mut); font-size:.88rem; }
footer.site .wrap { padding-top:18px; padding-bottom:24px; }
.draft { background:#fff8e1; border:1px solid #f0d060; border-radius:8px; padding:10px 14px; font-size:.9rem; }
"""

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Canonical Payload Binding</title>
<meta name="description" content="Canonical Payload Binding (CPB): a neutral, cross-organization registry for how bytes are canonicalized and digested before they are signed.">
<style>{css}</style>
</head>
<body>
<header class="site"><div class="wrap">
  <a class="brand" href="index.html">Canonical Payload Binding <small>· CPB</small></a>
  <nav>{nav}</nav>
</div></header>
<main class="wrap">
{body}
</main>
<footer class="site"><div class="wrap">
  Neutral registry · Apache-2.0 · co-authored (Anton Sokolov / TalTech + Steven Mih) ·
  <a href="https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/">IETF draft</a> ·
  <a href="https://github.com/action-state-group/scitt-payload-binding">source</a>
</div></footer>
</body>
</html>
"""


def render_nav(active_html: str) -> str:
    out = []
    for _src, html, label in PAGES:
        cls = ' class="active"' if html == active_html else ""
        out.append(f'<a href="{html}"{cls}>{label}</a>')
    return "".join(out)


def mdlinks_to_html(text: str) -> str:
    # rewrite inter-page links: (foo.md) -> (foo.html), (foo.md#x) -> (foo.html#x)
    return re.sub(r"\(([A-Za-z0-9_./-]+)\.md(#[^)]*)?\)", r"(\1.html\2)", text)


def main(argv: list[str]) -> int:
    DIST.mkdir(exist_ok=True)
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"])
    for src, html, label in PAGES:
        srcpath = SITE / src
        if not srcpath.exists():
            print(f"skip (missing): {src}", file=sys.stderr)
            continue
        text = mdlinks_to_html(srcpath.read_text())
        md.reset()
        body = md.convert(text)
        page = TEMPLATE.format(title=label, css=CSS, nav=render_nav(html), body=body)
        (DIST / html).write_text(page)
        print(f"built {html}")
    # a CNAME helper for GitHub Pages custom-domain deploys (harmless elsewhere)
    (DIST / "CNAME").write_text("canonicalpayloadbinding.org\n")
    print(f"\nsite in {DIST}")
    if "--serve" in argv:
        import http.server, socketserver, functools, os
        os.chdir(DIST)
        h = functools.partial(http.server.SimpleHTTPRequestHandler)
        print("serving http://127.0.0.1:8000  (Ctrl-C to stop)")
        socketserver.TCPServer(("127.0.0.1", 8000), h).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
