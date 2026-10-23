"""Terminal-style look for the dashboard (presentation only; no behaviour lives here)."""

from __future__ import annotations

import html

# Green-on-black palette
GREEN = "#00ff9c"
AMBER = "#ffb000"
RED = "#ff3b5c"
CYAN = "#3ddcff"
TEXT = "#c9f7d9"
DIM = "#5f9a7a"
BG = "#050806"
PANEL = "#0a120d"
LINE = "#14402b"

RISK_COLORS = {"SAFE": GREEN, "REVIEW": AMBER, "BLOCK": RED}

ASCII_LOGO = "<div class='og-logo'>&gt; OPSGUARD<span class='og-cursor'></span></div>"

CSS = f"""<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&display=swap');
:root {{--g:{GREEN};--a:{AMBER};--r:{RED};--c:{CYAN};--t:{TEXT};--d:{DIM};--bg:{BG};--p:{PANEL};--l:{LINE};}}
html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stSidebar"], [data-testid="stMarkdownContainer"],
button, input, textarea, select, label, p, li, td, th {{
  font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;}}
[data-testid="stIconMaterial"], .material-symbols-rounded, [class*="material-icons"] {{
  font-family:'Material Symbols Rounded','Material Icons' !important;}}
.stApp {{background:var(--bg);color:var(--t);}}
.stApp::before {{content:"";position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,rgba(0,255,156,.035) 0,rgba(0,255,156,.035) 1px,transparent 1px,transparent 3px);}}
[data-testid="stHeader"] {{background:transparent;}}
[data-testid="stSidebar"] {{background:#040604;border-right:1px solid var(--l);}}
[data-testid="stSidebar"] * {{color:var(--t);}}
.og-logo {{color:var(--g);font-size:1.45rem;font-weight:800;letter-spacing:.04em;margin:.2rem 0 .3rem;text-shadow:0 0 10px rgba(0,255,156,.6);}}
h1,h2,h3 {{color:var(--g) !important;text-shadow:0 0 6px rgba(0,255,156,.35);letter-spacing:.02em;}}
h2, h3 {{font-size:1.15rem !important;}}
h2::before,h3::before {{content:"// ";color:var(--d);}}
a {{color:var(--c) !important;}}
.og-prompt {{color:var(--d);font-size:.8rem;margin-bottom:.2rem;}}
.og-prompt b {{color:var(--g);font-weight:600;}}
.og-cursor {{display:inline-block;width:.6em;height:1em;background:var(--g);vertical-align:-.12em;margin-left:.2em;animation:og-blink 1.1s steps(1) infinite;}}
@keyframes og-blink {{50% {{opacity:0;}}}}
.og-title {{color:var(--g);font-size:1.9rem;font-weight:800;text-shadow:0 0 10px rgba(0,255,156,.5);margin:.1rem 0 .15rem;}}
.og-subtitle {{color:var(--d);margin-bottom:1rem;}}
.og-banner {{border:1px solid var(--a);color:var(--a);background:rgba(255,176,0,.05);padding:.55rem .9rem;margin:.4rem 0 1.1rem;font-size:.82rem;}}
.og-banner::before {{content:"[!] ";font-weight:800;}}
.og-card {{background:var(--p);border:1px solid var(--l);border-left:3px solid var(--g);padding:.9rem 1rem;min-height:118px;}}
.og-card-label {{font-size:.66rem;color:var(--d);letter-spacing:.08em;text-transform:uppercase;}}
.og-card-label::before {{content:"> ";color:var(--g);}}
.og-card-value {{font-size:1.8rem;font-weight:800;margin-top:.3rem;text-shadow:0 0 10px currentColor;}}
.og-decision {{border:2px solid;padding:1rem 1.2rem;font-size:1.3rem;font-weight:800;letter-spacing:.06em;background:rgba(0,0,0,.4);margin:.4rem 0 1rem;}}
.og-decision::before {{content:"> VERDICT: ";font-weight:400;opacity:.7;}}
.og-feed {{background:#030503;border:1px solid var(--l);padding:.7rem .9rem;font-size:.78rem;line-height:1.6;max-height:19rem;overflow:auto;}}
.og-feed .ts {{color:var(--d);}} .og-feed .cmd {{color:var(--t);}}
.og-tag {{font-weight:800;padding:0 .35rem;border:1px solid;margin:0 .5rem;}}
.og-bar {{display:flex;align-items:center;gap:.6rem;margin:.2rem 0;font-size:.8rem;}}
.og-bar .lab {{width:4.6rem;color:var(--d);}} .og-bar .blocks {{flex:1;letter-spacing:.08em;white-space:nowrap;overflow:hidden;}} .og-bar .val {{width:3.2rem;text-align:right;}}
.stButton>button, .stDownloadButton>button {{background:transparent;color:var(--g);border:1px solid var(--g);border-radius:0;transition:all .12s;}}
.stButton>button:hover, .stDownloadButton>button:hover {{background:var(--g);color:var(--bg);box-shadow:0 0 14px rgba(0,255,156,.55);border-color:var(--g);}}
.stButton>button[kind="primary"] {{background:rgba(0,255,156,.12);font-weight:800;}}
.stTextInput input, .stTextArea textarea, [data-baseweb="select"]>div, .stDateInput input {{background:#030503 !important;color:var(--t) !important;border:1px solid var(--l) !important;border-radius:0 !important;}}
.stTextInput input:focus, .stTextArea textarea:focus {{border-color:var(--g) !important;box-shadow:0 0 8px rgba(0,255,156,.4) !important;}}
[data-testid="stDataFrame"] {{border:1px solid var(--l);border-radius:0;}}
[data-testid="stExpander"], [data-testid="stChatMessage"], [data-testid="stVerticalBlockBorderWrapper"] {{border:1px solid var(--l) !important;border-radius:0 !important;background:var(--p);}}
[data-testid="stAlert"] {{border-radius:0;border:1px solid var(--l);background:var(--p);}}
[data-testid="stMetric"] {{background:var(--p);border:1px solid var(--l);border-left:3px solid var(--c);padding:.6rem .8rem;}}
[data-testid="stMetricValue"] {{color:var(--c);}}
pre, code {{background:#030503 !important;color:var(--g) !important;border:1px solid var(--l);border-radius:0 !important;}}
hr {{border-color:var(--l);}}
[data-testid="stSidebar"] [role="radiogroup"] label {{padding:.25rem .4rem;border-left:2px solid transparent;}}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{border-left-color:var(--g);background:rgba(0,255,156,.08);}}
::selection {{background:var(--g);color:var(--bg);}}
@media (prefers-reduced-motion:reduce) {{.og-cursor {{animation:none;}} .stApp::before {{display:none;}}}}
</style>"""


def feed_html(rows: list[tuple[str, str, str]]) -> str:
    """Render (timestamp, decision, command) rows as a terminal log. Commands are user input: always escaped."""
    lines = []
    for stamp, decision, command in rows:
        color = RISK_COLORS.get(decision, DIM)
        lines.append(
            f"<div><span class='ts'>{html.escape(stamp)}</span>"
            f"<span class='og-tag' style='color:{color};border-color:{color}'>{html.escape(decision)}</span>"
            f"<span class='cmd'>{html.escape(command)}</span></div>"
        )
    return "<div class='og-feed'>" + "".join(lines) + "</div>"


def bar_html(label: str, value: float, color: str, width: int = 24) -> str:
    filled = max(0, min(width, round(value * width)))
    blocks = f"<span style='color:{color};text-shadow:0 0 6px {color}'>{'█' * filled}</span><span style='color:{LINE}'>{'░' * (width - filled)}</span>"
    return f"<div class='og-bar'><span class='lab'>{html.escape(label)}</span><span class='blocks'>{blocks}</span><span class='val'>{value:.2f}</span></div>"
