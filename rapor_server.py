#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import os, re, urllib.parse
from datetime import datetime

REPORT_DIR = os.path.expanduser("~/ad_analyzer/report")

def parse_timestamp(filename):
    m = re.search(r'(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})', filename)
    if not m: return None
    return datetime(int(m[1]),int(m[2]),int(m[3]),int(m[4]),int(m[5]),int(m[6]))

def index_html():
    files = sorted(
        [f for f in os.listdir(REPORT_DIR) if f.startswith("adscan_report_") and f.endswith(".html")],
        key=lambda f: parse_timestamp(f) or datetime.min,
        reverse=True
    )

    rows = ""
    for i, filename in enumerate(files):
        date = parse_timestamp(filename)
        date_str = date.strftime("%Y-%m-%d %H:%M:%S") if date else "?"
        if date:
            diff = int((datetime.now() - date).total_seconds())
            if diff < 60:      time_ago = f"{diff} seconds ago"
            elif diff < 3600:  time_ago = f"{diff//60} minutes ago"
            elif diff < 86400: time_ago = f"{diff//3600} hours ago"
            else:              time_ago = f"{diff//86400} days ago"
        else:
            time_ago = ""
        path = os.path.join(REPORT_DIR, filename)
        size = f"{os.path.getsize(path)//1024} KB"

        if i == 0:
            card_cls = "card latest"
            label    = '<span class="badge-new">&#10003; LATEST</span>'
            icon     = "&#128196;"
        else:
            card_cls = "card old"
            label    = '<span class="badge-old">&#128193; OLDER</span>'
            icon     = "&#128203;"

        rows += f"""
        <div class="{card_cls}">
          <a class="card-link" href="/report/{filename}" target="_blank">
            <div class="card-left">
              <div class="icon">{icon}</div>
              <div>
                <div class="fname">{filename}</div>
                <div class="ftime">&#128336; {date_str} &nbsp;&bull;&nbsp; {time_ago} &nbsp;&bull;&nbsp; {size}</div>
              </div>
            </div>
          </a>
          <div class="card-right">
            {label}
            <a class="btn-open" href="/report/{filename}" target="_blank">Open &rarr;</a>
            <button class="btn-delete" onclick="deleteReport('{filename}', this)">&#128465; Delete</button>
          </div>
        </div>"""

    if not rows:
        rows = '<div class="empty">&#128235; No reports found yet.<br>Start a scan: <code>python3 ad_analyzer.py ...</code></div>'

    count = len(files)
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Analyzer &mdash; Reports ({count})</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}}
header{{background:#161b22;border-bottom:2px solid #da3633;padding:1.5rem 2rem;display:flex;justify-content:space-between;align-items:center}}
header h1{{color:#f85149;font-size:1.3rem}}
header p{{color:#8b949e;font-size:.82rem;margin-top:.25rem}}
.badge-count{{background:#da3633;color:#fff;font-size:.75rem;font-weight:700;padding:.25rem .65rem;border-radius:20px;margin-left:.5rem}}
.wrap{{max-width:960px;margin:2rem auto;padding:0 2rem}}
.meta{{color:#8b949e;font-size:.8rem;margin-bottom:1rem;display:flex;justify-content:space-between;align-items:center}}
.refresh-note{{color:#3fb950;font-size:.78rem}}

.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;
       padding:1.1rem 1.4rem;margin-bottom:.7rem;
       display:flex;align-items:center;justify-content:space-between;
       transition:all .2s}}
.card.latest{{border-left:4px solid #3fb950;background:#0d1f0f}}
.card.old{{border-left:4px solid #30363d;opacity:.85}}
.card.deleted{{opacity:0;transform:translateX(30px);transition:all .4s}}

.card-link{{display:flex;flex:1;text-decoration:none;color:inherit;min-width:0}}
.card-link:hover .fname{{color:#58a6ff}}
.card-left{{display:flex;align-items:center;gap:1rem}}
.card-right{{display:flex;align-items:center;gap:.6rem;flex-shrink:0;margin-left:1rem}}
.icon{{font-size:1.6rem}}
.fname{{font-weight:600;font-size:.92rem;color:#e6edf3;word-break:break-all}}
.ftime{{font-size:.8rem;color:#8b949e;margin-top:.25rem}}

.badge-new{{background:#0d4429;color:#3fb950;font-size:.73rem;font-weight:700;padding:.25rem .65rem;border-radius:5px;white-space:nowrap}}
.badge-old{{background:#21262d;color:#6e7681;font-size:.73rem;font-weight:700;padding:.25rem .65rem;border-radius:5px;white-space:nowrap}}
.btn-open{{background:#1f6feb;color:#fff;padding:.45rem 1rem;border-radius:6px;font-size:.83rem;white-space:nowrap;text-decoration:none}}
.btn-open:hover{{background:#388bfd}}

.btn-delete{{background:transparent;color:#6e7681;border:1px solid #30363d;
             padding:.45rem .85rem;border-radius:6px;font-size:.83rem;
             cursor:pointer;white-space:nowrap;transition:all .2s}}
.btn-delete:hover{{background:#3d1212;color:#f85149;border-color:#da3633}}
.btn-delete:disabled{{opacity:.4;cursor:not-allowed}}

.overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);
          z-index:100;align-items:center;justify-content:center}}
.overlay.show{{display:flex}}
.modal{{background:#161b22;border:1px solid #30363d;border-radius:12px;
        padding:2rem;max-width:400px;width:90%;text-align:center}}
.modal h3{{color:#f85149;margin-bottom:.75rem;font-size:1.1rem}}
.modal p{{color:#8b949e;font-size:.9rem;margin-bottom:1.5rem;word-break:break-all}}
.modal-btns{{display:flex;gap:.75rem;justify-content:center}}
.btn-cancel{{background:#21262d;color:#e6edf3;border:1px solid #30363d;
             padding:.55rem 1.25rem;border-radius:6px;cursor:pointer;font-size:.9rem}}
.btn-confirm{{background:#da3633;color:#fff;border:none;
              padding:.55rem 1.25rem;border-radius:6px;cursor:pointer;font-size:.9rem}}
.btn-confirm:hover{{background:#f85149}}

.empty{{color:#8b949e;text-align:center;padding:3rem;background:#161b22;border-radius:10px;line-height:2}}
code{{font-family:monospace;background:#21262d;padding:.1rem .4rem;border-radius:3px;color:#79c0ff}}
</style>
</head><body>

<!-- Delete Confirmation Modal -->
<div class="overlay" id="overlay">
  <div class="modal">
    <h3>&#128465; Delete Report</h3>
    <p id="modal-filename"></p>
    <p style="color:#e3b341;font-size:.85rem">This action cannot be undone!</p>
    <div style="margin:.75rem 0"></div>
    <div class="modal-btns">
      <button class="btn-cancel" onclick="closeModal()">Cancel</button>
      <button class="btn-confirm" onclick="confirmDelete()">Yes, Delete</button>
    </div>
  </div>
</div>

<header>
  <div>
    <h1>&#128737; AD Security Analyzer <span class="badge-count">{count} Reports</span></h1>
    <p>Active Directory Security Scan Reports</p>
  </div>
</header>

<div class="wrap">
  <div class="meta">
    <span>Newest report shown first</span>
    <span class="refresh-note">&#8635; Auto-refreshes every 15 seconds</span>
  </div>
  <div id="list">
    {rows}
  </div>
</div>

<script>
let pending = null;
let pendingEl = null;

function deleteReport(filename, btn) {{
  pending   = filename;
  pendingEl = btn;
  document.getElementById('modal-filename').textContent = filename;
  document.getElementById('overlay').classList.add('show');
}}

function closeModal() {{
  document.getElementById('overlay').classList.remove('show');
  pending   = null;
  pendingEl = null;
}}

async function confirmDelete() {{
  if (!pending) return;
  document.getElementById('overlay').classList.remove('show');

  const card = pendingEl.closest('.card');
  pendingEl.disabled = true;
  pendingEl.textContent = '...';

  try {{
    const r = await fetch('/delete/' + pending, {{method: 'DELETE'}});
    const j = await r.json();
    if (j.ok) {{
      card.classList.add('deleted');
      setTimeout(() => {{
        card.remove();
        const remaining = document.querySelectorAll('.card').length;
        document.querySelector('.badge-count').textContent = remaining + ' Reports';
        const first = document.querySelector('.card');
        if (first) {{
          first.classList.remove('old');
          first.classList.add('latest');
          const oldBadge = first.querySelector('.badge-old');
          if (oldBadge) oldBadge.outerHTML = '<span class="badge-new">&#10003; LATEST</span>';
          first.querySelector('.icon').textContent = '&#128196;';
        }}
        if (remaining === 0) {{
          document.getElementById('list').innerHTML =
            '<div class="empty">&#128235; No reports found yet.</div>';
        }}
      }}, 450);
    }} else {{
      alert('Could not delete: ' + j.error);
      pendingEl.disabled = false;
      pendingEl.textContent = '&#128465; Delete';
    }}
  }} catch(e) {{
    alert('Error: ' + e);
    pendingEl.disabled = false;
    pendingEl.textContent = '&#128465; Delete';
  }}
  pending = pendingEl = null;
}}

document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') closeModal();
}});

setInterval(() => location.reload(), 15000);
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [web] {args[0]} {args[1]}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            content = index_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)

        elif self.path.startswith("/report/"):
            filename = self.path.split("/report/")[1]
            path = os.path.join(REPORT_DIR, filename)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", len(content))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "Report not found")
        else:
            self.send_error(404)

    def do_DELETE(self):
        if self.path.startswith("/delete/"):
            filename = urllib.parse.unquote(self.path.split("/delete/")[1])
            if not (filename.startswith("adscan_report_") and filename.endswith(".html")):
                self._json({"ok": False, "error": "Invalid file"})
                return
            path = os.path.join(REPORT_DIR, filename)
            if os.path.isfile(path):
                os.remove(path)
                print(f"  [del] {filename} deleted")
                self._json({"ok": True})
            else:
                self._json({"ok": False, "error": "File not found"})
        else:
            self.send_error(404)

    def _json(self, data):
        import json
        content = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    os.makedirs(REPORT_DIR, exist_ok=True)
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print(f"\n  \033[92m[+]\033[0m Report server started → http://localhost:8080")
    print(f"  \033[94m[*]\033[0m Reports directory: {REPORT_DIR}")
    print(f"  \033[93m[!]\033[0m Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  \033[91m[x]\033[0m Server stopped.")
