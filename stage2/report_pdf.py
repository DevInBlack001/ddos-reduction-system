"""
report_pdf.py: renders the incident report context (see report_data.py) to
a PDF, as an HTML/CSS document handed to WeasyPrint. Keeping the layout in
HTML rather than hand-placed drawing primitives is what makes the grid tiles,
stacked bars, and gauges practical to build and to restyle later.
"""

import logging

from jinja2 import Environment
from weasyprint import HTML

# WeasyPrint, and fontTools underneath it, log their own CSS/layout/font
# subsetting diagnostics at INFO, which this project's global logging
# config (stage2 prefix, INFO level) would otherwise write dozens of lines
# to stage2.log on every single report generated.
logging.getLogger("weasyprint").setLevel(logging.WARNING)
logging.getLogger("fontTools").setLevel(logging.WARNING)

_TEMPLATE_SOURCE = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {
    size: letter landscape;
    margin: 20mm 12mm 16mm 12mm;
    @bottom-left { content: "FLOD System · CONFIDENTIAL · {{ ctx.report_id }}"; font-family: mono; font-size: 7.5pt; color: #7d838f; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font-family: mono; font-size: 7.5pt; color: #7d838f; }
  }
  @font-face { font-family: sans; src: local("Inter"), local("Segoe UI"), local("Helvetica Neue"), local("DejaVu Sans"); }
  @font-face { font-family: mono; src: local("Cascadia Mono"), local("Consolas"), local("DejaVu Sans Mono"); }
  * { box-sizing: border-box; }
  body { margin: 0; background: #191c22; color: #eef0f3; font-family: sans, sans-serif; font-size: 10.5pt; }
  /* Plain block flow, not flex: a flex column's fragmentation across page
     boundaries is unreliable, and pushes whole blocks to the next page
     even when the remaining space would fit them. */
  .block { break-inside: avoid; page-break-inside: avoid; margin-bottom: 5mm; }
  .block:last-child { margin-bottom: 0; }
  h1, h2, p { margin: 0; }
  h2 { font-size: 12.5pt; font-weight: 600; letter-spacing: -0.01em; }
  .muted { color: #9aa0ab; }
  .dim { color: #6f7581; }
  .mono { font-family: mono, monospace; }
  .label { font-family: mono, monospace; font-size: 7.5pt; letter-spacing: 0.1em; color: #6f7581; text-transform: uppercase; }
  .desc { margin-top: 2pt; margin-bottom: 8pt; font-size: 8.5pt; line-height: 1.5; color: #9aa0ab; }
  .header { display: flex; align-items: flex-end; justify-content: space-between; gap: 16pt; padding-bottom: 10pt; border-bottom: 1px solid #33373f; }
  .header-left { flex: 1 1 auto; min-width: 0; }
  .conf-tag { display: flex; align-items: center; gap: 6pt; font-family: mono, monospace; font-size: 7.5pt; letter-spacing: 0.12em; color: #c8493c; }
  .conf-dot { display: inline-block; width: 5pt; height: 5pt; background: #c8493c; }
  .title { font-size: 20pt; font-weight: 600; letter-spacing: -0.01em; line-height: 1.1; margin-top: 5pt; }
  .subtitle { margin-top: 5pt; max-width: 380pt; font-size: 8.5pt; line-height: 1.5; color: #9aa0ab; }
  .meta { flex: 0 0 auto; display: grid; grid-template-columns: auto auto; gap: 2pt 10pt; font-family: mono, monospace; font-size: 7.5pt; }
  .meta span:nth-child(odd) { color: #6f7581; white-space: nowrap; }
  .tiles { display: grid; gap: 1px; background: #33373f; border: 1px solid #33373f; }
  .tiles.n5 { grid-template-columns: repeat(5, 1fr); }
  .tiles.n4 { grid-template-columns: repeat(4, 1fr); }
  .tiles.n3 { grid-template-columns: repeat(3, 1fr); }
  .tile { background: #20242c; padding: 8pt 10pt; display: flex; flex-direction: column; gap: 3pt; }
  .tile-value { font-size: 16pt; font-weight: 600; }
  .tile-unit { font-size: 8pt; font-weight: 400; color: #6f7581; }
  .tile-sub { font-size: 8pt; color: #9aa0ab; }
  .legend { display: flex; gap: 8pt; margin-top: 4pt; font-family: mono, monospace; font-size: 7.5pt; }
  .legend-item { display: flex; align-items: center; gap: 4pt; color: #adb2bd; white-space: nowrap; }
  .swatch { width: 6pt; height: 6pt; border-radius: 1pt; }
  .chart-wrap { position: relative; padding-left: 26pt; }
  .axis { position: absolute; left: 0; top: 0; bottom: 14pt; width: 22pt; display: flex; flex-direction: column; justify-content: space-between; align-items: flex-end; font-family: mono, monospace; font-size: 6.5pt; color: #6f7581; }
  .plot { position: relative; display: flex; align-items: flex-end; gap: 1px; border-bottom: 1px solid #33373f; }
  .plot-h-large { height: 78pt; }
  .plot-h-small { height: 66pt; }
  .bar-col { flex: 1; display: flex; flex-direction: column; justify-content: flex-end; height: 100%; min-width: 0; }
  .bar-seg { width: 100%; }
  .plot-bar { flex: 1; min-height: 0.5pt; }
  .ticks { display: flex; gap: 1px; margin-top: 3pt; font-family: mono, monospace; font-size: 6pt; color: #6f7581; }
  .tick { flex: 1; text-align: center; white-space: nowrap; }
  .threshold-line { position: absolute; left: 0; right: 0; border-top: 1px dashed; }
  .threshold-label { position: absolute; right: 0; top: -9pt; font-family: mono, monospace; font-size: 6.5pt; letter-spacing: 0.05em; background: rgba(25,28,34,0.9); padding: 1pt 3pt; }
  .phase-grid { display: grid; gap: 1px; background: #33373f; border: 1px solid #33373f; }
  .phase { background: #20242c; padding: 7pt 9pt; display: flex; flex-direction: column; gap: 5pt; break-inside: avoid; }
  .phase-bar { height: 2pt; width: 20pt; }
  .phase-title { font-size: 9.5pt; font-weight: 600; }
  .phase-body { font-size: 8pt; line-height: 1.45; color: #9aa0ab; }
  .two-col { display: grid; grid-template-columns: 1.1fr 1fr; gap: 20pt; }
  .mix-bar { display: flex; height: 16pt; margin-bottom: 8pt; border: 1px solid #33373f; }
  .mix-row { display: grid; grid-template-columns: 8pt 1fr auto auto; align-items: center; gap: 8pt; padding: 4pt 0; border-bottom: 1px solid #2b2f37; font-size: 8.5pt; }
  .mix-count { font-family: mono, monospace; font-size: 8pt; color: #adb2bd; }
  .mix-pct { font-family: mono, monospace; font-size: 8pt; width: 38pt; text-align: right; }
  .barlist-row { display: flex; flex-direction: column; gap: 3pt; margin-bottom: 6pt; }
  .barlist-head { display: flex; justify-content: space-between; font-family: mono, monospace; font-size: 8pt; }
  .barlist-track { height: 6pt; background: #282c34; }
  .barlist-fill { height: 100%; }
  .srclist-row { display: grid; grid-template-columns: 76pt 1fr 30pt; align-items: center; gap: 8pt; margin-bottom: 5pt; }
  .srclist-track { height: 8pt; background: #282c34; }
  .srclist-fill { height: 100%; }
  .blocklist-row { display: grid; grid-template-columns: 76pt 1fr 44pt; align-items: center; gap: 8pt; padding: 4pt 0; border-bottom: 1px solid #2b2f37; font-size: 8pt; }
  .blocklist-track { height: 4pt; background: #282c34; }
  .blocklist-fill { height: 100%; background: #c8493c; }
  .baseline-tile { background: #20242c; padding: 10pt 11pt; display: flex; flex-direction: column; gap: 6pt; break-inside: avoid; }
  .baseline-value { display: flex; align-items: baseline; gap: 5pt; }
  .baseline-value .big { font-size: 15pt; font-weight: 600; }
  .baseline-value .unit { font-size: 8pt; color: #9aa0ab; }
  .gauge-track { position: relative; height: 5pt; background: #282c34; }
  .gauge-fill { position: absolute; left: 0; top: 0; bottom: 0; background: #5b93a8; }
  .gauge-marker { position: absolute; top: -2pt; bottom: -2pt; width: 1.5pt; background: #d99a4a; }
  .baseline-note { font-size: 8pt; line-height: 1.5; color: #9aa0ab; }
  .split-track { display: flex; height: 5pt; gap: 1px; }
  .empty-note { padding: 18pt; text-align: center; color: #6f7581; font-size: 9pt; }
</style>
</head>
<body>
<div class="doc">

  <div class="header block">
    <div class="header-left">
      <div class="conf-tag"><span class="conf-dot"></span><span>CONFIDENTIAL &mdash; INTERNAL USE ONLY</span></div>
      <div class="title">FLOD System &mdash; Incident Report</div>
      <p class="subtitle">Adaptive two-stage Layer-4 volumetric DDoS mitigation gateway.
        {% if ctx.cols %}Covers {{ ctx.window_label }}, {{ ctx.total_records }} classified records.{% else %}No traffic was classified in the selected time window.{% endif %}</p>
    </div>
    <div class="meta">
      <span>REPORT ID</span><span>{{ ctx.report_id }}</span>
      <span>GENERATED</span><span>{{ ctx.generated_at }}</span>
      <span>MODE</span><span>Transparent bridge &middot; {{ ctx.ingress_iface }} &rarr; {{ ctx.egress_iface }}</span>
      <span>VERSION</span><span>{{ ctx.version }}</span>
    </div>
  </div>

  <div class="tiles n5 block">
    <div class="tile">
      <div class="label">Classifier state</div>
      <div class="tile-value">{{ ctx.classifier_state|upper }}</div>
      <div class="tile-sub">at generation time</div>
    </div>
    <div class="tile">
      <div class="label">Hard-blocked</div>
      <div class="tile-value">{{ ctx.blocked_count }}</div>
      <div class="tile-sub">addresses in the kernel block set</div>
    </div>
    <div class="tile">
      <div class="label">Rate-limited</div>
      <div class="tile-value">{{ ctx.ratelimited_count }}</div>
      <div class="tile-sub">addresses under enforcement</div>
    </div>
    <div class="tile">
      <div class="label">Peak packet rate</div>
      <div class="tile-value">{{ ctx.peak_rate_fmt }}<span class="tile-unit"> pps</span></div>
      <div class="tile-sub">{% if ctx.peak_multiple >= 1.5 %}about {{ "%.0f"|format(ctx.peak_multiple) }}&times; the usual ceiling{% else %}within the usual range{% endif %}</div>
    </div>
    <div class="tile">
      <div class="label">Events logged</div>
      <div class="tile-value">{{ ctx.total_records }}</div>
      <div class="tile-sub">{{ ctx.unique_sources }} sources &middot; {{ ctx.unique_victims }} targets</div>
    </div>
  </div>

  {% if ctx.cols %}
  <div class="block">
    <h2>Event volume by classification</h2>
    <div class="legend">
      {% for cls in ["Normal", "Flash Crowd", "Rate Limited", "Blocked"] %}
      <span class="legend-item"><span class="swatch" style="background:{{ colors[cls] }};"></span>{{ cls }}</span>
      {% endfor %}
    </div>
    <p class="desc">One column per {{ ctx.bucket_label }}. Height is the number of classified records logged in that window.</p>
    <div class="chart-wrap">
      <div class="axis">{% for t in ctx.axis_total_ticks %}<span>{{ t }}</span>{% endfor %}</div>
      <div class="plot plot-h-large">
        {% for c in ctx.cols %}
        <div class="bar-col">
          <div class="bar-seg" style="height:{{ c.h_blocked }}; background:{{ colors['Blocked'] }};"></div>
          <div class="bar-seg" style="height:{{ c.h_rl }}; background:{{ colors['Rate Limited'] }};"></div>
          <div class="bar-seg" style="height:{{ c.h_flash }}; background:{{ colors['Flash Crowd'] }};"></div>
          <div class="bar-seg" style="height:{{ c.h_normal }}; background:{{ colors['Normal'] }};"></div>
        </div>
        {% endfor %}
      </div>
      <div class="ticks">{% for c in ctx.cols %}<span class="tick">{{ c.tick }}</span>{% endfor %}</div>
    </div>
  </div>

  <div class="block">
    <h2>Peak packet rate</h2>
    <div class="mono dim" style="font-size:7.5pt; margin-top:4pt;">LOG SCALE &middot; 0 &rarr; {{ ctx.axis_rate_top }} PPS</div>
    <p class="desc">Highest single record's rate in each {{ ctx.bucket_label }}, against the usual ceiling for this network ({{ "%.1f"|format(ctx.rate_threshold_val) }} pps, dashed line). Bars above it are unusual; well above it is a flood.</p>
    <div class="chart-wrap">
      <div class="axis"><span>{{ ctx.axis_rate_top }}</span><span></span><span></span><span>0</span></div>
      <div class="plot plot-h-small">
        <div class="threshold-line" style="bottom:{{ ctx.rate_threshold_pct }}; border-color:#d99a4a;">
          <span class="threshold-label" style="color:#d99a4a;">USUAL CEILING &middot; {{ "%.1f"|format(ctx.rate_threshold_val) }} PPS</span>
        </div>
        {% for c in ctx.cols %}
        <div class="plot-bar" style="height:{{ c.rate_h }}; background:{{ c.rate_color }};"></div>
        {% endfor %}
      </div>
      <div class="ticks">{% for c in ctx.cols %}<span class="tick">{{ c.tick }}</span>{% endfor %}</div>
    </div>
  </div>
  {% else %}
  <div class="empty-note block">No traffic was logged in the selected time window.</div>
  {% endif %}

  {% if ctx.cols %}
  <div class="block">
    <h2>How concentrated traffic was</h2>
    <p class="desc">Average spread of traffic across sources per {{ ctx.bucket_label }} (Shannon entropy). A value near 1.0 means many different sources; a value below the dashed line means traffic was unusually concentrated on very few sources, which is the classic sign of a flood aimed at one address.</p>
    <div class="chart-wrap">
      <div class="axis"><span>1.00</span><span>0.50</span><span>0.00</span></div>
      <div class="plot plot-h-small">
        <div class="threshold-line" style="bottom:{{ ctx.entropy_threshold_pct }}; border-color:#c8493c;">
          <span class="threshold-label" style="color:#c8493c;">USUAL FLOOR &middot; {{ "%.4f"|format(ctx.entropy_threshold_val) }} BITS</span>
        </div>
        {% for c in ctx.cols %}
        <div class="plot-bar" style="height:{{ c.entropy_h }}; background:{{ c.entropy_color }};"></div>
        {% endfor %}
      </div>
      <div class="ticks">{% for c in ctx.cols %}<span class="tick">{{ c.tick }}</span>{% endfor %}</div>
    </div>
  </div>
  {% endif %}

  {% if ctx.phases %}
  <div class="block">
    <h2 style="margin-bottom:8pt;">What the window contains</h2>
    <div class="phase-grid" style="grid-template-columns: repeat({{ ctx.phases|length }}, 1fr);">
      {% for p in ctx.phases %}
      <div class="phase">
        <div class="phase-bar" style="background:{{ p.color }};"></div>
        <div class="label">{{ p.time }}</div>
        <div class="phase-title">{{ p.title }}</div>
        <div class="phase-body">{{ p.body }}</div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <div class="two-col block">
    <div>
      <h2>Classification mix</h2>
      <p class="desc">All {{ ctx.total_records }} records in this window.</p>
      <div class="mix-bar">
        {% for k in ctx.classes_mix %}<div style="width:{{ k.w }}; background:{{ k.color }};"></div>{% endfor %}
      </div>
      {% for k in ctx.classes_mix %}
      <div class="mix-row">
        <span class="swatch" style="background:{{ k.color }};"></span>
        <span>{{ k.name }}</span>
        <span class="mix-count">{{ k.count }}</span>
        <span class="mix-pct">{{ k.pct }}</span>
      </div>
      {% endfor %}
    </div>
    <div>
      <h2>Targets behind the bridge</h2>
      <p class="desc">Events per protected address, most-hit first.</p>
      {% for v in ctx.victims %}
      <div class="barlist-row">
        <div class="barlist-head"><span class="mono">{{ v.ip }}</span><span class="muted">{{ v.n }} events</span></div>
        <div class="barlist-track"><div class="barlist-fill" style="width:{{ v.w }}; background:#5b93a8;"></div></div>
      </div>
      {% else %}
      <p class="desc">No destination addresses recorded.</p>
      {% endfor %}
    </div>
  </div>

  <div class="two-col block">
    <div>
      <h2>Loudest sources</h2>
      <p class="desc">
        Record count per source address.
        {% if ctx.unattributed_source %}The top entry, <strong>{{ ctx.unattributed_source.ip }}</strong>, is not a real address: it is the placeholder logged when a window's traffic could not be pinned to one dominant source, and it accounts for {{ ctx.unattributed_source.n }} of the {{ ctx.total_records }} records here.{% endif %}
      </p>
      {% for s in ctx.sources %}
      <div class="srclist-row">
        <span class="mono" style="font-size:8.5pt; {% if s.unattributed %}color:#d4664f;{% endif %}">{{ s.ip }}</span>
        <div class="srclist-track"><div class="srclist-fill" style="width:{{ s.w }}; background:{% if s.unattributed %}#c8493c{% else %}#5b93a8{% endif %};"></div></div>
        <span class="mono muted" style="font-size:8.5pt; text-align:right;">{{ s.n }}</span>
      </div>
      {% else %}
      <p class="desc">No source addresses recorded.</p>
      {% endfor %}
    </div>
    <div>
      <h2>Active hard blocks</h2>
      <p class="desc">
        {% if ctx.blocked_ips_total > ctx.blocks|length %}Top {{ ctx.blocks|length }} of {{ ctx.blocked_ips_total }} blocked addresses{% else %}All {{ ctx.blocked_ips_total }} blocked addresses{% endif %}, with time left before the hold expires.
      </p>
      {% for b in ctx.blocks %}
      <div class="blocklist-row">
        <span class="mono">{{ b.ip }}</span>
        <div class="blocklist-track"><div class="blocklist-fill" style="width:{{ b.w }};"></div></div>
        <span class="mono muted" style="text-align:right;">{{ b.left }}</span>
      </div>
      {% else %}
      <p class="desc">No addresses are currently blocked.</p>
      {% endfor %}
    </div>
  </div>

  <div class="block">
    <h2 style="margin-bottom:8pt;">Reading against the baseline</h2>
    <div class="tiles n3">
      <div class="baseline-tile">
        <div class="label">Rate at generation</div>
        <div class="baseline-value"><span class="big">{{ "%.1f"|format(ctx.current_rate) }}</span><span class="unit">pps &middot; {% if ctx.current_rate >= ctx.live_rate_threshold %}above{% else %}below{% endif %} the usual ceiling ({{ "%.1f"|format(ctx.live_rate_threshold) }})</span></div>
        <div class="gauge-track">
          <div class="gauge-fill" style="width:{{ ctx.rate_gauge_pct }};"></div>
          <div class="gauge-marker" style="left:100%;"></div>
        </div>
        <div class="baseline-note">This is a live reading at the moment the report was generated, not an average over the whole window above.</div>
      </div>
      <div class="baseline-tile">
        <div class="label">Entropy at generation</div>
        <div class="baseline-value"><span class="big">{{ "%.4f"|format(ctx.current_entropy) }}</span><span class="unit">bits &middot; {% if ctx.current_entropy >= ctx.live_entropy_threshold %}above{% else %}below{% endif %} the usual floor ({{ "%.4f"|format(ctx.live_entropy_threshold) }})</span></div>
        <div class="gauge-track">
          <div class="gauge-fill" style="width:{{ ctx.entropy_gauge_pct }};"></div>
          <div class="gauge-marker" style="left:{{ ctx.entropy_marker_pct }};"></div>
        </div>
        <div class="baseline-note">{{ ctx.below_entropy_count }} of {{ ctx.cols|length }} windows in this report fell below the usual floor ({{ "%.1f"|format(ctx.below_entropy_pct) }}%).</div>
      </div>
      <div class="baseline-tile">
        <div class="label">Posture vs. traffic</div>
        <div class="baseline-value"><span class="big">{{ ctx.enforced_total }}</span><span class="unit">addresses under enforcement</span></div>
        <div class="split-track">
          <div style="width:{{ ctx.blocked_share_pct }}; background:#c8493c;"></div>
          <div style="width:{{ ctx.ratelimited_share_pct }}; background:#d99a4a;"></div>
        </div>
        <div class="baseline-note">A {{ ctx.classifier_state|upper }} reading describes the traffic sample right now, not the enforcement state. A quiet reading can simply mean enforcement is holding, not that the sources are gone.</div>
      </div>
    </div>
  </div>

</div>
</body>
</html>
"""


def _build_env() -> Environment:
    env = Environment(autoescape=True)
    return env


def render_pdf(ctx: dict) -> bytes:
    env = _build_env()
    template = env.from_string(_TEMPLATE_SOURCE)
    ctx = dict(ctx)
    ctx.setdefault("bucket_label", _bucket_label(ctx))
    html = template.render(ctx=ctx, colors=_import_colors())
    return HTML(string=html, base_url=".").write_pdf()


def _bucket_label(ctx: dict) -> str:
    seconds = None
    cols = ctx.get("cols") or []
    if len(cols) >= 2:
        seconds = cols[1]["start"] - cols[0]["start"]
    if not seconds:
        seconds = 60
    if seconds < 3600:
        return f"{int(seconds // 60)}-minute window"
    return f"{int(seconds // 3600)}-hour window"


def _import_colors():
    from report_data import COLORS
    return COLORS
