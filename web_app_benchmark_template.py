"""Benchmark page HTML template (separated from web_app.py for clarity)."""
import json


def render_benchmark_page(runs: list[str]) -> str:
    if not runs:
        body = """
        <div class="panel">
          <h2 class="section-heading">No benchmark runs yet</h2>
          <p class="muted">Run the benchmark first:</p>
          <pre>python -m benchmarks.security.run_benchmark --compare-baseline</pre>
        </div>
        """
    else:
        options = "".join(f'<option value="{r}">{r}</option>' for r in runs)
        body = f"""
        <div class="panel">
          <div class="selector-row">
            <label for="run-select">Run:</label>
            <select id="run-select" onchange="loadRun(this.value)">{options}</select>
          </div>
        </div>
        <div id="content"><p class="muted">Loading…</p></div>
        <script>
        async function loadRun(runId) {{
          const el = document.getElementById('content');
          el.innerHTML = '<p class="muted">Loading…</p>';
          try {{
            const resp = await fetch(`/api/benchmark/run/${{runId}}`);
            if (!resp.ok) {{
              el.innerHTML = `<div class="panel"><p style="color:#ff8585">Failed: HTTP ${{resp.status}}</p></div>`;
              return;
            }}
            render(await resp.json());
          }} catch (e) {{
            el.innerHTML = `<div class="panel"><p style="color:#ff8585">Error: ${{e}}</p></div>`;
          }}
        }}
        function pct(x) {{ return (x === null || x === undefined) ? 'n/a' : (x * 100).toFixed(2) + '%'; }}
        function metricsCard(title, m, accent) {{
          const lat = m.latency;
          const latStr = lat ? `n=${{lat.n}}, mean=${{(lat.mean_s*1000).toFixed(1)}}ms, p95=${{(lat.p95_s*1000).toFixed(1)}}ms` : 'n/a';
          const rows = [
            ['Attack Success Rate (ASR)', pct(m.asr)],
            ['Block Rate', pct(m.block_rate)],
            ['False Positive Rate', pct(m.false_positive_rate)],
            ['Leakage Rate', pct(m.unauthorized_data_leakage_rate)],
            ['Authorization Accuracy', pct(m.authorization_accuracy)],
            ['Latency', latStr],
          ];
          const tr = rows.map(([k, v]) => `<tr><td>${{k}}</td><td>${{v}}</td></tr>`).join('');
          const counts = m.sample_counts || {{}};
          return `<div class="panel">
            <h3 style="margin-top:0;color:${{accent}}">${{title}}</h3>
            <table class="bench-table">
              <thead><tr><th>Metric</th><th>Value</th></tr></thead>
              <tbody>${{tr}}</tbody>
            </table>
            <p class="muted">Samples: attacks=${{counts.attacks || 0}}, legit=${{counts.legit || 0}}</p>
          </div>`;
        }}
        function render(data) {{
          const t = data.targets || {{}};
          let html = `<p class="muted">Run ID: <code>${{data.run_id}}</code></p>`;
          if (t.secure) html += metricsCard('Secure Gateway', t.secure.metrics, '#69e3a5');
          if (t.baseline) html += metricsCard('Insecure Baseline', t.baseline.metrics, '#ff8585');
          if (data.comparison) {{
            const rows = Object.entries(data.comparison).map(([k, v]) => {{
              const val = v === null ? 'n/a' : (v >= 0 ? '+' : '') + v.toFixed(4);
              return `<tr><td>${{k}}</td><td>${{val}}</td></tr>`;
            }}).join('');
            html += `<div class="panel">
              <h3 style="margin-top:0;color:#526cf5">Comparison (Secure - Baseline)</h3>
              <table class="bench-table">
                <thead><tr><th>Metric</th><th>Delta</th></tr></thead>
                <tbody>${{rows}}</tbody>
              </table>
            </div>`;
          }}
          document.getElementById('content').innerHTML = html;
        }}
        loadRun({json.dumps(runs[0])});
        </script>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Benchmark Dashboard | Secure AI Gateway</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, system-ui, sans-serif;
      --bg: #0b1020; --panel: #11182a; --panel-2: #0d1424;
      --border: #27314b; --text: #e8edf8; --muted: #aab6cf;
      --accent: #526cf5; --allowed: #69e3a5; --blocked: #ff8585; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; background: var(--bg); color: var(--text); }}
    .topnav {{ background: #0e1525; border-bottom: 1px solid var(--border);
      display: flex; padding: 0 24px; gap: 4px; position: sticky; top: 0; z-index: 50; }}
    .topnav a {{ color: var(--muted); text-decoration: none; padding: 14px 22px;
      font-size: 14px; font-weight: 600; border-bottom: 3px solid transparent; }}
    .topnav a:hover {{ color: var(--text); background: rgba(82,108,245,0.08); }}
    .topnav a.active {{ color: var(--text); border-bottom-color: var(--accent); background: rgba(82,108,245,0.12); }}
    header {{ padding: 26px 24px; border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, #11182a, #0e1525); }}
    header h1 {{ margin: 0 0 6px; font-size: clamp(22px, 4vw, 28px); }}
    header p {{ margin: 0; color: var(--muted); font-size: 14px; }}
    main {{ max-width: 960px; margin: 30px auto; padding: 0 18px; }}
    .panel {{ background: var(--panel); border: 1px solid var(--border);
      border-radius: 16px; padding: 22px; margin-bottom: 18px; }}
    .section-heading {{ font-size: 17px; margin: 0 0 8px; }}
    .muted {{ color: var(--muted); font-size: 13px; }}
    code {{ background: var(--panel-2); padding: 2px 8px; border-radius: 4px;
      font-size: 12px; border: 1px solid var(--border); }}
    pre {{ background: var(--panel-2); padding: 12px; border-radius: 8px;
      overflow: auto; border: 1px solid var(--border); font-size: 13px; }}
    .selector-row {{ display: flex; align-items: center; gap: 12px; }}
    .selector-row label {{ font-size: 14px; font-weight: 600; color: #c9d3e8; }}
    .selector-row select {{ flex: 1; padding: 10px 14px; border-radius: 10px;
      border: 1px solid #34415e; background: var(--panel-2);
      color: var(--text); font: inherit; max-width: 400px; }}
    .bench-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
    .bench-table th, .bench-table td {{ border: 1px solid var(--border);
      padding: 10px 14px; text-align: left; font-size: 13.5px; }}
    .bench-table th {{ background: var(--panel-2); font-weight: 600; color: #c9d3e8; }}
  </style>
</head>
<body>
  <nav class="topnav">
    <a href="/">💬 Chat</a>
    <a href="/benchmark" class="active">📊 Benchmark</a>
    <a href="/admin">⚙️ Admin</a>
  </nav>
  <header>
    <h1>Benchmark Dashboard</h1>
    <p>Reproducible security benchmark — Secure Gateway vs Insecure Baseline</p>
  </header>
  <main>{body}</main>
</body>
</html>"""