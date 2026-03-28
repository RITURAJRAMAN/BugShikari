"""
BugShikari - HTML Report Generator
Generates a beautiful HTML report from scan results.
"""

import glob
import json
import os
from datetime import datetime

import config
import utils


def generate_html_report(target: str = "unknown") -> str:
    """
    Generate an HTML report from all JSON result files in the results directory.

    Args:
        target: Target domain for the report title

    Returns:
        Path to the generated HTML report
    """
    # Collect all result files
    result_files = glob.glob(os.path.join(config.RESULTS_DIR, "*.json"))
    if not result_files:
        utils.print_error("No result files found. Run some scans first!")
        return ""

    results_data = {}

    # Normalize input target for comparison
    normalized_target_arg = target.lower().replace("https://", "").replace("http://", "").replace("www.", "")
    if "/" in normalized_target_arg:
        normalized_target_arg = normalized_target_arg.split("/")[0]

    for filepath in sorted(result_files):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

                # Filter by target
                if target != "unknown":
                    file_target = data.get("target", "").lower()
                    if not file_target:
                        continue

                    normalized_file_target = file_target.replace("https://", "").replace("http://", "").replace("www.",
                                                                                                                "")
                    if "/" in normalized_file_target:
                        normalized_file_target = normalized_file_target.split("/")[0]

                    # Check if domains match (loose check to allow subdomains/variations)
                    if normalized_target_arg not in normalized_file_target and normalized_file_target not in normalized_target_arg:
                        continue

                module = data.get("module", "unknown")
                if module not in results_data:
                    results_data[module] = []
                results_data[module].append(data)
        except (json.JSONDecodeError, IOError):
            continue

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    all_findings = []
    for module_data_list in results_data.values():
        for data in module_data_list:
            results_content = data.get("results", [])
            if not isinstance(results_content, list):
                results_content = [results_content]

            for result in results_content:
                if isinstance(result, dict):
                    # Propagate URL from result to findings if missing
                    parent_url = result.get('url', result.get('target', ''))
                    
                    current_findings = []

                    # 1. Standard findings list (e.g., header_analyzer, cors_scanner)
                    if "findings" in result and isinstance(result["findings"], list):
                        current_findings.extend(result["findings"])

                    # 2. Nested analyses finding (JS Analyzer specific)
                    elif "analyses" in result and isinstance(result["analyses"], list):
                        for analysis in result["analyses"]:
                            if isinstance(analysis, dict):
                                current_findings.extend(analysis.get("findings", []))
                    
                    # 3. The result itself is a finding (e.g., open_redirect)
                    elif "severity" in result and "title" in result:
                        current_findings.append(result)

                    for finding in current_findings:
                        sev = finding.get("severity", "info").lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1

                        # Ensure finding has a source URL
                        if 'url' not in finding and 'js_url' not in finding and parent_url:
                            finding['url'] = parent_url

                        all_findings.append(finding)

    total_findings = sum(severity_counts.values())
    max_summary_rows = 120
    max_js_rows_per_target = 80
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    module_titles = {
        "subdomain_enum": "Subdomain Enumeration",
        "header_analysis": "HTTP Header Analysis",
        "csp_analysis": "CSP Analysis",
        "tech_fingerprint": "Technology Fingerprinting",
        "google_dorks": "Google Dork Queries",
        "cors_scan": "CORS Scan",
        "js_analysis": "JavaScript Analysis",
        "open_redirect": "Open Redirect Scan",
        "port_scan": "Port Scan",
        "content_discovery": "Content Discovery",
    }
    nav_links = []
    for module_name in results_data:
        nav_links.append(
            f"<a href='#section-{module_name}'>{_escape_html(module_titles.get(module_name, module_name))}</a>"
        )
    module_nav_html = "".join(nav_links)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugShikari Report — {target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-primary: #0f1115;
            --bg-secondary: #151922;
            --bg-card: #1b2130;
            --text-primary: #e7ecf3;
            --text-secondary: #aab4c5;
            --accent-cyan: #58a6ff;
            --accent-blue: #3f85d9;
            --accent-purple: #7a8ba8;
            --accent-green: #7ec699;
            --border-color: #2a3242;
            --shadow-color: rgba(0, 0, 0, 0.22);
            --severity-critical: #ff3d71;
            --severity-high: #ff9f43;
            --severity-medium: #ffcd56;
            --severity-low: #4bc0c0;
            --severity-info: #78909c;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.7;
        }}

        .container {{ max-width: 95%; margin: 0 auto; padding: 1.5rem; }}

        .hero {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.4rem 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 4px 16px var(--shadow-color);
        }}
        .hero-top {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 1rem;
        }}
        .hero h1 {{
            font-size: 1.85rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.3rem;
        }}
        .eyebrow {{
            color: var(--text-secondary);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            margin-bottom: 0.25rem;
        }}
        .hero .subtitle {{ color: var(--text-secondary); font-size: 0.98rem; }}
        .meta-row {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }}
        .meta-chip {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.45rem 0.7rem;
            border: 1px solid var(--border-color);
            border-radius: 999px;
            color: var(--text-secondary);
            background: rgba(255, 255, 255, 0.02);
            font-size: 0.85rem;
        }}

        /* Header */
        .top-nav {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
            position: sticky;
            top: 0;
            z-index: 30;
            padding: 0.65rem;
            background: rgba(15, 17, 21, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 10px;
        }}
        .toolbar {{
            display: flex;
            gap: 0.5rem;
            justify-content: flex-end;
            margin-bottom: 0;
        }}
        .toolbar button {{
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-secondary);
            border-radius: 8px;
            padding: 0.35rem 0.65rem;
            font-size: 0.82rem;
            cursor: pointer;
        }}
        .toolbar button:hover {{
            color: var(--text-primary);
            border-color: var(--accent-cyan);
        }}
        .top-nav a {{
            display: inline-block;
            border: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            text-decoration: none;
            border-radius: 999px;
            padding: 0.35rem 0.7rem;
            font-size: 0.82rem;
        }}
        .top-nav a:hover {{
            color: var(--text-primary);
            border-color: var(--accent-cyan);
            text-decoration: none;
        }}

        /* Summary Section */
        .summary-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1rem;
            text-align: center;
            transition: border-color 0.2s ease;
        }}
        .stat-card:hover {{
            border-color: var(--accent-cyan);
        }}
        .stat-card .count {{
            font-size: 2.2rem;
            font-weight: 700;
            display: block;
            margin-bottom: 0.3rem;
        }}
        .stat-card .label {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .stat-critical .count {{ color: var(--severity-critical); }}
        .stat-high .count {{ color: var(--severity-high); }}
        .stat-medium .count {{ color: var(--severity-medium); }}
        .stat-low .count {{ color: var(--severity-low); }}
        .stat-info .count {{ color: var(--severity-info); }}
        .stat-total .count {{ color: var(--accent-cyan); }}

        .chart-container {{
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            min-height: 260px;
        }}

        /* Sections */
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        .section-header {{
            padding: 1rem 1.2rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
        }}
        .section-header h2 {{
            font-size: 1.08rem;
            color: var(--text-primary);
        }}
        .section-content {{
            padding: 1rem 1.2rem 1.2rem;
        }}

        /* Tables */
        .table-wrapper {{
            width: 100%;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-top: 1rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        thead th {{
            text-align: left;
            padding: 1rem;
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 2px solid var(--border-color);
            white-space: nowrap;
        }}
        tbody td {{
            padding: 1rem;
            vertical-align: top;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            overflow-wrap: anywhere;
        }}
        
        tr {{ transition: background-color 0.2s ease; }}
        tr:nth-child(even) {{ background: rgba(255, 255, 255, 0.01); }}
        tr:hover {{ background: rgba(88, 166, 255, 0.05); }}
        td:first-child, th:first-child {{ border-left: 4px solid transparent; }}
        tr:hover td:first-child {{ border-left-color: var(--accent-cyan); }}

        /* Severity badges */
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.65rem;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}
        .badge-critical {{ background: rgba(255, 61, 113, 0.12); color: var(--severity-critical); border: 1px solid rgba(255, 61, 113, 0.35); }}
        .badge-high {{ background: rgba(255, 159, 67, 0.12); color: var(--severity-high); border: 1px solid rgba(255, 159, 67, 0.35); }}
        .badge-medium {{ background: rgba(255, 205, 86, 0.12); color: var(--severity-medium); border: 1px solid rgba(255, 205, 86, 0.35); }}
        .badge-low {{ background: rgba(75, 192, 192, 0.12); color: var(--severity-low); border: 1px solid rgba(75, 192, 192, 0.35); }}
        .badge-info {{ background: rgba(120, 144, 156, 0.12); color: var(--severity-info); border: 1px solid rgba(120, 144, 156, 0.35); }}

        .detail {{ color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.3rem; }}
        .section-note {{ color: var(--text-secondary); font-size: 0.85rem; margin: 0.8rem 0 0.2rem; }}
        .detail-block {{
            background: rgba(255, 255, 255, 0.02);
            padding: 0.8rem;
            border-radius: 8px;
            margin-top: 0.5rem;
            font-family: 'Fira Code', 'Cascadia Code', monospace;
            font-size: 0.82rem;
            line-height: 1.45;
            white-space: pre-wrap;
            word-break: break-all;
            border: 1px solid var(--border-color);
        }}
        .expandable summary {{
            cursor: pointer;
            color: var(--accent-cyan);
            list-style: none;
            font-size: 0.88rem;
        }}
        .expandable summary::-webkit-details-marker {{ display: none; }}
        code {{
            background: rgba(0, 255, 136, 0.1);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: 'Fira Code', 'Cascadia Code', monospace;
            font-size: 0.85rem;
            color: var(--accent-green);
            border: 1px solid rgba(0, 255, 136, 0.2);
        }}
        a {{
            color: var(--accent-cyan);
            text-decoration: none;
            transition: color 0.2s;
        }}
        a:hover {{
            color: var(--accent-blue);
            text-decoration: underline;
        }}

        .dork-group {{
            margin: 0.5rem 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.35rem 0.7rem;
            background: rgba(255, 255, 255, 0.015);
        }}
        .dork-group > summary {{
            cursor: pointer;
            font-weight: 600;
            color: var(--text-primary);
        }}
        .dork-list {{
            margin: 0.6rem 0 0 1.2rem;
        }}
        .dork-list li {{
            margin-bottom: 0.35rem;
        }}

        body.light-mode {{
            --bg-primary: #f4f7fb;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #5f6c80;
            --accent-cyan: #1f6feb;
            --accent-blue: #1b5fcc;
            --accent-purple: #6b778c;
            --accent-green: #197a45;
            --border-color: #d7deea;
            --shadow-color: rgba(15, 23, 42, 0.07);
        }}

        @media print {{
            body {{
                background: #fff;
                color: #111;
                line-height: 1.4;
            }}
            .toolbar,
            .top-nav,
            #toTopBtn,
            .chart-container,
            script {{
                display: none !important;
            }}
            .container {{
                max-width: none;
                padding: 0;
            }}
            .section,
            .header {{
                box-shadow: none;
                border: 1px solid #bbb;
                page-break-inside: avoid;
            }}
            .table-wrapper {{
                max-height: none;
                overflow: visible;
            }}
            a {{
                color: #111;
                text-decoration: none;
            }}
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 2rem 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        /* Back to top button */
        #toTopBtn {{
            display: none;
            position: fixed;
            bottom: 20px;
            right: 30px;
            z-index: 99;
            border: none;
            outline: none;
            background-color: var(--accent-purple);
            color: white;
            cursor: pointer;
            padding: 15px;
            border-radius: 50%;
            font-size: 18px;
            width: 50px;
            height: 50px;
            transition: background-color 0.3s, transform 0.3s;
        }}
        #toTopBtn:hover {{
            background-color: var(--accent-blue);
            transform: scale(1.1);
        }}

        /* Responsive */
        @media (max-width: 1200px) {{
            .summary-grid {{ grid-template-columns: 1fr; }}
        }}
        @media (max-width: 768px) {{
            .container {{ padding: 1rem; }}
            .header {{ padding: 2rem; }}
            .header h1 {{ font-size: 1.5rem; }}
            .stats-grid {{ grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); }}
            th, td {{ padding: 0.8rem; }}
        }}
        @media (max-width: 480px) {{
            .stats-grid {{ grid-template-columns: 1fr 1fr; }}
            .header .meta {{ flex-direction: column; gap: 0.5rem; }}
        }}
    </style>
</head>
<body>
    <button onclick="scrollToTop()" id="toTopBtn" title="Go to top">↑</button>
    <div class="container">
        <div class="hero">
            <div class="hero-top">
                <div>
                    <div class="eyebrow">BugShikari report</div>
                    <h1>Reconnaissance Summary</h1>
                    <div class="subtitle">Passive security reconnaissance summary</div>
                </div>
                <div class="toolbar">
                    <button type="button" onclick="toggleTheme()" id="themeBtn">Theme</button>
                </div>
            </div>
            <div class="meta-row">
                <span class="meta-chip"><strong>Target:</strong> {target}</span>
                <span class="meta-chip"><strong>Generated:</strong> {timestamp}</span>
                <span class="meta-chip"><strong>Modules:</strong> {len(results_data)}</span>
            </div>
        </div>

        <div class="top-nav">
            {module_nav_html}
        </div>

        <div class="summary-grid">
            <div class="stats-grid">
                <div class="stat-card stat-total">
                    <span class="count">{total_findings}</span>
                    <span class="label">Total</span>
                </div>
                <div class="stat-card stat-critical">
                    <span class="count">{severity_counts['critical']}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="stat-card stat-high">
                    <span class="count">{severity_counts['high']}</span>
                    <span class="label">High</span>
                </div>
                <div class="stat-card stat-medium">
                    <span class="count">{severity_counts['medium']}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="stat-card stat-low">
                    <span class="count">{severity_counts['low']}</span>
                    <span class="label">Low</span>
                </div>
                <div class="stat-card stat-info">
                    <span class="count">{severity_counts['info']}</span>
                    <span class="label">Info</span>
                </div>
            </div>
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
"""

    # Add findings table
    if all_findings:
        sorted_findings = sorted(
            all_findings,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity", "info"), 5)
        )
        displayed_findings = sorted_findings[:max_summary_rows]
        html += """
        <div class="section">
            <div class="section-header">
                <h2>All Findings Summary</h2>
            </div>
            <div class="section-content">
                <p class="section-note">Showing top findings first for readability.</p>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Finding</th>
                            <th>Details</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        for finding in displayed_findings:
            sev = finding.get("severity", "info").lower()
            title = _escape_html(finding.get('title', finding.get('pattern', 'N/A')))
            detail = finding.get('detail', finding.get('match', ''))
            source = finding.get('url', finding.get('js_url', ''))

            # Generate PoC and Impact analysis
            analysis = _get_vulnerability_analysis(finding)

            # Combine detail with analysis
            detail_html = _render_value(detail, 160)
            if analysis:
                detail_html += f"<div style='margin-top: 8px;'>{analysis}</div>"

            html += f"""
                        <tr>
                            <td><span class="badge badge-{sev}">{sev}</span></td>
                            <td>{title}</td>
                            <td>{detail_html}</td>
                            <td>{_render_value(source, 70, code=True)}</td>
                        </tr>
"""
        html += """
                    </tbody>
                </table>
            </div>
        </div>
"""
        if len(sorted_findings) > max_summary_rows:
            html += f"<p class='section-note'>+ {len(sorted_findings) - max_summary_rows} additional findings are available in module sections below.</p>"

    # Module details

    for module_name, data_list in results_data.items():
        title = module_titles.get(module_name, module_name)
        html += f"""
        <div class="section" id="section-{module_name}">
            <div class="section-header">
                <h2>{title}</h2>
            </div>
            <div class="section-content">
                <p class="detail">Scanned at: {data_list[0].get('timestamp', 'N/A')}</p>
"""
        # Module-specific rendering
        if module_name == "subdomain_enum":
            results = data_list[0].get("results", [])
            if isinstance(results, list):
                html += f"<p>Discovered <strong>{len(results)}</strong> subdomains from {len(set(r.get('method') for r in results))} sources.</p>"
                html += "<div class='table-wrapper'><table><thead><tr><th>Subdomain</th><th>IPs</th><th>Method</th><th>HTTP Status</th><th>Title</th></tr></thead><tbody>"
                for r in results[:50]:
                    if isinstance(r, dict):
                        status = f"HTTPS: {r.get('https_status', '-')}, HTTP: {r.get('http_status', '-')}"
                        html += f"<tr><td><code>{_escape_html(r.get('subdomain', ''))}</code></td>"
                        html += f"<td>{_render_value(', '.join(r.get('ips', [])), 60)}</td>"
                        html += f"<td>{_escape_html(r.get('method', ''))}</td>"
                        html += f"<td>{status}</td>"
                        html += f"<td class='detail'>{_render_value(r.get('title', ''), 90)}</td></tr>"
                if len(results) > 50:
                    html += f"<tr><td colspan='5' style='text-align:center;'>... and {len(results) - 50} more.</td></tr>"
                html += "</tbody></table></div>"

        elif module_name == "google_dorks":
            results = data_list[0].get("results", {})
            if isinstance(results, dict):
                categories = results.get("categories", {})
                for cat, queries in categories.items():
                    html += f"<details class='dork-group'><summary>{_escape_html(cat)} ({len(queries)})</summary><ul class='dork-list'>"
                    for q in queries:
                        html += f"<li><a href='https://www.google.com/search?q={_escape_html(q)}' target='_blank' rel='noopener noreferrer'><code>{_escape_html(q)}</code></a></li>"
                    html += "</ul></details>"

        elif module_name == "tech_fingerprint":
            for data in data_list:
                results = data.get("results", [])
                if isinstance(results, list):
                    for result in results:
                        if isinstance(result, dict):
                            techs = result.get("technologies", [])
                            if techs:
                                html += f"<p><strong>{_escape_html(result.get('url', ''))}</strong></p>"
                                html += "<div class='table-wrapper'><table><thead><tr><th>Technology</th><th>Category</th><th>Source</th><th>Details</th></tr></thead><tbody>"
                                for t in techs:
                                    html += f"<tr><td>{_escape_html(t.get('technology', ''))}</td>"
                                    html += f"<td>{_escape_html(t.get('category', ''))}</td>"
                                    html += f"<td class='detail'>{_escape_html(t.get('source', ''))}</td>"
                                    html += f"<td class='detail'>{_escape_html(t.get('version', ''))}</td></tr>"
                                html += "</tbody></table></div>"

        elif module_name == "js_analysis":
            for data in data_list:
                # The 'results' key for js_analysis is a list of dicts, not a dict
                results_list = data.get("results", [])
                if not isinstance(results_list, list): continue

                for result_item in results_list:
                    analyses = result_item.get("analyses", [])
                    if analyses:
                        html += f"<h4>Target: {_escape_html(result_item.get('target', ''))}</h4>"
                        html += f"<p>{result_item.get('js_files_found', 0)} JS files, {result_item.get('inline_scripts_found', 0)} inline scripts.</p>"

                        all_findings = []
                        for analysis in analyses:
                            all_findings.extend(analysis.get("findings", []))

                        if all_findings:
                            dedup = []
                            seen = set()
                            for item in all_findings:
                                key = (
                                    item.get("severity", "info"),
                                    item.get("pattern", ""),
                                    item.get("match", ""),
                                    item.get("js_url", ""),
                                )
                                if key in seen:
                                    continue
                                seen.add(key)
                                dedup.append(item)
                            visible = dedup[:max_js_rows_per_target]
                            html += "<div class='table-wrapper'><table><thead><tr><th>Severity</th><th>Type</th><th>Finding / Match</th><th>Source (Line)</th><th>POC / Context</th></tr></thead><tbody>"
                            for f in visible:
                                sev = f.get("severity", "info")
                                poc_context = f.get('poc', '')
                                if poc_context:
                                    safe_poc = _escape_html(poc_context)
                                    poc_html = (
                                        "<details class='expandable' style='margin-top: 2px;'>"
                                        "<summary style='color: var(--accent-purple); font-size: 0.8rem; cursor: pointer; user-select: none; opacity: 0.9;'>"
                                        "<span style='border-bottom: 1px dashed var(--accent-purple);'>View Context</span>"
                                        "</summary>"
                                        "<div style='margin-top: 4px;'>"
                                        f"<pre style='background: #0d1117; padding: 6px 8px; border-radius: 4px; font-family: \"Fira Code\", monospace; font-size: 0.76rem; color: #e6edf3; overflow-x: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid #30363d; margin: 0;'>{safe_poc}</pre>"
                                        "</div>"
                                        "</details>"
                                    )
                                else:
                                    poc_html = "<span style='color:#555'>-</span>"

                                line_num = f.get('line', '')
                                line_display = f" <span style='color:#888;font-size:0.9em'>(L{line_num})</span>" if line_num else ""

                                html += f"<tr><td><span class='badge badge-{sev}'>{sev}</span></td>"
                                html += f"<td>{_escape_html(f.get('pattern', ''))}</td>"
                                html += f"<td>{_render_value(f.get('match', ''), 60)}</td>"
                                html += f"<td>{_render_value(f.get('js_url', ''), 50, code=True)}{line_display}</td>"
                                html += f"<td>{poc_html}</td></tr>"
                            html += "</tbody></table></div>"
                            if len(dedup) > max_js_rows_per_target:
                                html += f"<p class='section-note'>Showing {max_js_rows_per_target} unique findings for this target. {len(dedup) - max_js_rows_per_target} more hidden for readability.</p>"

        elif module_name == "port_scan":
            for data in data_list:
                results = data.get("results", [])
                if isinstance(results, list) and results:
                    html += "<div class='table-wrapper'><table><thead><tr><th>Port</th><th>State</th><th>Banner</th></tr></thead><tbody>"
                    for r in results:
                        html += f"<tr><td><span class='badge badge-info'>{r.get('port')}</span></td>"
                        html += f"<td>{r.get('state')}</td>"
                        html += f"<td class='detail'>{_render_value(r.get('banner', ''), 90)}</td></tr>"
                    html += "</tbody></table></div>"

        elif module_name == "content_discovery":
            for data in data_list:
                results = data.get("results", [])
                if isinstance(results, list) and results:
                    html += "<div class='table-wrapper'><table><thead><tr><th>Code</th><th>Path</th><th>Size</th><th>Redirect</th></tr></thead><tbody>"
                    for r in results:
                        status = r.get('status_code')
                        status_class = "low"  # default blue
                        if status == 200: status_class = "medium"  # yellow/greenish context
                        if status == 403: status_class = "high"  # Use high for forbidden

                        html += f"<tr><td><span class='badge badge-{status_class}'>{status}</span></td>"
                        html += f"<td>{_render_value(r.get('path', ''), 65, code=True)}</td>"
                        html += f"<td>{r.get('length')}</td>"
                        html += f"<td class='detail'>{_render_value(r.get('redirect') or '', 75)}</td></tr>"
                    html += "</tbody></table></div>"

        # Generic handler for detailed vulnerabilities (CORS, Open Redirect, Headers, CSP, etc.)
        else:
            found_any = False
            for data in data_list:
                results = data.get("results", [])
                # Normalize result structure: can be list of findings, or list of targets having findings
                # Most modules store findings in a list of dicts.

                # Check if 'results' is a list of findings directly
                if isinstance(results, list):
                    findings_list = []
                    # Flatten if results is list of target objects with 'findings' key
                    for r in results:
                        if isinstance(r, dict):
                            if "findings" in r:
                                findings_list.extend(r["findings"])
                            elif "type" in r or "severity" in r:
                                findings_list.append(r)

                    if findings_list:
                        found_any = True
                        html += "<div class='table-wrapper'><table><thead><tr><th>Severity</th><th>Finding / Pattern</th><th>Details / Match</th><th>Source</th></tr></thead><tbody>"
                        for f in findings_list:
                            sev = f.get("severity", "info").lower()
                            title = f.get('title', f.get('pattern', 'Finding'))
                            detail = f.get('detail', f.get('match', ''))
                            source = f.get('url', f.get('target', ''))

                            # Calculate POC
                            analysis = _get_vulnerability_analysis(f)

                            detail_html = _render_value(detail, 90)
                            if analysis:
                                detail_html += f"<div style='margin-top: 5px;'>{analysis}</div>"

                            html += f"<tr><td><span class='badge badge-{sev}'>{sev}</span></td>"
                            html += f"<td>{_escape_html(title)}</td>"
                            html += f"<td>{detail_html}</td>"
                            html += f"<td>{_render_value(source, 50, code=True)}</td></tr>"
                        html += "</tbody></table></div>"

            if not found_any:
                html += "<p class='section-note'>No significant findings or detailed data available for this module.</p>"

        html += "</div></div>"

    # Footer
    html += f"""
        <div class="footer">
            <p>Generated by <a href="https://github.com/BugShikari" target="_blank" rel="noopener noreferrer" style="color: inherit; text-decoration: none;"><strong>BugShikari</strong></a> — Advanced Bug Hunting Toolkit</p>
            <p style="margin-top: 0.5rem; font-size: 0.85rem; opacity: 0.7;">
                <strong>Disclaimer:</strong> This report is generated by an automated scanning toolkit and does not replace a manual penetration test. Always verify findings and their impact through manual analysis before taking any action. The tool may produce false positives or miss certain vulnerabilities.
            </p>
        </div>
    </div>

    <script>
        (function initViewPrefs() {{
            try {{
                const theme = localStorage.getItem("bugshikari_report_theme");
                if (theme === "light") document.body.classList.add("light-mode");
            }} catch (e) {{}}
        }})();

        function toggleTheme() {{
            document.body.classList.toggle("light-mode");
            try {{
                localStorage.setItem(
                    "bugshikari_report_theme",
                    document.body.classList.contains("light-mode") ? "light" : "dark"
                );
            }} catch (e) {{}}
        }}

        // Back to top button logic
        const toTopBtn = document.getElementById("toTopBtn");
        window.onscroll = function() {{
            if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) {{
                toTopBtn.style.display = "block";
            }} else {{
                toTopBtn.style.display = "none";
            }}
        }};
        function scrollToTop() {{
            document.body.scrollTop = 0; // For Safari
            document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
        }}

        // Chart.js logic
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityData = {{
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{{
                label: 'Findings by Severity',
                data: [
                    {severity_counts['critical']},
                    {severity_counts['high']},
                    {severity_counts['medium']},
                    {severity_counts['low']},
                    {severity_counts['info']}
                ],
                backgroundColor: [
                    'rgba(255, 61, 113, 0.5)',
                    'rgba(255, 159, 67, 0.5)',
                    'rgba(255, 205, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(120, 144, 156, 0.5)'
                ],
                borderColor: [
                    '#ff3d71',
                    '#ff9f43',
                    '#ffcd56',
                    '#4bc0c0',
                    '#78909c'
                ],
                borderWidth: 2
            }}]
        }};

        new Chart(ctx, {{
            type: 'doughnut',
            data: severityData,
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{
                            color: 'var(--text-primary)',
                            font: {{
                                size: 14
                            }}
                        }}
                    }},
                    title: {{
                        display: true,
                        text: 'Findings Distribution',
                        color: 'var(--text-primary)',
                        font: {{
                            size: 16
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""

    # Save report
    report_filename = f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join(config.RESULTS_DIR, report_filename)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    utils.print_success(f"HTML report generated: {report_path}")
    return report_path


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _get_vulnerability_analysis(finding: dict) -> str:
    """Generate Impact and PoC steps based on finding type."""
    title = finding.get('title', finding.get('pattern', '')).lower()
    url = finding.get('url', finding.get('js_url', ''))
    match_val = finding.get('match', '')
    detail = finding.get('detail', '')

    impact = ""
    poc = ""

    # 1. CORS Findings
    if "cors" in title or "origin reflected" in title:
        impact = "An attacker can host a malicious website that forces the victim's browser to send requests to this endpoint, allowing them to read sensitive response data."
        poc = f"curl -I -H \"Origin: https://evil.com\" -H \"Access-Control-Request-Method: GET\" \"{url}\""
        if "credentials" in str(finding).lower():
            poc += " -H \"Cookie: session=...\""

    # 2. Open Redirect
    elif "open redirect" in title or "redirect" in title:
        impact = "Attackers can redirect users to malicious sites to conduct phishing attacks or bypass security filters."
        # Attempt to reconstruct the payload into the URL if not present
        poc_url = url
        if "payload" in finding and finding["payload"] not in url:
            poc_url = f"{url}?redirect={finding['payload']}"
        poc = f"curl -I -L \"{poc_url}\""

    # 3. CSP Issues
    elif "csp" in title or "content-security-policy" in title or "unsafe-inline" in title or "unsafe-eval" in title:
        impact = "Weak CSP configuration reduces protection against XSS. "
        if "unsafe-inline" in title: impact += "'unsafe-inline' allows execution of malicious inline scripts."
        elif "unsafe-eval" in title: impact += "'unsafe-eval' allows dynamic code execution (eval)."
        elif "wildcard" in title: impact += "Wildcards allow resources from too many locations."
        
        poc = f"# Verify CSP header:\ncurl -I -s \"{url}\" | grep -i \"Content-Security-Policy\""

    # 4. Secrets / API Keys / Emails
    elif "api key" in title or "secret" in title or "token" in title or "key" in title or "email" in title:
        impact = "Exposure of secrets allows unauthorized access to APIs or services. Leaked emails increase phishing risk."
        search_term = match_val[:20] + "..." if len(match_val) > 20 else match_val
        if not search_term: search_term = "the secret pattern"
        poc = f"# Manual verification:\n1. Open {url}\n2. View Source (Ctrl+U)\n3. Ctrl+F and search for: '{search_term}'\n4. Verify if it's a valid/active credential."

    # 5. Missing Security Headers
    elif "missing header" in title or "hsts" in title or "clickjacking" in title or "frame-options" in title:
        impact = "Missing headers reduce defense-in-depth against Clickjacking (X-Frame-Options) or Man-in-the-Middle attacks (HSTS)."
        poc = f"curl -I -s \"{url}\""

    # 6. Exposed Files / Status Codes / Directories
    elif "status code" in title or "exposed" in title or "directory" in title or "git" in title or "env" in title:
        impact = "Sensitive files or directories exposed to the public can leak source code, configuration, or user data."
        poc = f"curl -I \"{url}\"\n# If 200 OK, try downloading or viewing content."
    
    # 7. High Entropy / Random Strings
    elif "entropy" in title:
        impact = "High entropy strings often indicate hardcoded keys, passwords, or encrypted data."
        poc = f"# Inspect the string context in:\n{url}\n# String: {match_val}"

    # 8. Subdomain / Host
    elif "subdomain" in title or "host" in title:
         impact = "Discovering subdomains expands the attack surface, potentially revealing forgotten dev/staging environments."
         poc = f"host {match_val if match_val else url}"

    # Default / Generic Fallback
    else:
        impact = "This finding represents a potential security configuration issue or information leak that should be reviewed."
        poc = f"# Manual Review:\n1. Analyze the resource at {url}\n2. Verify the presence of: {title}"
        if detail:
            poc += f"\n3. Details: {detail}"

    return f"""
    <details class='expandable' style='margin-top: 3px;'>
        <summary style='color: var(--accent-purple); font-size: 0.8rem; cursor: pointer; user-select: none; opacity: 0.9;'>
            <span style='border-bottom: 1px dashed var(--accent-purple);'>View Impact & PoC</span>
        </summary>
        <div style='background: rgba(88, 166, 255, 0.03); border: 1px solid var(--border-color); margin-top: 4px; padding: 8px; border-radius: 4px; display: grid; grid-template-columns: 60px 1fr; gap: 4px 10px; align-items: start;'>
            
            <div style='color: var(--text-primary); font-weight: 600; font-size: 0.82rem;'>Impact:</div>
            <div style='color: var(--text-secondary); font-size: 0.82rem; line-height: 1.4;'>{impact}</div>
            
            <div style='color: var(--text-primary); font-weight: 600; font-size: 0.82rem; margin-top: 2px;'>PoC:</div>
            <div style='margin-top: 2px;'>
                <pre style='background: #0d1117; padding: 6px 8px; border-radius: 4px; font-family: "Fira Code", monospace; font-size: 0.76rem; color: #e6edf3; overflow-x: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid #30363d; margin: 0;'>{_escape_html(poc)}</pre>
            </div>
        </div>
    </details>
    """


def _render_value(value, max_len: int = 120, code: bool = False) -> str:
    """Render a value as compact HTML with optional expandable full content."""
    raw = "" if value is None else str(value)
    escaped = _escape_html(raw)
    if len(raw) <= max_len:
        return f"<code>{escaped}</code>" if code else escaped

    short = _escape_html(raw[:max_len] + "...")
    short_html = f"<code>{short}</code>" if code else short
    full_html = f"<code>{escaped}</code>" if code else escaped
    return (
        "<details class='expandable'>"
        f"<summary>{short_html}</summary>"
        f"<div class='detail-block'>{full_html}</div>"
        "</details>"
    )
