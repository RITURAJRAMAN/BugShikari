"""
# BugShikari - Module 3: Content Security Policy (CSP) Analyzer
Deep analysis of CSP headers for bypass opportunities.
"""

import re

import config
import utils

# Known JSONP endpoints that can bypass CSP
JSONP_ENDPOINTS = [
    "accounts.google.com/o/oauth2/revoke?callback=",
    "accounts.google.com/ServiceLogin?continue=",
    "ajax.googleapis.com/ajax/libs/",
    "clients1.google.com/generate_204",
    "cse.google.com/cse.js?cx=",
    "maps.googleapis.com/maps/api/js?callback=",
    "translate.googleapis.com/translate_a/element.js?cb=",
    "www.google.com/complete/search?client=chrome&q=test&callback=",
    "www.google.com/jsapi?callback=",
    "www.googleapis.com/customsearch/v1?callback=",
]

# Known Angular/CSTI-prone libraries hosted on CDNs
ANGULAR_CDN_PATHS = [
    "cdnjs.cloudflare.com/ajax/libs/angular.js",
    "ajax.googleapis.com/ajax/libs/angularjs",
    "cdn.jsdelivr.net/npm/angular",
    "unpkg.com/angular",
]


def parse_csp(csp_string: str) -> dict[str, list[str]]:
    """
    Parse a CSP header string into a dict of directive → sources.

    Args:
        csp_string: Raw CSP header value

    Returns:
        Dict mapping directive names to lists of source values
    """
    directives = {}
    # Split by semicolons
    for part in csp_string.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive_name = tokens[0].lower()
            sources = tokens[1:] if len(tokens) > 1 else []
            directives[directive_name] = sources
    return directives


def analyze_csp(url: str) -> dict:
    """
    Perform deep analysis of a target's CSP.

    Args:
        url: URL to analyze

    Returns:
        Dict with CSP analysis results
    """
    response = utils.make_request(url)
    if response is None:
        return {"url": url, "error": "Failed to reach target", "findings": []}

    csp_header = response.headers.get("Content-Security-Policy", "")
    csp_report_only = response.headers.get("Content-Security-Policy-Report-Only", "")

    findings = []
    result = {
        "url": url,
        "status_code": response.status_code,
        "csp_present": bool(csp_header),
        "csp_report_only_present": bool(csp_report_only),
        "csp_raw": csp_header,
        "csp_report_only_raw": csp_report_only,
        "directives": {},
        "findings": findings,
    }

    if not csp_header and not csp_report_only:
        findings.append({
            "severity": "high",
            "title": "No Content-Security-Policy header found",
            "detail": "The page has no CSP at all — any script can execute. This is a potential XSS vector.",
        })
        return result

    # If only report-only is present
    if not csp_header and csp_report_only:
        findings.append({
            "severity": "medium",
            "title": "CSP is in Report-Only mode",
            "detail": "CSP-Report-Only does NOT enforce restrictions. It only reports violations. "
                      "Scripts can still execute without being blocked.",
        })
        csp_to_analyze = csp_report_only
    else:
        csp_to_analyze = csp_header

    directives = parse_csp(csp_to_analyze)
    result["directives"] = directives

    # ─── Check for dangerous directive values ─────────────────────────
    for directive, sources in directives.items():
        for source in sources:
            source_lower = source.lower().strip("'")
            for dangerous, reason in config.CSP_DANGEROUS_DIRECTIVES.items():
                if source_lower == dangerous.strip("'"):
                    severity = "high" if dangerous in ("'unsafe-eval'", "'unsafe-inline'") else "medium"
                    findings.append({
                        "severity": severity,
                        "title": f"{directive}: contains {dangerous}",
                        "detail": reason,
                        "directive": directive,
                        "source": source,
                    })

    # ─── Check for wildcard sources ────────────────────────────────────
    for directive, sources in directives.items():
        if "*" in sources:
            findings.append({
                "severity": "high",
                "title": f"{directive}: wildcard (*) source",
                "detail": "Allows loading resources from ANY origin. Effectively disables CSP for this directive.",
                "directive": directive,
            })

    # ─── Check if default-src is missing ───────────────────────────────
    if "default-src" not in directives:
        findings.append({
            "severity": "medium",
            "title": "Missing default-src directive",
            "detail": "Without default-src, any directive not explicitly set has no restriction.",
        })

    # ─── Check for CDN bypass opportunities ────────────────────────────
    for directive, sources in directives.items():
        if directive in ("script-src", "default-src"):
            for source in sources:
                for cdn in config.CSP_BYPASS_CDNS:
                    if cdn in source:
                        findings.append({
                            "severity": "high",
                            "title": f"{directive}: allows {cdn} (known CSP bypass)",
                            "detail": f"'{cdn}' hosts libraries that can be used to bypass CSP. "
                                      f"Attackers can load Angular.js or other script-gadgets from this CDN.",
                            "directive": directive,
                            "source": source,
                            "bypass_cdn": cdn,
                        })

    # ─── Check for JSONP bypass opportunities ──────────────────────────
    script_sources = directives.get("script-src", []) + directives.get("default-src", [])
    for source in script_sources:
        for jsonp in JSONP_ENDPOINTS:
            jsonp_domain = jsonp.split("/")[0]
            if jsonp_domain in source:
                findings.append({
                    "severity": "high",
                    "title": f"Potential JSONP bypass via {jsonp_domain}",
                    "detail": f"The CSP allows scripts from '{source}', which has a JSONP endpoint at "
                              f"'{jsonp}'. This could be used to execute arbitrary JavaScript.",
                    "jsonp_endpoint": jsonp,
                })

    # ─── Check for data: URI in script-src ─────────────────────────────
    for directive in ("script-src", "default-src"):
        if directive in directives and "data:" in directives[directive]:
            findings.append({
                "severity": "high",
                "title": f"{directive}: allows data: URIs",
                "detail": "data: URIs in script-src allow arbitrary script execution via:\n"
                          '  <script src="data:text/javascript,alert(1)"></script>',
            })

    # ─── Check for missing frame-ancestors (clickjacking) ──────────────
    if "frame-ancestors" not in directives:
        findings.append({
            "severity": "low",
            "title": "Missing frame-ancestors directive",
            "detail": "Without frame-ancestors, the page may be framed by any origin (clickjacking risk). "
                      "Check X-Frame-Options as fallback.",
        })

    # ─── Check for overly permissive connect-src ────────────────────────
    if "connect-src" in directives:
        if "*" in directives["connect-src"] or "data:" in directives["connect-src"]:
            findings.append({
                "severity": "medium",
                "title": "Overly permissive connect-src",
                "detail": "Allows AJAX/WebSocket connections to any origin. "
                          "This could be used for data exfiltration via XSS.",
            })

    # ─── Check for base-uri missing ────────────────────────────────────
    if "base-uri" not in directives:
        findings.append({
            "severity": "low",
            "title": "Missing base-uri directive",
            "detail": "Without base-uri, an attacker injecting a <base> tag could hijack relative URLs.",
        })

    # ─── Check for nonce/hash usage ────────────────────────────────────
    nonce_pattern = re.compile(r"'nonce-[A-Za-z0-9+/=]+'")
    hash_pattern = re.compile(r"'sha(256|384|512)-[A-Za-z0-9+/=]+'")

    for directive in ("script-src", "style-src", "default-src"):
        if directive in directives:
            has_nonce = any(nonce_pattern.match(s) for s in directives[directive])
            has_hash = any(hash_pattern.match(s) for s in directives[directive])

            if has_nonce:
                findings.append({
                    "severity": "info",
                    "title": f"{directive}: Uses nonce-based CSP",
                    "detail": "Nonce-based CSP is strong if the nonce is truly random and not predictable. "
                              "Check if the nonce changes on each page load.",
                })
            if has_hash:
                findings.append({
                    "severity": "info",
                    "title": f"{directive}: Uses hash-based CSP",
                    "detail": "Hash-based CSP is strong but inflexible. "
                              "Check if any script content can be controlled by the attacker.",
                })

    return result


def run(targets: list[str]) -> list[dict]:
    """
    Run CSP analysis across multiple targets.

    Args:
        targets: List of URLs to analyze

    Returns:
        List of CSP analysis results
    """
    utils.print_section_header(
        "🔐 Module 3: CSP Analyzer",
        f"Deep Content-Security-Policy analysis for {len(targets)} target(s)"
    )

    all_results = []

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"
        utils.print_status(f"Analyzing CSP: {url}")

        result = analyze_csp(url)
        all_results.append(result)

        if result.get("error"):
            utils.print_error(f"Failed: {result['error']}")
            continue

        # Print CSP status
        if result["csp_present"]:
            utils.print_success(f"CSP header found")
        if result["csp_report_only_present"]:
            utils.print_finding("info", "CSP-Report-Only header found")

        # Print directives table
        if result["directives"]:
            table = utils.create_table(
                f"CSP Directives — {url}",
                [
                    ("Directive", "bold white"),
                    ("Sources", "cyan"),
                ],
            )
            for directive, sources in sorted(result["directives"].items()):
                sources_str = " ".join(sources) if sources else "[dim]none[/dim]"
                # Truncate long source lists
                if len(sources_str) > 100:
                    sources_str = sources_str[:97] + "..."
                table.add_row(directive, sources_str)

            utils.console.print(table)

        # Print findings
        if result["findings"]:
            utils.console.print(f"\n  [bold]📋 Findings ({len(result['findings'])}):[/bold]")
            for finding in result["findings"]:
                utils.print_finding(finding["severity"], finding["title"], finding.get("detail"))
        else:
            utils.print_success("No significant CSP issues found")

        utils.console.print()

    # Save results
    utils.save_results(
        "csp_analysis",
        all_results,
        targets[0] if targets else "unknown",
    )

    return all_results
