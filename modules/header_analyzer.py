"""
# BugShikari - Module 2: HTTP Security Header Analyzer
Analyzes HTTP response headers for security misconfigurations.
"""

import config
import utils


def analyze_headers(url: str) -> dict:
    """
    Analyze HTTP security headers for a given URL.

    Args:
        url: The URL to analyze (e.g., 'https://mail.google.com')

    Returns:
        Dict with header analysis results
    """
    response = utils.make_request(url)
    if response is None:
        return {"url": url, "error": "Failed to reach the target", "headers": {}, "findings": []}

    headers = dict(response.headers)
    findings = []
    header_results = {}

    for header_name, header_info in config.SECURITY_HEADERS.items():
        value = headers.get(header_name)
        result = {
            "header": header_name,
            "description": header_info["description"],
            "value": value,
            "present": value is not None,
            "required": header_info.get("required", False),
        }

        if value is None:
            if header_info.get("required"):
                result["status"] = "missing"
                result["severity"] = "medium"
                findings.append({
                    "severity": "medium",
                    "title": f"Missing header: {header_name}",
                    "detail": header_info["description"],
                })
            else:
                result["status"] = "absent"
                result["severity"] = "info"
        else:
            # Check for weak configurations
            result["status"] = "present"
            result["severity"] = "ok"

            # Specific value checks
            if header_name == "X-Content-Type-Options" and value.lower() != "nosniff":
                result["status"] = "weak"
                result["severity"] = "low"
                findings.append({
                    "severity": "low",
                    "title": f"Weak {header_name}: {value}",
                    "detail": "Expected 'nosniff'",
                })

            if header_name == "Strict-Transport-Security":
                if "max-age=0" in value.lower():
                    result["status"] = "weak"
                    result["severity"] = "medium"
                    findings.append({
                        "severity": "medium",
                        "title": "HSTS disabled (max-age=0)",
                        "detail": "The site sets HSTS but with max-age=0, effectively disabling it",
                    })
                elif "max-age" in value.lower():
                    try:
                        max_age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
                        if max_age < 31536000:  # Less than 1 year
                            result["status"] = "weak"
                            result["severity"] = "low"
                            findings.append({
                                "severity": "low",
                                "title": f"HSTS max-age is short ({max_age}s)",
                                "detail": "Recommended: at least 31536000 (1 year)",
                            })
                        if "includesubdomains" not in value.lower():
                            findings.append({
                                "severity": "info",
                                "title": "HSTS does not include subdomains",
                                "detail": "Consider adding includeSubDomains directive",
                            })
                    except (ValueError, IndexError):
                        pass

            if header_name == "X-Frame-Options":
                val_lower = value.lower()
                if val_lower not in ("deny", "sameorigin"):
                    result["status"] = "weak"
                    result["severity"] = "low"
                    findings.append({
                        "severity": "low",
                        "title": f"Unusual X-Frame-Options: {value}",
                        "detail": "Expected 'DENY' or 'SAMEORIGIN'",
                    })

            if header_name == "Referrer-Policy":
                risky_policies = ["unsafe-url", "no-referrer-when-downgrade"]
                if value.lower() in risky_policies:
                    result["status"] = "weak"
                    result["severity"] = "low"
                    findings.append({
                        "severity": "low",
                        "title": f"Permissive Referrer-Policy: {value}",
                        "detail": "This may leak sensitive URL information",
                    })

        header_results[header_name] = result

    # Check for information disclosure headers
    info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
    for h in info_headers:
        if h in headers:
            findings.append({
                "severity": "info",
                "title": f"Information disclosure: {h}: {headers[h]}",
                "detail": "Server version information may help attackers",
            })

    # Check for interesting custom headers
    for h, v in headers.items():
        h_lower = h.lower()
        if h_lower.startswith("x-") and h not in config.SECURITY_HEADERS and h not in info_headers:
            if any(keyword in h_lower for keyword in ["debug", "trace", "internal", "backend", "upstream"]):
                findings.append({
                    "severity": "low",
                    "title": f"Interesting custom header: {h}: {v}",
                    "detail": "This header may reveal internal infrastructure details",
                })

    return {
        "url": url,
        "status_code": response.status_code,
        "headers": header_results,
        "all_headers": headers,
        "findings": findings,
        "cookies": analyze_cookies(response),
    }


def analyze_cookies(response) -> list[dict]:
    """Analyze cookies for security attributes."""
    cookie_findings = []

    for cookie in response.cookies:
        info = {
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
            "samesite": None,
            "issues": [],
        }

        # Check for SameSite
        for attr in ["SameSite", "samesite"]:
            if cookie.has_nonstandard_attr(attr):
                info["samesite"] = cookie.get_nonstandard_attr(attr)

        if not cookie.secure:
            info["issues"].append("Missing Secure flag")
        if not info["httponly"]:
            info["issues"].append("Missing HttpOnly flag")
        if info["samesite"] is None:
            info["issues"].append("Missing SameSite attribute")

        if info["issues"]:
            cookie_findings.append(info)

    return cookie_findings


def run(targets: list[str]) -> list[dict]:
    """
    Run header analysis across multiple targets.

    Args:
        targets: List of URLs to analyze

    Returns:
        List of analysis results
    """
    utils.print_section_header(
        "🛡️ Module 2: HTTP Security Header Analyzer",
        f"Analyzing {len(targets)} target(s)"
    )

    all_results = []

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"
        utils.print_status(f"Analyzing: {url}")

        result = analyze_headers(url)
        all_results.append(result)

        if result.get("error"):
            utils.print_error(f"Failed: {result['error']}")
            continue

        # Print header analysis table
        table = utils.create_table(
            f"Security Headers — {url} (HTTP {result['status_code']})",
            [
                ("Header", "bold white"),
                ("Status", ""),
                ("Value", "dim"),
            ],
        )

        for header_name, info in result["headers"].items():
            status_display = {
                "present": "[green]✅ Present[/green]",
                "missing": "[red]❌ Missing[/red]",
                "weak": "[yellow]⚠️  Weak[/yellow]",
                "absent": "[dim]— Optional[/dim]",
            }.get(info["status"], info["status"])

            value_display = str(info["value"])[:60] if info["value"] else "[dim]-[/dim]"
            table.add_row(header_name, status_display, value_display)

        utils.console.print(table)

        # Print findings
        if result["findings"]:
            utils.console.print(f"\n  [bold]📋 Findings ({len(result['findings'])}):[/bold]")
            for finding in result["findings"]:
                utils.print_finding(finding["severity"], finding["title"], finding.get("detail"))

        # Print cookie issues
        if result["cookies"]:
            utils.console.print(f"\n  [bold]🍪 Cookie Issues:[/bold]")
            for cookie in result["cookies"]:
                issues_str = ", ".join(cookie["issues"])
                utils.print_finding(
                    "low",
                    f"Cookie '{cookie['name']}': {issues_str}",
                    f"Domain: {cookie['domain']}"
                )

    # Save results
    utils.save_results(
        "header_analysis",
        all_results,
        targets[0] if targets else "unknown",
    )

    return all_results
