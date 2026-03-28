"""
# BugShikari - Module 6: CORS Misconfiguration Scanner
Checks for Cross-Origin Resource Sharing misconfigurations.
"""

import utils

# Origins to test for CORS reflection
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.google.com",
    "https://google.com.evil.com",
    "https://notgoogle.com",
    "null",
    "https://google.com%60.evil.com",
    "https://googlex.com",
    "https://sub.google.com",
]


def check_cors(url: str) -> dict:
    """
    Test CORS configuration for a URL by sending requests with various Origin headers.

    Args:
        url: Target URL to test

    Returns:
        Dict with CORS analysis results
    """
    findings = []
    cors_results = []

    for origin in TEST_ORIGINS:
        response = utils.make_request(
            url,
            headers={"Origin": origin},
            timeout=8,
        )
        if response is None:
            continue

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        acam = response.headers.get("Access-Control-Allow-Methods", "")
        acah = response.headers.get("Access-Control-Allow-Headers", "")
        aceo = response.headers.get("Access-Control-Expose-Headers", "")

        result = {
            "origin_sent": origin,
            "acao": acao,
            "acac": acac,
            "acam": acam,
            "acah": acah,
            "aceo": aceo,
            "reflected": acao == origin,
        }
        cors_results.append(result)

        # Check for dangerous CORS configurations
        if acao == origin and origin not in ("https://sub.google.com",):
            severity = "critical" if acac.lower() == "true" else "high"
            findings.append({
                "severity": severity,
                "title": f"Origin reflected: {origin}",
                "detail": (
                        f"ACAO: {acao} | Credentials: {acac}\n"
                        f"An attacker at {origin} can read responses from this endpoint."
                        + (" WITH cookies/credentials!" if acac.lower() == "true" else "")
                ),
            })

        if acao == "*":
            findings.append({
                "severity": "medium",
                "title": "Wildcard ACAO (*)",
                "detail": "Access-Control-Allow-Origin is set to '*'. "
                          "Any origin can read responses (without credentials).",
            })

        if acao == "null" and origin == "null":
            findings.append({
                "severity": "high",
                "title": "Null origin reflected",
                "detail": "The server reflects 'null' as ACAO. Attackers can use "
                          "sandboxed iframes (sandbox='allow-scripts') to send requests "
                          "with a null origin and read responses.",
            })

    # Check for pre-flight bypass
    preflight_response = utils.make_request(
        url,
        method="OPTIONS",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "X-Custom-Header",
        },
        timeout=8,
    )
    if preflight_response is not None:
        acao = preflight_response.headers.get("Access-Control-Allow-Origin", "")
        acam = preflight_response.headers.get("Access-Control-Allow-Methods", "")
        if "PUT" in acam or "DELETE" in acam or "PATCH" in acam:
            findings.append({
                "severity": "medium",
                "title": f"Dangerous methods allowed in CORS preflight: {acam}",
                "detail": "The server allows state-changing methods (PUT/DELETE/PATCH) "
                          "from cross-origin requests.",
            })

    return {
        "url": url,
        "cors_tests": cors_results,
        "findings": findings,
        "has_cors": any(r["acao"] for r in cors_results),
    }


def run(targets: list[str]) -> list[dict]:
    """
    Run CORS misconfiguration checks across targets.

    Args:
        targets: List of URLs

    Returns:
        List of CORS analysis results
    """
    utils.print_section_header(
        "🌐 Module 6: CORS Misconfiguration Scanner",
        f"Testing {len(targets)} target(s) with {len(TEST_ORIGINS)} origin variations"
    )

    all_results = []

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"
        utils.print_status(f"Testing CORS: {url}")

        result = check_cors(url)
        all_results.append(result)

        # Print CORS test results
        table = utils.create_table(
            f"CORS Tests — {url}",
            [
                ("Origin Sent", "bold white"),
                ("ACAO Response", "cyan"),
                ("Credentials", "yellow"),
                ("Reflected?", ""),
            ],
        )

        for test in result["cors_tests"]:
            reflected_display = "[bold red]✅ YES[/bold red]" if test["reflected"] else "[green]No[/green]"
            table.add_row(
                test["origin_sent"],
                test["acao"] or "[dim]-[/dim]",
                test["acac"] or "[dim]-[/dim]",
                reflected_display,
            )

        utils.console.print(table)

        # Print findings
        if result["findings"]:
            utils.console.print(f"\n  [bold]📋 CORS Findings ({len(result['findings'])}):[/bold]")
            for finding in result["findings"]:
                utils.print_finding(finding["severity"], finding["title"], finding.get("detail"))
        elif result["has_cors"]:
            utils.print_success("CORS is configured — no misconfigurations detected")
        else:
            utils.print_finding("info", "No CORS headers present", "This endpoint may not support CORS")

        utils.console.print()

    utils.save_results("cors_scan", all_results, targets[0] if targets else "unknown")
    return all_results
