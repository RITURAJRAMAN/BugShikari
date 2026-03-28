"""
# BugShikari - Module 7: JavaScript File Analyzer
Discovers and analyzes JavaScript files for sensitive data leaks.
Finds API keys, endpoints, tokens, secrets, and internal URLs in JS files.
"""

import math
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

import config
import utils

# Regex patterns for sensitive data in JS files
SENSITIVE_PATTERNS = {
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth Client ID": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Google Cloud Project": r'(?:project[_-]?id|projectId)\s*[:=]\s*["\']([a-z][a-z0-9-]{4,28}[a-z0-9])["\']',
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?:aws_secret|secret_key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    "Generic API Key": r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,64})["\']',
    "Generic Secret": r'(?:secret|private[_-]?key|password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,64})["\']',
    "Bearer Token": r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    "JWT Token": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "Firebase Config": r'firebase[Cc]onfig\s*[:=]\s*\{[^}]+\}',
    "Internal IP": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    "Email Address": r'[a-zA-Z0-9._%+-]+@(?:google\.com|gmail\.com|chromium\.org|youtube\.com)',
    "Slack Webhook": r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]+',
    "GitHub Token": r'gh[ps]_[A-Za-z0-9_]{36}',
}

# Patterns for interesting endpoints/URLs in JS
ENDPOINT_PATTERNS = {
    "Internal API": r'(?:https?://)?(?:internal|staging|dev|test|admin|debug)[.-][a-zA-Z0-9.-]+(?:/[a-zA-Z0-9/._-]*)?',
    "API Endpoint": r'["\'](?:\/api\/v[0-9]+\/[a-zA-Z0-9/_-]+)["\']',
    "GraphQL": r'["\'](?:\/graphql|\/gql)["\']',
    "REST Path": r'["\'](?:\/(?:admin|internal|debug|config|settings|manage|panel|dashboard)\/[a-zA-Z0-9/_-]*)["\']',
    "Absolute URL": r'https?://[a-zA-Z0-9.-]+\.google\.com(?:/[a-zA-Z0-9/._?&=-]*)?',
    "WebSocket": r'wss?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9/._-]*)?',
    "Redirect Param": r'(?:redirect|return|next|url|goto|target|rurl|dest|destination|redir|redirect_uri|return_url|continue)\s*[:=]',
    "Source Map": r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Higher entropy (close to 6-8) indicates randomness (keys, encrypted data).
    English text is usually around 3.5-4.5.
    """
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def find_high_entropy_strings(text: str, threshold: float = 4.5) -> list[dict]:
    """
    Find strings with high entropy (potential secrets).
    """
    candidates = []
    # Find potential strings (quoted) using finditer for position
    for match in re.finditer(r'["\']([A-Za-z0-9+/=]{16,})["\']', text):
        match_str = match.group(1)  # capture group 1

        # Skip common false positives
        if " " in match_str or "/" in match_str or "." in match_str:
            continue

        entropy = calculate_entropy(match_str)
        if entropy > threshold:
            candidates.append({
                "match": match_str,
                "entropy": entropy,
                "start": match.start(),
                "end": match.end()
            })

    return candidates


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """
    Extract JavaScript file URLs from HTML page.

    Args:
        html: HTML content
        base_url: Base URL for resolving relative paths

    Returns:
        List of absolute JS file URLs
    """
    soup = BeautifulSoup(html, "html.parser")
    js_urls = set()

    # Script tags with src
    for script in soup.find_all("script", src=True):
        src = script["src"]
        absolute_url = urljoin(base_url, src)
        js_urls.add(absolute_url)

    # Also look for dynamically loaded scripts in inline code
    for script in soup.find_all("script", src=False):
        if script.string:
            # Find URLs ending in .js
            urls = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', script.string)
            for url in urls:
                if url.startswith("//"):
                    url = "https:" + url
                elif url.startswith("/"):
                    url = urljoin(base_url, url)
                if url.startswith("http"):
                    js_urls.add(url)

    return sorted(js_urls)


def analyze_js_content(js_content: str, js_url: str) -> dict:
    """
    Analyze JavaScript content for sensitive data.

    Args:
        js_content: JavaScript source code
        js_url: URL of the JS file (for context)

    Returns:
        Dict with findings
    """
    findings = []

    def get_context(content: str, start: int, end: int) -> tuple[int, str]:
        """Get line number and code snippet."""
        try:
            line_num = content.count('\n', 0, start) + 1

            # Get the full line content
            line_start = content.rfind('\n', 0, start) + 1
            line_end = content.find('\n', start)
            if line_end == -1: line_end = len(content)

            line_content = content[line_start:line_end].strip()

            # If line is extremely long (minified code), take a window around the match
            if len(line_content) > 300:
                match_len = end - start
                window_start = max(0, (start - line_start) - 100)
                window_end = min(len(line_content), (end - line_start) + match_len + 100)
                line_content = line_content[window_start:window_end]
                if window_start > 0: line_content = "..." + line_content
                if window_end < len(content[line_start:line_end]): line_content = line_content + "..."

            return line_num, line_content
        except Exception:
            return 0, ""

    # Search for sensitive patterns
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        # Use finditer to get match objects with position
        matches_iter = re.finditer(pattern, js_content)
        count = 0
        for match in matches_iter:
            if count >= 5: break
            count += 1

            start, end = match.span()
            match_str = match.group(0)
            line_num, snippet = get_context(js_content, start, end)

            findings.append({
                "type": "sensitive_data",
                "severity": "high" if "key" in pattern_name.lower() or "token" in pattern_name.lower() or "secret" in pattern_name.lower() else "medium",
                "pattern": pattern_name,
                "match": match_str[:100],
                "js_url": js_url,
                "line": line_num,
                "poc": snippet
            })

    # PROCEED WITH DEEP SCAN: Shannon Entropy Check
    high_entropy_results = find_high_entropy_strings(js_content, threshold=config.ENTROPY_THRESHOLD)
    for item in high_entropy_results[:10]:  # Limit to top 10
        match_str = item["match"]
        entropy = item["entropy"]
        start = item["start"]
        end = item["end"]
        line_num, snippet = get_context(js_content, start, end)

        findings.append({
            "type": "high_entropy",
            "severity": "medium",
            "pattern": f"High Entropy ({entropy:.2f})",
            "match": match_str,
            "js_url": js_url,
            "line": line_num,
            "poc": snippet
        })

    # Search for endpoints
    for pattern_name, pattern in ENDPOINT_PATTERNS.items():
        matches_iter = re.finditer(pattern, js_content)
        count = 0
        for match in matches_iter:
            if count >= 10: break

            match_str = match.group(0)
            # Filter out noise
            if len(match_str) < 5 or match_str.startswith("//"):
                continue

            count += 1
            start, end = match.span()
            line_num, snippet = get_context(js_content, start, end)

            findings.append({
                "type": "endpoint",
                "severity": "info",
                "pattern": pattern_name,
                "match": match_str[:200],
                "js_url": js_url,
                "line": line_num,
                "poc": snippet
            })

    # Check for source maps
    if "sourceMappingURL" in js_content:
        # crude context finding for source map
        start = js_content.find("sourceMappingURL")
        end = start + 50
        line_num, snippet = get_context(js_content, start, end)

        findings.append({
            "type": "source_map",
            "severity": "medium",
            "pattern": "Source Map",
            "match": "sourceMappingURL found — original source code may be accessible",
            "js_url": js_url,
            "line": line_num,
            "poc": snippet
        })

    # Check for debug/dev mode indicators
    debug_patterns = [
        (r'(?:debug|DEBUG)\s*[:=]\s*true', "Debug mode enabled"),
        (r'(?:dev|DEV|development)\s*[:=]\s*true', "Development mode flag"),
        (r'console\.\s*(?:log|debug|info|warn|error)\s*\(', "Console logging present"),
        (r'(?:TODO|FIXME|HACK|XXX|BUG)\s*:', "Developer comment/todo"),
    ]

    for pattern, description in debug_patterns:
        matches_iter = re.finditer(pattern, js_content)
        count = 0
        for match in matches_iter:
            if count >= 5: break
            count += 1

            start, end = match.span()
            line_num, snippet = get_context(js_content, start, end)

            findings.append({
                "type": "debug",
                "severity": "low",
                "pattern": description,
                "match": match.group(0)[:100],
                "js_url": js_url,
                "line": line_num,
                "poc": snippet
            })

    return {
        "js_url": js_url,
        "size": len(js_content),
        "findings": findings,
    }


def run(targets: list[str]) -> list[dict]:
    """
    Discover and analyze JavaScript files for sensitive data.

    Args:
        targets: List of URLs to scan

    Returns:
        List of analysis results
    """
    utils.print_section_header(
        "📜 Module 7: JavaScript File Analyzer",
        f"Scanning JS files from {len(targets)} target(s) for secrets & endpoints"
    )

    all_results = []

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"
        utils.print_status(f"Fetching page: {url}")

        # Get the HTML page
        response = utils.make_request(url)
        if response is None:
            utils.print_error(f"Failed to reach {url}")
            continue

        # Extract JS URLs
        js_urls = extract_js_urls(response.text, url)
        utils.print_success(f"Found {len(js_urls)} JavaScript files")

        # Also analyze inline scripts
        soup = BeautifulSoup(response.text, "html.parser")
        inline_scripts = [s.string for s in soup.find_all("script", src=False) if s.string and len(s.string) > 50]

        target_results = {
            "target": url,
            "js_files_found": len(js_urls),
            "inline_scripts_found": len(inline_scripts),
            "analyses": [],
        }

        # Analyze inline scripts
        if inline_scripts:
            utils.print_status(f"Analyzing {len(inline_scripts)} inline scripts...")
            combined_inline = "\n".join(inline_scripts)
            inline_result = analyze_js_content(combined_inline, f"{url} (inline)")
            target_results["analyses"].append(inline_result)

        # Analyze external JS files (limit to 20 to avoid excessive requests)
        js_to_analyze = js_urls[:20]
        if len(js_urls) > 20:
            utils.print_finding("info", f"Limiting analysis to first 20 of {len(js_urls)} JS files")

        for js_url in js_to_analyze:
            utils.print_status(f"Analyzing: {js_url[:80]}...")
            js_response = utils.make_request(js_url, timeout=10)
            if js_response is None:
                continue

            js_result = analyze_js_content(js_response.text, js_url)
            target_results["analyses"].append(js_result)

        all_results.append(target_results)

        # Print summary of findings
        all_findings = []
        for analysis in target_results["analyses"]:
            all_findings.extend(analysis["findings"])  # type: ignore

        if all_findings:
            # Group by type
            sensitive = [f for f in all_findings if f["type"] == "sensitive_data"]
            endpoints = [f for f in all_findings if f["type"] == "endpoint"]
            source_maps = [f for f in all_findings if f["type"] == "source_map"]
            debug = [f for f in all_findings if f["type"] == "debug"]
            high_entropy = [f for f in all_findings if f["type"] == "high_entropy"]

            if sensitive:
                utils.console.print(f"\n  [bold red]🔑 Sensitive Data Found ({len(sensitive)}):[/bold red]")
                table = utils.create_table(
                    "Secrets & Tokens",
                    [
                        ("Type", "bold yellow"),
                        ("Match", "red"),
                        ("Source", "dim"),
                    ],
                )
                for f in sensitive[:20]:
                    table.add_row(f["pattern"], f["match"][:60], f["js_url"][:50])
                utils.console.print(table)

            if high_entropy:
                utils.console.print(f"\n  [bold orange1]🎲 High Entropy Strings ({len(high_entropy)}):[/bold orange1]")
                table = utils.create_table(
                    "High Entropy Strings (Potential Secrets)",
                    [
                        ("Entropy", "bold yellow"),
                        ("Match", "red"),
                        ("Source", "dim"),
                    ],
                )
                for f in high_entropy[:15]:
                    match_str = f["match"][:50] + "..." if len(f["match"]) > 50 else f["match"]
                    table.add_row(f"{f['pattern'].split('(')[1][:-1]}", match_str, f["js_url"][:50])
                utils.console.print(table)

            if endpoints:
                utils.console.print(f"\n  [bold cyan]🔗 Endpoints Discovered ({len(endpoints)}):[/bold cyan]")
                table = utils.create_table(
                    "API Endpoints & URLs",
                    [
                        ("Type", "yellow"),
                        ("Endpoint", "bold green"),
                        ("Source", "dim"),
                    ],
                )
                seen_matches = set()
                for f in endpoints:
                    if f["match"] not in seen_matches:
                        table.add_row(f["pattern"], f["match"][:80], f["js_url"][:50])
                        seen_matches.add(f["match"])
                        if len(seen_matches) >= 30:
                            break
                utils.console.print(table)

            if source_maps:
                utils.console.print(f"\n  [bold yellow]🗺️ Source Maps Found ({len(source_maps)}):[/bold yellow]")
                for f in source_maps:
                    utils.print_finding("medium", f["match"], f["js_url"])

            if debug:
                utils.console.print(f"\n  [bold]🐛 Debug Indicators ({len(debug)}):[/bold]")
                for f in debug:
                    utils.print_finding("low", f"{f['pattern']}: {f['match']}", f["js_url"][:60])
        else:
            utils.print_success(f"No sensitive data found in JS files for {url}")

        utils.console.print()

    utils.save_results("js_analysis", all_results, targets[0] if targets else "unknown")
    return all_results
