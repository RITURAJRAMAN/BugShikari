"""
# BugShikari - Module 4: Technology Fingerprinter
Identifies technologies, frameworks, and server software used by a target.
"""

import re

import utils

# ─── Fingerprint Signatures ───────────────────────────────────────────
# Maps header values / HTML patterns to technology names

HEADER_SIGNATURES = {
    "Server": {
        "gws": "Google Web Server (GWS)",
        "gfe": "Google Front End (GFE)",
        "GSE": "Google Servlet Engine",
        "ESF": "Google ESF",
        "nginx": "Nginx",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "ATS": "Apache Traffic Server",
        "sffe": "Google Static File Frontend",
    },
    "X-Powered-By": {
        "Express": "Express.js (Node.js)",
        "PHP": "PHP",
        "ASP.NET": "ASP.NET",
        "Next.js": "Next.js",
        "Phusion Passenger": "Phusion Passenger (Ruby)",
    },
    "X-Content-Type-Options": {},
    "Via": {
        "google": "Google HTTP Proxy",
        "1.1 google": "Google HTTP/1.1 Proxy",
    },
}

HTML_SIGNATURES = [
    # (pattern, technology_name, category)
    (r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', "CMS/Generator: {0}", "CMS"),
    (r'wp-content/', "WordPress", "CMS"),
    (r'drupal\.js|Drupal\.settings', "Drupal", "CMS"),
    (r'/sites/default/files/', "Drupal", "CMS"),
    (r'joomla', "Joomla", "CMS"),

    # JS Frameworks
    (r'angular[./]', "Angular", "Framework"),
    (r'ng-app|ng-controller|ng-model', "AngularJS (1.x)", "Framework"),
    (r'react\.production\.min\.js|react-dom', "React", "Framework"),
    (r'__NEXT_DATA__|_next/static', "Next.js", "Framework"),
    (r'vue\.js|Vue\.component|v-bind|v-model', "Vue.js", "Framework"),
    (r'svelte', "Svelte", "Framework"),
    (r'ember\.js|Ember\.', "Ember.js", "Framework"),
    (r'backbone\.js|Backbone\.', "Backbone.js", "Framework"),

    # Google-specific
    (r'closure/goog/', "Google Closure Library", "Google"),
    (r'/_/scs/', "Google SCS (Shared Common Services)", "Google"),
    (r'gstatic\.com', "Google Static Content (gstatic)", "Google"),
    (r'apis\.google\.com', "Google APIs", "Google"),
    (r'accounts\.google\.com', "Google Accounts", "Google"),
    (r'fonts\.googleapis\.com', "Google Fonts", "Google"),
    (r'www\.googletagmanager\.com', "Google Tag Manager", "Analytics"),
    (r'www\.google-analytics\.com|gtag\(', "Google Analytics", "Analytics"),
    (r'recaptcha', "Google reCAPTCHA", "Google"),
    (r'firebase', "Firebase", "Google"),
    (r'material.*icons|material-design', "Material Design", "Google"),

    # Analytics & Tracking
    (r'hotjar\.com', "Hotjar", "Analytics"),
    (r'segment\.com|analytics\.js', "Segment", "Analytics"),
    (r'facebook.*pixel|fbq\(', "Facebook Pixel", "Analytics"),

    # Libraries
    (r'jquery[.\-/]', "jQuery", "Library"),
    (r'bootstrap[.\-/]', "Bootstrap", "Library"),
    (r'tailwindcss|tailwind', "Tailwind CSS", "Library"),
    (r'lodash', "Lodash", "Library"),
    (r'moment\.js|moment\.min\.js', "Moment.js", "Library"),
    (r'socket\.io', "Socket.IO", "Library"),
    (r'polyfill\.io', "Polyfill.io", "Library"),

    # Security-related
    (r'cloudflare', "Cloudflare", "CDN/Security"),
    (r'akamai', "Akamai", "CDN/Security"),
    (r'fastly', "Fastly", "CDN/Security"),
]

COOKIE_SIGNATURES = {
    "JSESSIONID": "Java (Servlet/JSP)",
    "PHPSESSID": "PHP",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django/Python",
    "laravel_session": "Laravel (PHP)",
    "connect.sid": "Express.js (Node.js)",
    "_rails_session": "Ruby on Rails",
    "NID": "Google NID Cookie",
    "SID": "Google Session ID",
    "HSID": "Google HSID",
    "SSID": "Google SSID",
    "APISID": "Google API SID",
    "SAPISID": "Google SAPISID",
    "__Secure-": "Secure Cookie Prefix (Modern)",
    "__Host-": "Host Cookie Prefix (Strong)",
    "1P_JAR": "Google 1P_JAR",
    "CONSENT": "Google Consent Cookie",
}


def fingerprint_headers(headers: dict) -> list[dict]:
    """Identify technologies from HTTP response headers."""
    technologies = []
    seen = set()

    for header_name, signatures in HEADER_SIGNATURES.items():
        value = headers.get(header_name, "")
        if not value:
            continue

        for signature, tech_name in signatures.items():
            if signature.lower() in value.lower() and tech_name not in seen:
                technologies.append({
                    "technology": tech_name,
                    "source": f"Header: {header_name}",
                    "evidence": f"{header_name}: {value}",
                    "category": "Server/Infrastructure",
                })
                seen.add(tech_name)

        # If we found a header but no known signature, still report the raw value
        if value and header_name in ("Server", "X-Powered-By") and not any(
                sig.lower() in value.lower() for sig in signatures
        ):
            tech_name = f"Unknown ({value})"
            if tech_name not in seen:
                technologies.append({
                    "technology": tech_name,
                    "source": f"Header: {header_name}",
                    "evidence": f"{header_name}: {value}",
                    "category": "Server/Infrastructure",
                })
                seen.add(tech_name)

    return technologies


def fingerprint_html(html: str) -> list[dict]:
    """Identify technologies from HTML content."""
    technologies = []
    seen = set()

    for pattern, tech_template, category in HTML_SIGNATURES:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            # Format tech name with capture groups if present
            tech_name = tech_template.format(*match.groups()) if match.groups() else tech_template
            if tech_name not in seen:
                technologies.append({
                    "technology": tech_name,
                    "source": "HTML Content",
                    "evidence": match.group(0)[:100],
                    "category": category,
                })
                seen.add(tech_name)

    return technologies


def fingerprint_cookies(cookies) -> list[dict]:
    """Identify technologies from cookie names."""
    technologies = []
    seen = set()

    for cookie in cookies:
        for signature, tech_name in COOKIE_SIGNATURES.items():
            if signature.lower() in cookie.name.lower() and tech_name not in seen:
                technologies.append({
                    "technology": tech_name,
                    "source": "Cookie",
                    "evidence": f"Cookie: {cookie.name}",
                    "category": "Session/Auth",
                })
                seen.add(tech_name)

    return technologies


def analyze_target(url: str) -> dict:
    """
    Perform full technology fingerprinting on a target.

    Args:
        url: Target URL

    Returns:
        Dict with fingerprinting results
    """
    response = utils.make_request(url)
    if response is None:
        return {"url": url, "error": "Failed to reach target", "technologies": []}

    technologies = []

    # Fingerprint from headers
    technologies.extend(fingerprint_headers(dict(response.headers)))

    # Fingerprint from HTML
    technologies.extend(fingerprint_html(response.text))

    # Fingerprint from cookies
    technologies.extend(fingerprint_cookies(response.cookies))

    # Deduplicate
    seen = set()
    unique_techs = []
    for tech in technologies:
        if tech["technology"] not in seen:
            unique_techs.append(tech)
            seen.add(tech["technology"])

    return {
        "url": url,
        "status_code": response.status_code,
        "technologies": unique_techs,
    }


def run(targets: list[str]) -> list[dict]:
    """
    Run technology fingerprinting across multiple targets.

    Args:
        targets: List of URLs to fingerprint

    Returns:
        List of fingerprinting results
    """
    utils.print_section_header(
        "🔬 Module 4: Technology Fingerprinter",
        f"Identifying technologies for {len(targets)} target(s)"
    )

    all_results = []

    for target in targets:
        url = target if target.startswith("http") else f"https://{target}"
        utils.print_status(f"Fingerprinting: {url}")

        result = analyze_target(url)
        all_results.append(result)

        if result.get("error"):
            utils.print_error(f"Failed: {result['error']}")
            continue

        # Group by category
        categories = {}
        for tech in result["technologies"]:
            cat = tech.get("category", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tech)

        # Print results table
        table = utils.create_table(
            f"Technologies — {url}",
            [
                ("Technology", "bold white"),
                ("Category", "yellow"),
                ("Source", "cyan"),
                ("Evidence", "dim"),
            ],
        )

        for category in sorted(categories.keys()):
            for tech in categories[category]:
                table.add_row(
                    tech["technology"],
                    category,
                    tech["source"],
                    tech["evidence"][:60],
                )

        utils.console.print(table)

        if not result["technologies"]:
            utils.print_finding("info", "No technologies identified", "The target may use custom/unrecognized tech")

        utils.console.print()

    # Save results
    utils.save_results(
        "tech_fingerprint",
        all_results,
        targets[0] if targets else "unknown",
    )

    return all_results
