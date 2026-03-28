"""
# BugShikari - Module 5: Google Dork Query Generator
Generates targeted Google dork queries for reconnaissance.
Does NOT execute searches — outputs queries for manual use.
"""

import config
import utils


def generate_dorks(domain: str) -> dict[str, list[str]]:
    """
    Generate Google dork queries for a given domain.

    Args:
        domain: Target domain (e.g., 'mail.google.com')

    Returns:
        Dict mapping categories to lists of dork queries
    """
    dorks = {}
    for category, templates in config.DORK_TEMPLATES.items():
        dorks[category] = [t.format(domain=domain) for t in templates]
    return dorks


def generate_custom_dorks(domain: str) -> dict[str, list[str]]:
    """
    Generate additional custom dork queries specific to Google services.

    Args:
        domain: Target domain

    Returns:
        Dict with additional dork categories
    """
    custom = {
        "Auth & Sensitive Parameters": [
            f'site:{domain} inurl:"/accounts/"',
            f'site:{domain} inurl:"/oauth/"',
            f'site:{domain} inurl:"/auth/"',
            f'site:{domain} inurl:"callback"',
            f'site:{domain} inurl:"redirect"',
            f'site:{domain} inurl:"return_url" OR inurl:"returnUrl" OR inurl:"next="',
            f'site:{domain} inurl:"token" -inurl:"tokenservice"',
            f'site:{domain} inurl:"debug" OR inurl:"test"',
            f'site:{domain} inurl:"internal" OR inurl:"staging"',
            f'site:{domain} inurl:"graphql" OR inurl:"playground"',
        ],
        "Potential Misconfigurations": [
            f'site:{domain} "phpinfo()"',
            f'site:{domain} "not for distribution"',
            f'site:{domain} "confidential"',
            f'site:{domain} intitle:"Apache2 Ubuntu Default Page"',
            f'site:{domain} intitle:"Welcome to nginx"',
            f'site:{domain} "directory listing for"',
            f'site:{domain} intitle:"Dashboard" inurl:dashboard',
            f'site:{domain} inurl:".git"',
            f'site:{domain} inurl:".svn"',
            f'site:{domain} inurl:".env"',
        ],
        "Subdomain Discovery": [
            f'site:*.{domain} -www',
            f'site:*.{domain} -www -mail -docs -drive',
            f'site:*.*.{domain}',
            f'site:{domain} -site:www.{domain}',
        ],
        "Exposed APIs & Docs": [
            f'site:{domain} inurl:swagger',
            f'site:{domain} inurl:"api-docs"',
            f'site:{domain} inurl:openapi',
            f'site:{domain} intitle:"API Reference"',
            f'site:{domain} inurl:graphql',
            f'site:{domain} inurl:graphiql',
            f'site:{domain} filetype:yaml inurl:api',
            f'site:{domain} filetype:json inurl:openapi',
        ],
    }
    return custom


def run(domain: str) -> dict:
    """
    Generate and display all dork queries for a domain.

    Args:
        domain: Target domain

    Returns:
        Dict with all generated queries
    """
    utils.print_section_header(
        "🔎 Module 5: Google Dork Query Generator",
        f"Target domain: {domain}"
    )

    utils.console.print(
        "\n  [bold yellow]⚠ IMPORTANT:[/bold yellow] These are search queries for you to run "
        "[bold]manually[/bold] in your browser.\n"
        "  Copy-paste them into Google Search. This module does NOT execute searches.\n"
    )

    # Generate standard dorks
    standard_dorks = generate_dorks(domain)

    # Generate custom Google-specific dorks
    custom_dorks = generate_custom_dorks(domain)

    # Combine all dorks
    all_dorks = {**standard_dorks, **custom_dorks}

    # Print all dork categories
    total_queries = 0
    for category, queries in all_dorks.items():
        table = utils.create_table(
            category,
            [
                ("#", "dim"),
                ("Dork Query", "bold green"),
                ("What to Look For", "dim"),
            ],
        )

        tips = get_tips_for_category(category)

        for i, query in enumerate(queries, 1):
            tip = tips[i - 1] if i - 1 < len(tips) else "Check for unexpected results"
            table.add_row(str(i), query, tip)
            total_queries += 1

        utils.console.print(table)
        utils.console.print()

    # Print usage guide
    utils.console.print(
        f"\n  [bold cyan]📊 Total queries generated:[/bold cyan] [bold]{total_queries}[/bold]\n"
    )

    utils.console.print("  [bold]🎯 How to Use These Dorks:[/bold]")
    utils.console.print("  1. Copy a query from above")
    utils.console.print("  2. Paste it into [bold]Google Search[/bold] (google.com)")
    utils.console.print("  3. Look for unexpected or sensitive results")
    utils.console.print("  4. Document any interesting findings with screenshots")
    utils.console.print("  5. Share findings with me for analysis!\n")

    # Save results
    results = {
        "domain": domain,
        "total_queries": total_queries,
        "categories": all_dorks,
    }
    utils.save_results("google_dorks", results, domain)

    return results


def get_tips_for_category(category: str) -> list[str]:
    """Return tips for what to look for in each dork category."""
    tips = {
        "Exposed Files": [
            "Internal documents, policies, or sensitive PDFs",
            "Word docs with metadata or internal info",
            "Spreadsheets with user data or configs",
            "Database dumps or SQL files",
            "Log files with error details or credentials",
            "Environment files with secrets",
            "Configuration files",
            "Backup files (may contain source code)",
            "XML files with API definitions",
            "JSON files with data or configs",
        ],
        "Login & Admin Pages": [
            "Login pages that shouldn't be public",
            "Admin panels with weak auth",
            "Sign-in pages for internal tools",
            "Dashboard access without proper auth",
            "Control panels",
            "Login pages for internal services",
            "Admin portals",
            "Auth endpoints",
        ],
        "Error & Debug Pages": [
            "Error messages revealing stack traces",
            "Stack traces with file paths and versions",
            "Debug endpoints left in production",
            "404 pages revealing internal structure",
            "500 errors with detailed error info",
            "PHP errors showing file paths",
            "Warning messages with sensitive info",
        ],
        "Directory Listings": [
            "Open directories with files",
            "Directory listing enabled on servers",
            "Parent directory access",
        ],
        "Sensitive Information": [
            "Password leaks in log files",
            "API keys in public files",
            "Secrets in JSON configs",
            "Tokens in publicly accessible files",
            "Config files with credentials",
            "Setup pages still accessible",
            "Backup pages with data",
            "Environment variables exposed",
        ],
        "API Endpoints": [
            "API endpoints returning data",
            "Versioned API endpoints",
            "GraphQL endpoints (try introspection)",
            "Swagger/OpenAPI documentation",
            "REST API documentation",
            "API endpoints returning JSON data",
        ],
        "Google-Specific Recon": [
            "Account-related endpoints",
            "OAuth endpoints that may be misconfigured",
            "Auth endpoints with redirect params",
            "Callback URLs that could be exploited",
            "Redirect parameters (open redirect check)",
            "Return URL parameters",
            "Token endpoints",
            "Debug/test endpoints in production",
            "Internal/staging pages publicly accessible",
            "GraphQL playground enabled",
        ],
        "Potential Misconfigurations": [
            "PHP info pages revealing server config",
            "Confidential documents indexed by Google",
            "Internal/confidential content",
            "Default Apache pages (fresh installs)",
            "Default Nginx pages",
            "Directory listing enabled",
            "Dashboard without authentication",
            "Exposed .git directory",
            "Exposed .svn directory",
            "Exposed environment files",
        ],
        "Subdomain Discovery": [
            "Subdomains not found by DNS enumeration",
            "Internal subdomains indexed by Google",
            "Deep subdomains",
            "Non-www subdomains",
        ],
        "Exposed APIs & Docs": [
            "Swagger UI accessible publicly",
            "API documentation pages",
            "OpenAPI specification files",
            "API reference documentation",
            "GraphQL endpoints",
            "GraphiQL interface (interactive)",
            "API definition YAML files",
            "OpenAPI JSON specs",
        ],
    }
    return tips.get(category, ["Check for unexpected or sensitive results"])
