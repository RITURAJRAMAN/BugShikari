"""
BugShikari - Advanced Bug Hunting Toolkit
Main CLI Runner

Usage:
    python main.py --target <domain>              Run all modules
    python main.py --target <domain> --module 1   Run specific module
    python main.py --list-targets                 Show example targets
    python main.py --report                       Generate HTML report
"""

import argparse
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt

import config
import report_generator
import utils
from modules import (
    subdomain_enum,
    header_analyzer,
    csp_analyzer,
    tech_fingerprint,
    google_dorker,
    cors_scanner,
    js_analyzer,
    open_redirect,
    port_scanner,
    content_discovery,
)

console = Console()


def show_menu():
    """Display the interactive module selection menu."""
    console.print("\n  [bold cyan]Available Modules:[/bold cyan]\n")
    modules = [
        ("1", "🔍 Subdomain Enumerator", "Discover subdomains via DNS + Certificate Transparency"),
        ("2", "🛡️ HTTP Header Analyzer", "Check security headers for misconfigurations"),
        ("3", "🔐 CSP Analyzer", "Deep Content-Security-Policy analysis"),
        ("4", "🔬 Technology Fingerprinter", "Identify server tech, frameworks, and libraries"),
        ("5", "🔎 Google Dork Generator", "Generate reconnaissance search queries"),
        ("6", "🌐 CORS Scanner", "Check for CORS misconfigurations"),
        ("7", "📜 JS File Analyzer", "Scan JavaScript files for secrets & endpoints"),
        ("8", "↗️ Open Redirect Scanner", "Test for open redirect vulnerabilities"),
        ("9", "🔌 Port Scanner", "Scan for open ports"),
        ("10", "📂 Content Discovery", "Fuzz directories and files"),
        ("11", "🚀 Run ALL Modules", "Full reconnaissance scan"),
        ("12", "📊 Generate HTML Report", "Create a beautiful HTML report from scan results"),
        ("0", "❌ Exit", ""),
    ]

    table = utils.create_table(
        "Module Selection",
        [
            ("#", "bold yellow"),
            ("Module", "bold white"),
            ("Description", "dim"),
        ],
    )
    for num, name, desc in modules:
        table.add_row(num, name, desc)
    console.print(table)


def list_inscope_targets():
    """Display example in-scope domains."""
    utils.print_section_header(
        "🎯 Example Bug Bounty Targets",
        "These are some common domains with bug bounty programs."
    )

    table = utils.create_table(
        "Example Targets",
        [
            ("#", "dim"),
            ("Domain", "bold green"),
            ("Wildcard", "cyan"),
        ],
    )
    for i, domain in enumerate(config.IN_SCOPE_DOMAINS, 1):
        table.add_row(str(i), domain, f"*.{domain}")

    console.print(table)

    console.print(
        "\n  [bold yellow]⚠ Note:[/bold yellow] Always verify the scope of the program before hunting.\n"
        "  Check platforms like HackerOne, Bugcrowd, or the company's security page.\n"
    )


def sanitize_target(target: str) -> str:
    """Clean the target string to get the bare domain/hostname."""
    if not target:
        return ""
    
    target = target.strip().lower()
    
    # Remove protocol
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    
    # Remove trailing slash and paths
    if "/" in target:
        target = target.split("/")[0]
        
    return target


def get_target_urls(domain: str) -> list[str]:
    """Convert a domain to a list of URLs to test."""
    # Ensure domain is clean
    domain = sanitize_target(domain)
    
    urls = [f"https://{domain}"]

    # If it's a base domain, add common subdomains
    if domain.count(".") == 1:  # e.g., 'google.com'
        common_subs = ["www", "mail", "accounts", "docs", "drive", "maps", "cloud"]
        for sub in common_subs:
            urls.append(f"https://{sub}.{domain}")

    return urls


def run_module(module_num: int, target: str):
    """Run a specific module."""
    # Sanitize target for modules that expect a domain
    clean_target = sanitize_target(target)
    
    if module_num == 1:
        subdomain_enum.run(clean_target)

    elif module_num == 2:
        urls = get_target_urls(clean_target)
        header_analyzer.run(urls)

    elif module_num == 3:
        urls = get_target_urls(clean_target)
        csp_analyzer.run(urls)

    elif module_num == 4:
        urls = get_target_urls(clean_target)
        tech_fingerprint.run(urls)

    elif module_num == 5:
        google_dorker.run(clean_target)

    elif module_num == 6:
        urls = get_target_urls(clean_target)
        cors_scanner.run(urls)

    elif module_num == 7:
        urls = get_target_urls(clean_target)
        js_analyzer.run(urls)

    elif module_num == 8:
        urls = get_target_urls(clean_target)
        valid_urls = [u for u in urls if u.startswith("http")]
        open_redirect.run(valid_urls)

    elif module_num == 9:
        port_scanner.run(clean_target)

    elif module_num == 10:
        content_discovery.run(clean_target)

    elif module_num == 11:
        run_all(clean_target)

    elif module_num == 12:
        report_path = report_generator.generate_html_report(clean_target)
        if report_path:
            utils.print_success(f"Report generated: {report_path}")
            # Try to open the report
            try:
                os.startfile(report_path)
            except AttributeError:
                pass  # Not on Windows

    elif module_num == 0:
        sys.exit(0)



def run_all(target: str):
    """Run all modules sequentially."""
    console.print(
        Panel(
            f"[bold green]🚀 Running full reconnaissance on: {target}[/bold green]\n"
            f"[dim]Executing all modules with deep scanning enabled[/dim]",
            border_style="green",
        )
    )

    # 1. Subdomain Enum
    utils.print_section_header("Module 1/10", "Subdomain Enumeration")
    subdomains = subdomain_enum.run(target)

    # Collect URLs for other modules
    urls = [f"https://{target}", f"http://{target}"]
    if subdomains:
        for s in subdomains[:15]:  # Limit to top 15 to avoid excessive scan times
            if s.get("subdomain"):
                urls.append(f"https://{s['subdomain']}")

    urls = list(set(urls))  # Deduplicate
    utils.print_status(f"Targeting {len(urls)} URLs for deep analysis")

    # 2. Port Scan (Main target only)
    utils.print_section_header("Module 2/10", "Port Scanner")
    port_scanner.run(target)

    # 3. Headers
    utils.print_section_header("Module 3/10", "HTTP Header Analyzer")
    header_analyzer.run(urls)

    # 4. CSP
    utils.print_section_header("Module 4/10", "CSP Analyzer")
    csp_analyzer.run(urls)

    # 5. Tech Fingerprint
    utils.print_section_header("Module 5/10", "Technology Fingerprinter")
    tech_fingerprint.run(urls)

    # 6. Google Dorks
    utils.print_section_header("Module 6/10", "Google Dork Generator")
    google_dorker.run(target)

    # 7. CORS
    utils.print_section_header("Module 7/10", "CORS Scanner")
    cors_scanner.run(urls)

    # 8. JS Analysis
    utils.print_section_header("Module 8/10", "JS File Analyzer")
    js_analyzer.run(urls)

    # 9. Open Redirect
    utils.print_section_header("Module 9/10", "Open Redirect Scanner")
    open_redirect.run(urls)

    # 10. Content Discovery (Main target only)
    utils.print_section_header("Module 10/10", "Content Discovery")
    content_discovery.run(target)

    # Generate HTML report
    console.print(f"\n  [bold cyan]{'─' * 60}[/bold cyan]")
    console.print(f"  [bold cyan]Generating HTML Report[/bold cyan]\n")
    report_path = report_generator.generate_html_report(target)

    # Summary
    console.print(
        Panel(
            "[bold green]✅ Full reconnaissance complete![/bold green]\n\n"
            f"  📁 Results saved in: [bold]{config.RESULTS_DIR}[/bold]\n"
            + (f"  📊 HTML Report: [bold]{report_path}[/bold]\n" if report_path else "")
            + "  📋 Review the JSON files for detailed findings.\n"
              "  🎯 Use the Google Dork queries manually in your browser.\n"
              "  📝 Use report_template.md to document any bugs found.",
            title="[bold]Scan Complete[/bold]",
            border_style="green",
        )
    )


def interactive_mode():
    """Run in interactive mode with a menu."""
    utils.print_banner()

    console.print(
        Panel(
            "[bold]Welcome to BugShikari![/bold]\n\n"
            "This toolkit performs [green]passive reconnaissance[/green] to help you find\n"
            "potential security issues in Google's VRP in-scope targets.\n\n"
            "[yellow]⚡ All scans are non-intrusive and legal.[/yellow]\n"
            "[yellow]📖 Always follow Google VRP rules:[/yellow] [link]https://bughunters.google.com[/link]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )

    # Get target
    target = Prompt.ask(
        "\n  [bold cyan]Enter target domain[/bold cyan]",
        default="google.com",
    )

    # Validate target is in scope
    is_in_scope = any(
        target == domain or target.endswith(f".{domain}")
        for domain in config.IN_SCOPE_DOMAINS
    )
    if not is_in_scope:
        console.print(
            f"\n  [bold yellow]⚠ Warning:[/bold yellow] '{target}' may not be in Google VRP scope.\n"
            "  Proceed with caution. Type 'list' to see in-scope domains.\n"
        )

    while True:
        show_menu()
        try:
            choice = IntPrompt.ask("\n  [bold]Select module[/bold]", default=11)
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [dim]Goodbye! 👋[/dim]")
            break

        if choice == 0:
            console.print("\n  [dim]Goodbye! Happy bug hunting! 🐛[/dim]")
            break
        elif 1 <= choice <= 12:
            try:
                run_module(choice, target)
            except KeyboardInterrupt:
                console.print("\n  [yellow]Scan interrupted.[/yellow]")
            except Exception as e:
                utils.print_error(f"Module error: {e}")
        else:
            console.print("  [red]Invalid choice. Pick 0-12.[/red]")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BugShikari — Google VRP Bug Hunting Toolkit (Advanced)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                    Interactive mode
  python main.py --target google.com                Run all 8 modules
  python main.py --target mail.google.com -m 2      Header analyzer
  python main.py --target google.com -m 6           CORS scanner
  python main.py --target google.com -m 7           JS file analyzer
  python main.py --target google.com -m 8           Open redirect scanner
  python main.py --target google.com -m 9           Port scanner
  python main.py --target google.com -m 10          Content discovery
  python main.py --report google.com                Generate HTML report
  python main.py --list-targets                     Show in-scope domains
        """,
    )
    parser.add_argument(
        "--target", "-t",
        help="Target domain (e.g., google.com, mail.google.com)",
    )
    parser.add_argument(
        "--module", "-m",
        type=int,
        choices=list(range(1, 13)),
        help="Module to run (1-10 individual, 11=all, 12=report)",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List example in-scope domains",
    )
    parser.add_argument(
        "--report", "-r",
        metavar="DOMAIN",
        help="Generate HTML report for a domain",
    )

    args = parser.parse_args()

    if args.list_targets:
        utils.print_banner()
        list_inscope_targets()
        return

    if args.report:
        utils.print_banner()
        report_generator.generate_html_report(args.report)
        return

    if args.target:
        utils.print_banner()
        module = args.module or 11
        run_module(module, args.target)
    else:
        # Interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()
