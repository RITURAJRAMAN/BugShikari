"""
BugShikari - Advanced Bug Hunting Toolkit
Shared utilities for HTTP, output formatting, and file I/O
"""

import json
import os
import random
import time
from datetime import datetime
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import config

console = Console()

# Global cache for cookies
_cached_cookies_loaded = False
_cached_cookies_session = None


def load_cookies(session, target_url):
    """
    Load cookies from file into session if matching target domain.
    Includes simple caching to avoid re-reading file on every request.
    """
    global _cached_cookies_loaded, _cached_cookies_session

    # If we already loaded cookies into a session for this process, re-use logic could be complex
    # if targets change. For now, we will just optimize file reading.
    # But since session is created fresh in make_request each time (stateless mostly),
    # we should probably load the cookie dict once and re-apply it.

    if not os.path.exists(config.COOKIE_FILE_PATH):
        return

    try:
        target_domain = urlparse(target_url).netloc
        # Simple optimization: Reading file is expensive.
        # We can read it once into memory.

        if not hasattr(load_cookies, "cookie_data"):
            with open(config.COOKIE_FILE_PATH, 'r') as f:
                load_cookies.cookie_data = json.load(f)

        matched_cookies = False
        for cookie in load_cookies.cookie_data:
            # Check if the cookie domain is a superdomain of the target domain
            if 'domain' in cookie and target_domain.endswith(cookie['domain']):
                session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])
                matched_cookies = True

        if matched_cookies and not getattr(load_cookies, "notified", False):
            console.print(
                f"  [bold yellow]🍪 Loaded cookies for [cyan]{target_domain}[/cyan]. Authenticated scanning enabled.[/bold yellow]")
            load_cookies.notified = True

    except (json.JSONDecodeError, IOError) as e:
        if not getattr(load_cookies, "error_shown", False):
            console.print(f"  [red]✗ Failed to load or parse cookie file: {e}[/red]")
            load_cookies.error_shown = True


# ─── Banner ───────────────────────────────────────────────────────────
BANNER = r"""
██████╗ ██╗   ██╗ ██████╗ ███████╗██╗  ██╗██╗██╗  ██╗ █████╗ ██████╗ ██╗
██╔══██╗██║   ██║██╔════╝ ██╔════╝██║  ██║██║██║ ██╔╝██╔══██╗██╔══██╗██║
██████╔╝██║   ██║██║  ███╗███████╗███████║██║█████╔╝ ███████║██████╔╝██║
██╔══██╗██║   ██║██║   ██║╚════██║██╔══██╗██║██╔═██╗ ██╔══██║██╔══██╗██║
██████╔╝╚██████╔╝╚██████╔╝███████║██║  ██║██║██║  ██╗██║  ██║██║  ██║██║
╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
"""


def print_banner():
    """Display the BugShikari toolkit banner."""
    console.print(
        Panel(
            Text(BANNER, style="bold red", justify="center"),
            title="[bold white]BugShikari - The Ultimate Bug Hunting Toolkit[/bold white]",
            subtitle="[dim]Advanced Reconnaissance & Vulnerability Analysis[/dim]",
            border_style="bright_yellow",
            padding=(0, 2),
        )
    )


# ─── HTTP Utilities ───────────────────────────────────────────────────
def get_random_user_agent() -> str:
    """Return a random User-Agent string."""
    return random.choice(config.USER_AGENTS)


def make_request(
        url: str,
        method: str = "GET",
        timeout: int = None,
        allow_redirects: bool = True,
        verify_ssl: bool = True,
        headers: dict = None,
) -> requests.Response | None:
    """
    Make an HTTP request with retries, timeout, and User-Agent rotation.
    Loads cookies from the file specified in config for authenticated scanning.
    Only sends cookies that match the target domain.

    Returns the Response object on success, or None on failure.
    """
    if timeout is None:
        timeout = config.REQUEST_TIMEOUT

    # Prepare session object
    session = requests.Session()
    session.headers.update({
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    if headers:
        session.headers.update(headers)

    # Load cookies optimized
    load_cookies(session, url)

    for attempt in range(1, config.MAX_RETRIES + 1):
        try:
            response = session.request(
                method=method,
                url=url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
            )
            return response

        except requests.exceptions.Timeout:
            if attempt < config.MAX_RETRIES:
                console.print(
                    f"  [yellow]⏳ Timeout on attempt {attempt}/{config.MAX_RETRIES}. Retrying...[/yellow]"
                )
                time.sleep(config.RETRY_DELAY)
            else:
                console.print(f"  [red]✗ Request timed out after {config.MAX_RETRIES} attempts: {url}[/red]")

        except requests.exceptions.SSLError:
            console.print(f"  [red]✗ SSL Error for {url}[/red]")
            return None

        except requests.exceptions.ConnectionError:
            if attempt < config.MAX_RETRIES:
                console.print(
                    f"  [yellow]⚡ Connection error on attempt {attempt}/{config.MAX_RETRIES}. Retrying...[/yellow]"
                )
                time.sleep(config.RETRY_DELAY)
            else:
                console.print(f"  [red]✗ Connection failed after {config.MAX_RETRIES} attempts: {url}[/red]")

        except requests.exceptions.RequestException as e:
            console.print(f"  [red]✗ Request error: {e}[/red]")
            return None

    return None


# ─── Output Utilities ─────────────────────────────────────────────────
def print_section_header(title: str, subtitle: str = ""):
    """Print a styled section header."""
    console.print()
    content = f"[bold white]{title}[/bold white]"
    if subtitle:
        content += f"\n[dim]{subtitle}[/dim]"
    console.print(
        Panel(
            content,
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_finding(severity: str, title: str, detail: str = ""):
    """Print a finding with severity indicator."""
    severity_styles = {
        "critical": ("🔴", "bold red"),
        "high": ("🟠", "bold bright_red"),
        "medium": ("🟡", "bold yellow"),
        "low": ("🔵", "bold blue"),
        "info": ("⚪", "bold white"),
        "ok": ("🟢", "bold green"),
    }
    icon, style = severity_styles.get(severity.lower(), ("⚪", "bold white"))
    console.print(f"  {icon} [{style}]{title}[/{style}]")
    if detail:
        console.print(f"     [dim]{detail}[/dim]")


def create_table(title: str, columns: list[tuple[str, str]]) -> Table:
    """
    Create a Rich table with given title and columns.

    Args:
        title: Table title
        columns: List of (column_name, style) tuples
    """
    table = Table(
        title=f"[bold]{title}[/bold]",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        padding=(0, 1),
    )
    for col_name, style in columns:
        table.add_column(col_name, style=style)
    return table


def save_results(module_name: str, data: dict | list, target: str = ""):
    """
    Save scan results to a JSON file in the results directory.

    Args:
        module_name: Name of the module that produced the results
        target: Target domain that was scanned
        data: Results data to save
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_").replace(":", "") if target else "unknown"
    filename = f"{module_name}_{safe_target}_{timestamp}.json"
    filepath = os.path.join(config.RESULTS_DIR, filename)

    output = {
        "module": module_name,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "results": data,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    console.print(f"\n  [green]💾 Results saved to:[/green] [bold]{filepath}[/bold]")
    return filepath


def print_status(message: str, style: str = "cyan"):
    """Print a status message."""
    console.print(f"  [{style}]► {message}[/{style}]")


def print_error(message: str):
    """Print an error message."""
    console.print(f"  [red]✗ {message}[/red]")


def print_success(message: str):
    """Print a success message."""
    console.print(f"  [green]✓ {message}[/green]")
