"""
# BugShikari - Module 10: Content Discovery
Fuzzes directories and files to find hidden content.
"""

import concurrent.futures

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

import config
import utils


def check_path(url: str, path: str) -> dict | None:
    """
    Check if a path exists on the target.

    Returns:
        Dict with result if found, None otherwise.
    """
    full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
    try:
        response = utils.make_request(full_url, allow_redirects=False, timeout=5)
        if response:
            if response.status_code in (200, 301, 302, 403, 500):
                return {
                    "path": path,
                    "url": full_url,
                    "status_code": response.status_code,
                    "length": len(response.content),
                    "redirect": response.headers.get("Location")
                }
    except Exception:
        pass

    return None


def run(target: str) -> list[dict]:
    """
    Run content discovery on target.

    Args:
        target: Target domain (e.g., 'google.com')

    Returns:
        List of discovered content
    """
    utils.print_section_header(
        "📂 Module 11: Content Discovery",
        f"Fuzzing directories on {target}"
    )

    discovered = []
    base_url = f"https://{target}"

    # Check if target is reachable first
    if not utils.make_request(base_url, timeout=5):
        utils.print_error(f"Target {base_url} is not reachable via HTTPS. Trying HTTP...")
        base_url = f"http://{target}"
        if not utils.make_request(base_url, timeout=5):
            utils.print_error(f"Target {base_url} is unreachable. Skipping.")
            return []

    wordlist = config.CONTENT_DISCOVERY_WORDLIST

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=utils.console,
    ) as progress:
        task = progress.add_task("  Fuzzing paths...", total=len(wordlist))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(check_path, base_url, path): path
                for path in wordlist
            }

            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    discovered.append(result)
                    code_style = "green" if result['status_code'] == 200 else "yellow" if result['status_code'] in (301,
                                                                                                                    302) else "red"
                    progress.console.print(
                        f"  [{code_style}]{result['status_code']}[/{code_style}] "
                        f"[bold]{result['path']}[/bold] (len: {result['length']})"
                        f"{' → ' + result['redirect'] if result.get('redirect') else ''}"
                    )

    if not discovered:
        utils.print_status("No interesting content found.")

    # Save results
    utils.save_results("content_discovery", discovered, target)

    return discovered
