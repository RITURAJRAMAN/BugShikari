"""
# BugShikari - Module 1: Subdomain Enumerator
Discovers subdomains using DNS brute-force and Certificate Transparency logs.
"""

import concurrent.futures
import json

import dns.resolver
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

import config
import utils


def resolve_subdomain(subdomain: str) -> dict | None:
    """
    Try to resolve a subdomain via DNS.

    Returns a dict with subdomain info if it resolves, else None.
    """
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        ips = [str(rdata) for rdata in answers]
        return {
            "subdomain": subdomain,
            "ips": ips,
            "method": "dns_bruteforce",
        }
    except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.name.EmptyLabel,
            dns.resolver.LifetimeTimeout,
            Exception,
    ):
        return None


def check_http_status(subdomain: str) -> dict:
    """Check the HTTP status code for a subdomain."""
    result: dict[str, int | str | None] = {"http_status": None, "https_status": None, "title": None}

    # Try HTTPS first
    response = utils.make_request(f"https://{subdomain}", timeout=5)
    if response is not None:
        result["https_status"] = response.status_code
        # Try to extract page title
        try:
            if "<title>" in response.text.lower():
                start = response.text.lower().index("<title>") + 7
                end = response.text.lower().index("</title>", start)
                result["title"] = response.text[start:end].strip()[:80]
        except (ValueError, IndexError):
            pass
    else:
        # Fallback to HTTP
        response = utils.make_request(f"http://{subdomain}", timeout=5)
        if response is not None:
            result["http_status"] = response.status_code

    return result


def enumerate_dns(domain: str) -> list[dict]:
    """
    Brute-force subdomain discovery using the wordlist from config.

    Args:
        domain: The target domain (e.g., 'google.com')

    Returns:
        List of discovered subdomain dicts
    """
    utils.print_status(f"DNS brute-force for *.{domain} ({len(config.SUBDOMAIN_WORDLIST)} prefixes)")
    discovered = []

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=utils.console,
    ) as progress:
        task = progress.add_task("  Resolving subdomains...", total=len(config.SUBDOMAIN_WORDLIST))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for prefix in config.SUBDOMAIN_WORDLIST:
                subdomain = f"{prefix}.{domain}"
                future = executor.submit(resolve_subdomain, subdomain)
                futures[future] = subdomain

            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    discovered.append(result)
                    progress.console.print(
                        f"  [green]✓ Found:[/green] [bold]{result['subdomain']}[/bold] → {', '.join(result['ips'])}"
                    )

    return discovered


def enumerate_crtsh(domain: str) -> list[dict]:
    """
    Discover subdomains via Certificate Transparency logs (crt.sh).

    Args:
        domain: The target domain (e.g., 'google.com')

    Returns:
        List of discovered subdomain dicts
    """
    utils.print_status(f"Querying Certificate Transparency logs for *.{domain}")
    discovered = []
    seen = set()

    url = config.CRT_SH_URL.format(domain=domain)
    response = utils.make_request(url, timeout=30)

    if response is None:
        utils.print_error("Failed to query crt.sh. The service may be unavailable.")
        return discovered

    try:
        entries = response.json()
    except (json.JSONDecodeError, ValueError):
        utils.print_error("Invalid response from crt.sh")
        return discovered

    for entry in entries:
        name_value = entry.get("name_value", "")
        # crt.sh can return multiple names separated by newlines
        for name in name_value.split("\n"):
            name = name.strip().lower()
            # Skip wildcards and duplicates
            if name.startswith("*."):
                name = name[2:]
            if name in seen or not name.endswith(f".{domain}"):
                continue
            seen.add(name)
            discovered.append({
                "subdomain": name,
                "ips": [],
                "method": "certificate_transparency",
                "issuer": entry.get("issuer_name", "Unknown"),
            })

    utils.print_success(f"Found {len(discovered)} unique subdomains from CT logs")

    # Resolve a sample of discovered subdomains
    if discovered:
        sample_size = min(50, len(discovered))
        utils.print_status(f"Resolving top {sample_size} subdomains from CT logs...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            sample = discovered[:sample_size]
            futures = {
                executor.submit(resolve_subdomain, d["subdomain"]): i
                for i, d in enumerate(sample)
            }
            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                result = future.result()
                if result:
                    sample[idx]["ips"] = result["ips"]

    return discovered


def enumerate_alienvault(domain: str) -> list[dict]:
    """
    Discover subdomains via AlienVault OTX.
    """
    utils.print_status(f"Querying AlienVault OTX for *.{domain}")
    discovered = []

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    response = utils.make_request(url, timeout=30)

    if not response:
        return discovered

    try:
        data = response.json()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname.endswith(f".{domain}") and hostname != domain:
                discovered.append({
                    "subdomain": hostname,
                    "ips": [entry.get("address")] if entry.get("record_type") == "A" else [],
                    "method": "alienvault",
                })
    except Exception:
        pass

    return discovered


def enumerate_hackertarget(domain: str) -> list[dict]:
    """
    Discover subdomains via HackerTarget.
    """
    utils.print_status(f"Querying HackerTarget for *.{domain}")
    discovered = []

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    response = utils.make_request(url, timeout=30)

    if not response:
        return discovered

    for line in response.text.splitlines():
        parts = line.split(",")
        if len(parts) >= 2:
            hostname = parts[0]
            if hostname.endswith(f".{domain}"):
                discovered.append({
                    "subdomain": hostname,
                    "ips": [parts[1]],
                    "method": "hackertarget",
                })

    return discovered


def enumerate_wayback(domain: str) -> list[dict]:
    """
    Discover subdomains via Wayback Machine.
    """
    utils.print_status(f"Querying Wayback Machine for *.{domain}")
    discovered = []
    seen = set()

    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    response = utils.make_request(url, timeout=60)

    if not response:
        return discovered

    try:
        data = response.json()
        if not data:
            return discovered

        # Skip header row
        for row in data[1:]:
            original_url = row[0]
            try:
                # Extract hostname
                hostname = original_url.split("/")[2]
                # Remove port if present
                if ":" in hostname:
                    hostname = hostname.split(":")[0]

                if hostname.endswith(f".{domain}") and hostname not in seen:
                    seen.add(hostname)
                    discovered.append({
                        "subdomain": hostname,
                        "ips": [],
                        "method": "wayback_machine",
                    })
            except IndexError:
                continue
    except Exception:
        pass

    return discovered


def run(domain: str) -> list[dict]:
    """
    Run full subdomain enumeration.

    Args:
        domain: Target domain (e.g., 'google.com')

    Returns:
        Combined list of all discovered subdomains
    """
    utils.print_section_header(
        "🔍 Module 1: Subdomain Enumerator",
        f"Target: *.{domain}"
    )

    all_subdomains = {}

    # Method 1: DNS brute-force
    dns_results = enumerate_dns(domain)
    for result in dns_results:
        all_subdomains[result["subdomain"]] = result

    # Method 2: Certificate Transparency
    ct_results = enumerate_crtsh(domain)
    for result in ct_results:
        if result["subdomain"] not in all_subdomains:
            all_subdomains[result["subdomain"]] = result
        elif not all_subdomains[result["subdomain"]].get("issuer"):
            all_subdomains[result["subdomain"]]["issuer"] = result.get("issuer")

    # Method 3: AlienVault OTX
    av_results = enumerate_alienvault(domain)
    for result in av_results:
        if result["subdomain"] not in all_subdomains:
            all_subdomains[result["subdomain"]] = result

    # Method 4: HackerTarget
    ht_results = enumerate_hackertarget(domain)
    for result in ht_results:
        if result["subdomain"] not in all_subdomains:
            all_subdomains[result["subdomain"]] = result

    # Method 5: Wayback Machine
    wb_results = enumerate_wayback(domain)
    for result in wb_results:
        if result["subdomain"] not in all_subdomains:
            all_subdomains[result["subdomain"]] = result

    results = list(all_subdomains.values())

    # Print summary table
    utils.console.print()
    table = utils.create_table(
        f"Discovered Subdomains ({len(results)} total)",
        [
            ("Subdomain", "bold white"),
            ("IPs", "cyan"),
            ("Method", "yellow"),
        ],
    )
    for r in sorted(results, key=lambda x: x["subdomain"])[:100]:
        table.add_row(
            r["subdomain"],
            ", ".join(r["ips"]) if r["ips"] else "[dim]unresolved[/dim]",
            r["method"],
        )
    if len(results) > 100:
        table.add_row("[dim]...[/dim]", f"[dim]+{len(results) - 100} more[/dim]", "")

    utils.console.print(table)

    # Check HTTP status for resolved subdomains
    resolved = [r for r in results if r["ips"]]
    if resolved:
        utils.print_status(f"Checking HTTP status for {len(resolved)} resolved subdomains...")
        sample = resolved[:30]  # Limit to avoid excessive requests

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_http_status, r["subdomain"]): r
                for r in sample
            }
            for future in concurrent.futures.as_completed(futures):
                r = futures[future]
                status = future.result()
                r.update(status)

        # Print HTTP results
        http_table = utils.create_table(
            "HTTP Status Check",
            [
                ("Subdomain", "bold white"),
                ("HTTPS", "green"),
                ("HTTP", "yellow"),
                ("Title", "dim"),
            ],
        )
        for r in sorted(sample, key=lambda x: x["subdomain"]):
            http_table.add_row(
                r["subdomain"],
                str(r.get("https_status", "-")),
                str(r.get("http_status", "-")),
                r.get("title", "-") or "-",
            )
        utils.console.print(http_table)

    # Save results
    utils.save_results("subdomain_enum", results, domain)

    return results
