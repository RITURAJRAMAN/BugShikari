"""
# BugShikari - Module 9: Port Scanner
Scans target for open ports to identify running services.
"""

import concurrent.futures
import socket

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

import config
import utils


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Check if a port is open on the target host.

    Returns:
        Dict with port info if open, None otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                # Try to grab banner
                banner = None
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                except:
                    pass

                return {
                    "port": port,
                    "state": "open",
                    "banner": banner[:50] if banner else None
                }
    except (socket.timeout, socket.error):
        pass

    return None


def run(target: str) -> list[dict]:
    """
    Run port scan on target.

    Args:
        target: Target domain or IP

    Returns:
        List of open ports
    """
    utils.print_section_header(
        "🔌 Module 10: Port Scanner",
        f"Scanning top {len(config.COMMON_PORTS)} ports on {target}"
    )

    open_ports = []

    # Resolve domain to IP
    try:
        target_ip = socket.gethostbyname(target)
        utils.print_status(f"Resolved {target} to {target_ip}")
    except socket.gaierror:
        utils.print_error(f"Could not resolve domain {target}")
        return []

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=utils.console,
    ) as progress:
        task = progress.add_task("  Scanning ports...", total=len(config.COMMON_PORTS))

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(scan_port, target_ip, port): port
                for port in config.COMMON_PORTS
            }

            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    open_ports.append(result)
                    desc = f" ({result['banner']})" if result['banner'] else ""
                    progress.console.print(
                        f"  [green]✓ Open Port:[/green] [bold]{result['port']}[/bold]{desc}"
                    )

    if not open_ports:
        utils.print_status("No open ports found (from common list).")

    # Save results
    utils.save_results("port_scan", open_ports, target)

    return open_ports
