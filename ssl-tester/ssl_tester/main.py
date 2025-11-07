# ssl_tester/main.py
import argparse
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box
import pyfiglet

from .scanner import scan_ssl
from .reporter import print_report, save_json

console = Console()

def print_banner():
    """Show fancy banner at start"""
    banner = pyfiglet.figlet_format("SSL - TESTER", font="slant")
    console.print(f"[cyan]{banner}[/cyan]")
    console.print(
        Panel.fit(
            "[bold yellow]A lightweight SSL/TLS analyzer tool[/bold yellow]\n"
            "[green]Developed by Prashant[/green]",
            box=box.DOUBLE,
            border_style="bright_blue"
        )
    )

def run_cli():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="ssl-tester",
        description="Interactive SSL testing and certificate analysis tool"
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--port", type=int, default=443, help="Port to connect (default: 443)")
    parser.add_argument("--json", help="Save output as JSON file")
    parser.add_argument("--verbose", action="store_true", help="Show detailed information")

    args = parser.parse_args()

    # Loading animation during SSL handshake
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting to target server...", start=True)
        time.sleep(0.8)  # small delay for animation effect
        try:
            report = scan_ssl(args.target, args.port)
            progress.update(task, description="[green]Connection successful!")
            time.sleep(0.3)
        except Exception as e:
            progress.update(task, description=f"[red]Connection failed: {e}")
            time.sleep(0.5)
            return

    console.print("\n[bold cyan]🔍 Analyzing SSL configuration...[/bold cyan]")
    time.sleep(0.5)
    print_report(report, verbose=args.verbose)

    if args.json:
        save_json(report, args.json)
        console.print(f"\n💾 [green]JSON report saved to[/green] [bold]{args.json}[/bold]")

    console.print("\n[bold bright_green]✔ Scan complete![/bold bright_green]")
    console.print("[dim]Stay secure — Prashant's SSL Tester[/dim]\n")

