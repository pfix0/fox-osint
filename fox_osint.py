import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
import re
import socket
import dns.resolver

# Initialize Rich Console
console = Console()

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888
]

def print_banner():
    fox_ascii = r"""
          /\     /\
         {  `---'  }
         {  O   O  }
         ~~>  V  <~~
          \  \|/  /
           `-----'____
           /     \    \_
          {       }\  )_\_   _
          |  \_/  |/ /  \_\_/ )
           \__/  /(_/     \__/
             (__/
    """
    banner_text = "[bold orange1][blink]Fox OSINT[/blink][/bold orange1]"
    console.print(Panel.fit(
        fox_ascii + "\n" + banner_text,
        style="bold orange1",
        border_style="bright_red"
    ))

def get_dns_records(domain):
    """Retrieve DNS records for the given domain."""
    dns_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
    results = {}

    for record_type in dns_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = ["No record found"]
        except dns.resolver.NXDOMAIN:
            console.print(f"[red]Domain {domain} does not exist.[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Error fetching {record_type} records: {e}[/red]")
            results[record_type] = ["Error fetching records"]

    return results

def display_dns_records(domain, records):
    """Display DNS records using Rich tables."""
    table = Table(title=f"DNS Records for {domain}")
    table.add_column("Record Type", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    for record_type, values in records.items():
        for value in values:
            table.add_row(record_type, value)

    console.print(table)

def scan_ports(host):
    """Scan the top ports for the given host and return open ones with service names."""
    open_ports = []
    console.print(f"[cyan]Scanning ports for {host}...[/cyan]")
    for port in TOP_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                open_ports.append((port, service))
    return open_ports

def display_port_results(domain, ports):
    """Display the port scan results in a table."""
    table = Table(title=f"Open Ports for {domain}")
    table.add_column("Port", justify="right", style="magenta")
    table.add_column("Service", justify="left", style="green")

    for port, service in ports:
        table.add_row(str(port), service)

    console.print(table)

def get_subdomains(domain):
    """Retrieve subdomains using the crt.sh service."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            subdomains = set()
            data = response.json()
            for entry in data:
                subdomain = entry['name_value']
                if '\n' in subdomain:
                    subdomains.update(subdomain.split('\n'))
                else:
                    subdomains.add(subdomain)
            return list(subdomains)
    except Exception as e:
        console.print(f"[red]An error occurred while fetching subdomains: {e}[/red]")
    return []

def resolve_ip(subdomain):
    """Resolve the IP address of the given subdomain."""
    try:
        ip_address = socket.gethostbyname(subdomain)
        return ip_address
    except socket.gaierror:
        return "N/A"

def check_subdomain_status(subdomain):
    """Check the status of a subdomain using both http and https."""
    protocols = ["http", "https"]
    for protocol in protocols:
        url = f"{protocol}://{subdomain}"
        try:
            response = requests.get(url, timeout=5)
            return f"{protocol}://{subdomain}", "Working", True
        except requests.RequestException:
            continue

    return subdomain, "Not Working", False

def display_ip_addresses(ip_results):
    """Display IP addresses in a table using Rich."""
    table = Table(title="Subdomains and IP Addresses")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("IP Address", justify="left", style="magenta")

    for subdomain, ip_address in ip_results.items():
        table.add_row(subdomain, ip_address)

    console.print(table)

def display_results(results):
    """Display the subdomain status results in a table using Rich."""
    table = Table(title="Subdomain Status")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("URL", justify="left", style="magenta")
    table.add_column("Status", justify="center", style="bold")

    for subdomain, (url, status, _) in results.items():
        status_color = "[green]" if status == "Working" else "[red]"
        table.add_row(subdomain, url, f"{status_color}{status}[/]")

    console.print(table)

def display_port_scan_results(scan_results):
    """Display port scan results in a table using Rich."""
    table = Table(title="Open Ports and Services")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right", style="magenta")
    table.add_column("Service", justify="left", style="green")

    for subdomain, open_ports in scan_results.items():
        for port, service in open_ports:
            table.add_row(subdomain, str(port), service)

    console.print(table)

def main(domain):
    print_banner()   # Cyber fox logo at the start!
    # Step 1: Fetch DNS records
    console.print(f"[bold]Fetching DNS records for: {domain}[/bold]")
    dns_records = get_dns_records(domain)
    if dns_records:
        display_dns_records(domain, dns_records)

    # Step 2: Scan ports for the main domain
    console.print(f"[bold]Scanning ports for: {domain}[/bold]")
    main_domain_ports = scan_ports(domain)
    display_port_results(domain, main_domain_ports)

    # Step 3: Search for subdomains
    console.print(f"[bold]Searching for subdomains of: {domain}[/bold]")
    subdomains = get_subdomains(domain)

    results = {}
    ip_results = {}
    scan_results = {}

    with Progress() as progress:
        task = progress.add_task("[cyan]Resolving IP Addresses...", total=len(subdomains))

        for subdomain in subdomains:
            ip_address = resolve_ip(subdomain)
            ip_results[subdomain] = ip_address
            progress.update(task, advance=1)

        task = progress.add_task("[cyan]Checking Subdomain Status...", total=len(subdomains))
        for subdomain in subdomains:
            url, status, is_working = check_subdomain_status(subdomain)
            results[subdomain] = (url, status, is_working)
            progress.update(task, advance=1)

        task = progress.add_task("[cyan]Scanning Ports...", total=len([s for s in results if results[s][2]]))
        for subdomain in results:
            if results[subdomain][2]:
                open_ports = scan_ports(subdomain)
                scan_results[subdomain] = open_ports
                progress.update(task, advance=1)

    display_ip_addresses(ip_results)
    display_results(results)
    display_port_scan_results(scan_results)

if __name__ == "__main__":
    console.print(
        "[bold]Enter the domain name to find Data[/bold] "
        "[yellow](e.g., example.com):[/yellow] ",
        end=""
    )
    domain_to_check = input().strip()
    main(domain_to_check)
