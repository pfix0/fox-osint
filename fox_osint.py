import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
import re
import socket
import dns.resolver
import time

# Initialize Rich Console
console = Console()

# List of top ports to scan (common service ports)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888
]

# Maximum number of subdomains to process (to avoid issues with large domains)
MAX_SUBDOMAINS = 100

def print_banner():
    """
    Print a cyber fox ASCII art banner with tool name using Rich.
    """
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
    """
    Retrieve DNS records (A, AAAA, MX, NS, CNAME, TXT) for the given domain.
    """
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
    """
    Display DNS records for the domain using a Rich table.
    """
    table = Table(title=f"DNS Records for {domain}")
    table.add_column("Record Type", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    for record_type, values in records.items():
        for value in values:
            table.add_row(record_type, value)

    console.print(table)

def scan_ports(host):
    """
    Scan the most common ports on the host and return a list of open ports with service names.
    """
    open_ports = []
    console.print(f"[cyan]Scanning ports for {host}...[/cyan]")
    for port in TOP_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                result = sock.connect_ex((host, port))
            except Exception:
                continue
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                open_ports.append((port, service))
    return open_ports

def display_port_results(domain, ports):
    """
    Display the port scan results for the main domain in a Rich table.
    """
    table = Table(title=f"Open Ports for {domain}")
    table.add_column("Port", justify="right", style="magenta")
    table.add_column("Service", justify="left", style="green")

    for port, service in ports:
        table.add_row(str(port), service)

    console.print(table)

def get_subdomains(domain):
    """
    Retrieve subdomains using crt.sh public certificate transparency logs.
    Returns a list of unique subdomains (no empty values).
    """
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
            # Remove duplicates and empty entries
            subdomains = [s.strip() for s in subdomains if s.strip()]
            return subdomains
    except Exception as e:
        console.print(f"[red]An error occurred while fetching subdomains: {e}[/red]")
    return []

def resolve_ip(subdomain):
    """
    Resolve the IP address for the given subdomain.
    Returns "N/A" if resolution fails.
    """
    try:
        ip_address = socket.gethostbyname(subdomain)
        return ip_address
    except Exception:
        return "N/A"

def check_subdomain_status(subdomain):
    """
    Check if the subdomain responds to HTTP/HTTPS requests.
    Returns the working URL, status string, and a boolean.
    """
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
    """
    Display a table of subdomains and their resolved IP addresses.
    """
    table = Table(title="Subdomains and IP Addresses")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("IP Address", justify="left", style="magenta")

    for subdomain, ip_address in ip_results.items():
        table.add_row(subdomain, ip_address)

    console.print(table)

def display_results(results):
    """
    Display the status (working/not working) for each subdomain in a table.
    """
    table = Table(title="Subdomain Status")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("URL", justify="left", style="magenta")
    table.add_column("Status", justify="center", style="bold")

    for subdomain, (url, status, _) in results.items():
        status_color = "[green]" if status == "Working" else "[red]"
        table.add_row(subdomain, url, f"{status_color}{status}[/]")

    console.print(table)

def display_port_scan_results(scan_results):
    """
    Display open ports and services for each working subdomain.
    """
    table = Table(title="Open Ports and Services")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right", style="magenta")
    table.add_column("Service", justify="left", style="green")

    for subdomain, open_ports in scan_results.items():
        for port, service in open_ports:
            table.add_row(subdomain, str(port), service)

    console.print(table)

def main(domain):
    """
    Main function for the tool.
    Executes: print banner -> DNS records -> main domain ports -> subdomain logic (IP, status, ports).
    """
    print_banner()   # Show cyber fox banner at the start

    # Step 1: Fetch and display DNS records
    console.print(f"[bold]Fetching DNS records for: {domain}[/bold]")
    dns_records = get_dns_records(domain)
    if dns_records:
        display_dns_records(domain, dns_records)

    # Step 2: Scan and display open ports for the main domain
    console.print(f"[bold]Scanning ports for: {domain}[/bold]")
    main_domain_ports = scan_ports(domain)
    display_port_results(domain, main_domain_ports)

    # Step 3: Discover subdomains via crt.sh
    console.print(f"[bold]Searching for subdomains of: {domain}[/bold]")
    subdomains = get_subdomains(domain)

    # Handle domains with too many subdomains (limit results)
    if len(subdomains) > MAX_SUBDOMAINS:
        console.print(
            f"[yellow]Found {len(subdomains)} subdomains, limiting output to first {MAX_SUBDOMAINS} for performance.[/yellow]"
        )
        subdomains = subdomains[:MAX_SUBDOMAINS]

    results = {}       # Will store subdomain status info
    ip_results = {}    # Will store subdomain IPs
    scan_results = {}  # Will store open port info for each subdomain

    with Progress() as progress:
        # Step 4: Resolve IP addresses for subdomains
        task = progress.add_task("[cyan]Resolving IP Addresses...", total=len(subdomains))
        for subdomain in subdomains:
            ip_address = resolve_ip(subdomain)
            ip_results[subdomain] = ip_address
            progress.update(task, advance=1)
            time.sleep(0.05)  # Optional: slow down for big domains

        # Step 5: Check if subdomains are live (HTTP/HTTPS)
        task = progress.add_task("[cyan]Checking Subdomain Status...", total=len(subdomains))
        for subdomain in subdomains:
            url, status, is_working = check_subdomain_status(subdomain)
            results[subdomain] = (url, status, is_working)
            progress.update(task, advance=1)
            time.sleep(0.05)  # Optional: slow down for big domains

        # Step 6: For each live subdomain, scan its ports
        working_subdomains = [s for s in results if results[s][2]]
        task = progress.add_task("[cyan]Scanning Ports...", total=len(working_subdomains))
        for subdomain in working_subdomains:
            open_ports = scan_ports(subdomain)
            scan_results[subdomain] = open_ports
            progress.update(task, advance=1)
            time.sleep(0.05)  # Optional: slow down for big domains

    # Display all final results in beautiful tables
    display_ip_addresses(ip_results)
    display_results(results)
    display_port_scan_results(scan_results)

if __name__ == "__main__":
    # Prompt the user for the domain to check
    console.print(
        "[bold]Enter the domain name to find Data[/bold] "
        "[yellow](e.g., example.com):[/yellow] ",
        end=""
    )
    domain_to_check = input().strip()
    main(domain_to_check)
