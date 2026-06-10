import os
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from scapy.all import DNS, DNSQR, IP, sniff

# BPF filter: restrict capture to outbound UDP packets destined for port 53.
# This is evaluated in-kernel before Scapy ever receives the frame, keeping
# overhead minimal.
BPF_FILTER = "udp and dst port 53"

BLACKLIST_PATH = os.path.join("data", "blacklist.txt")

console = Console()


def build_table() -> Table:
    """
    Construct and return a fresh Rich Table with all column definitions.
    Called once at startup; rows are appended to this instance at runtime.
    """
    table = Table(
        title="[bold white]Telemetry Sieve — Live DNS Monitor[/bold white]",
        show_header=True,
        header_style="bold white",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("Time",          style="cyan",    no_wrap=True, width=12)
    table.add_column("Source IP",     style="magenta", no_wrap=True, width=18)
    table.add_column("Target Domain", style="yellow",  no_wrap=False)
    table.add_column("Status",        no_wrap=True,    width=16)
    return table


def load_blacklist(path: str) -> set[str]:
    """
    Read the threat-intel domain blocklist from disk into a set for O(1) lookups.

    Each non-empty, non-comment line is treated as one domain entry.
    A missing or empty file is non-fatal: a warning is printed and an empty
    set is returned so the capture loop can still run unimpeded.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            domains = {
                line.strip().lower()
                for line in fh
                # Skip blank lines and comment lines beginning with '#'.
                if line.strip() and not line.strip().startswith("#")
            }
        if not domains:
            console.print(f"[yellow][!] Warning: blacklist file '{path}' exists but contains no entries.[/yellow]")
            return set()

        console.print(f"[green][*] Blacklist loaded — {len(domains)} domain(s) from '{path}'[/green]")
        return domains

    except FileNotFoundError:
        console.print(f"[yellow][!] Warning: blacklist file not found at '{path}'. Running with empty blocklist.[/yellow]")
        return set()


def process_packet(packet: object, table: Table, blacklist: set[str]) -> None:
    """
    Callback invoked by sniff() for every packet that passes the BPF filter.

    Packet anatomy expected here:
      [ Ethernet / IP / UDP / DNS / DNSQR ]
        - IP   : network layer — confirms we have a routable src/dst
        - UDP  : transport layer — DNS uses UDP on port 53 by default
        - DNS  : application layer — the DNS message envelope (qr, opcode, …)
        - DNSQR: the first Question Record inside the DNS envelope,
                 carrying the queried name (qname) and type (A, AAAA, MX, …)
    """
    # Guard: only process packets that carry a DNS message.
    # The BPF filter already narrows to UDP/53, but a DNS layer check prevents
    # misparsing any non-DNS traffic that may share port 53.
    if not packet.haslayer(DNS):
        return

    dns_layer = packet[DNS]

    # qr == 0 means this is a query (not a response).
    # Responses share the same port so we explicitly skip them here.
    if dns_layer.qr != 0:
        return

    # DNSQR holds the question records; qdcount tells us how many.
    # In practice almost all queries carry exactly one question.
    if not packet.haslayer(DNSQR):
        return

    question = packet[DNSQR]

    # qname is returned as bytes (e.g. b'example.com.').
    # Decode to a plain string and strip the mandatory trailing root-label dot
    # that the DNS wire format appends.
    raw_qname: bytes = question.qname
    domain = raw_qname.decode("utf-8", errors="replace").rstrip(".")

    src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Set membership test is O(1) — no performance penalty even on large blocklists.
    if domain.lower() in blacklist:
        status = Text("⬤ BLOCKED", style="bold red")
    else:
        status = Text("⬤ ALLOWED", style="bold green")

    table.add_row(timestamp, src_ip, domain, status)


def main() -> None:
    blacklist = load_blacklist(BLACKLIST_PATH)
    table = build_table()

    console.print("[bold cyan][*] Telemetry Sieve — DNS capture starting (Ctrl+C to stop) …[/bold cyan]")
    console.print(f"[dim][*] Active BPF filter: '{BPF_FILTER}'[/dim]\n")

    # Bind the table and blacklist into the callback via a closure so sniff()
    # can call process_packet(packet) with the standard single-argument
    # signature it expects, while both shared objects remain accessible.
    def packet_handler(packet: object) -> None:
        process_packet(packet, table, blacklist)

    try:
        # Live redraws the table in-place at up to 4 fps; no line-spam.
        # The table reference is shared with packet_handler, so every
        # table.add_row() call is reflected on the next refresh cycle.
        with Live(table, console=console, refresh_per_second=4):
            # store=False discards each packet from memory after the callback
            # returns, preventing unbounded RAM growth during long capture sessions.
            sniff(
                filter=BPF_FILTER,
                prn=packet_handler,
                store=False,
            )
    except KeyboardInterrupt:
        # Scapy closes its raw socket internally when sniff() unwinds;
        # this block ensures we exit cleanly without a traceback.
        console.print("\n[bold cyan][*] Capture interrupted — sockets closed. Goodbye.[/bold cyan]")


if __name__ == "__main__":
    main()
