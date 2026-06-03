from scapy.all import sniff, DNS, DNSQR, IP, UDP

# BPF filter: restrict capture to outbound UDP packets destined for port 53.
# This is evaluated in-kernel before Scapy ever receives the frame, keeping
# overhead minimal.
BPF_FILTER = "udp and dst port 53"


def process_packet(packet: object) -> None:
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

    print(f"[DNS Query]  {src_ip}  →  {domain}")


def main() -> None:
    print("[*] Telemetry Sieve — DNS capture starting (Ctrl+C to stop) …")
    print(f"[*] Active BPF filter: '{BPF_FILTER}'\n")

    try:
        # store=False discards each packet from memory after the callback
        # returns, preventing unbounded RAM growth during long capture sessions.
        sniff(
            filter=BPF_FILTER,
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        # Scapy closes its raw socket internally when sniff() unwinds;
        # this block ensures we exit cleanly without a traceback.
        print("\n[*] Capture interrupted — sockets closed. Goodbye.")


if __name__ == "__main__":
    main()
