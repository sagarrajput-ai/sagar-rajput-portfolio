from dotenv import load_dotenv
load_dotenv(override=True)

from flask import Flask, render_template, request, Response, redirect, url_for, jsonify
import ipaddress
import socket
import os
import re
import json
import ssl
import subprocess
import platform
import time
import urllib.parse
import urllib.request
import urllib.error
import http.client
import concurrent.futures

from port_scanner import port_scanner_bp
from tavily import TavilyClient




app = Flask(__name__)
app.register_blueprint(port_scanner_bp)
app.config["SITE_URL"] = "https://sagarrajput.com"

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)

# Limit incoming request bodies. These tools only need very small form payloads.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB

# ---------------------------------------------------------------------------
# Security / networking helpers
# ---------------------------------------------------------------------------

MAX_HOSTNAME_LENGTH = 253
MAX_SUBNETS = 1024
SOCKET_TIMEOUT = 3

# ---------------------------------------------------------------------------
# Network Diagnostic Lab limits
# ---------------------------------------------------------------------------

DIAGNOSTIC_TIMEOUT = 5
MAX_BULK_PING_TARGETS = 50
MAX_PING_PACKETS = 10
MAX_PACKET_SIZE = 1400
MAX_DIAGNOSTIC_INPUT = 4096
MAX_TRACE_HOPS = 30
MAX_DNS_NAMES = 20

DIAGNOSTIC_USER_AGENT = (
    "SagarRajput-NetworkDiagnosticLab/1.0"
)

# ---------------------------------------------------------------------------
# Enterprise Protocol & Port Quick Lookup
# ---------------------------------------------------------------------------

PROTOCOL_PORT_DATABASE = [

    # =========================
    # Routing
    # =========================

    {
        "service": "BGP",
        "port": "179",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Routing",
        "purpose": "Inter-domain routing between autonomous systems.",
        "platforms": "Cisco, Fortinet, Aruba, Juniper, Pica8",
        "notes": "BGP uses TCP for reliable session establishment."
    },

    {
        "service": "OSPF",
        "port": "—",
        "transport": "IP",
        "protocol_number": "89",
        "category": "Routing",
        "purpose": "Interior gateway routing protocol.",
        "platforms": "Cisco, Fortinet, Aruba, Juniper, Pica8",
        "notes": "OSPF does not use TCP or UDP ports."
    },

    {
        "service": "EIGRP",
        "port": "—",
        "transport": "IP",
        "protocol_number": "88",
        "category": "Routing",
        "purpose": "Cisco-originated interior gateway routing protocol.",
        "platforms": "Cisco",
        "notes": "EIGRP operates directly over IP."
    },

    {
        "service": "RIP",
        "port": "520",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Routing",
        "purpose": "Distance-vector interior routing protocol.",
        "platforms": "Cisco, Aruba, Linux",
        "notes": "RIPv2 commonly uses UDP 520."
    },

    # =========================
    # Infrastructure
    # =========================

    {
        "service": "DNS",
        "port": "53",
        "transport": "TCP / UDP",
        "protocol_number": "6 / 17",
        "category": "Infrastructure",
        "purpose": "Domain name resolution.",
        "platforms": "Windows, Linux, Cisco, Fortinet, Aruba",
        "notes": "UDP is commonly used for queries; TCP is used for larger responses and zone transfers."
    },

    {
        "service": "DHCP Server",
        "port": "67",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Infrastructure",
        "purpose": "Provides IP addressing configuration to clients.",
        "platforms": "Windows, Linux, Cisco, Fortinet",
        "notes": "Client uses UDP 68."
    },

    {
        "service": "DHCP Client",
        "port": "68",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Infrastructure",
        "purpose": "Receives DHCP configuration from a DHCP server.",
        "platforms": "Windows, Linux, Cisco, Aruba",
        "notes": "Communicates with DHCP server on UDP 67."
    },

    {
        "service": "NTP",
        "port": "123",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Infrastructure",
        "purpose": "Network time synchronization.",
        "platforms": "Windows, Linux, Cisco, Fortinet, Aruba",
        "notes": "Accurate time is important for logs, authentication and troubleshooting."
    },

    {
        "service": "TFTP",
        "port": "69",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Infrastructure",
        "purpose": "Simple file transfer commonly used for network device configuration and image operations.",
        "platforms": "Cisco, Aruba, Pica8",
        "notes": "TFTP has no built-in authentication."
    },

    # =========================
    # Monitoring
    # =========================

    {
        "service": "SNMP",
        "port": "161",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Monitoring",
        "purpose": "Network device monitoring and management queries.",
        "platforms": "Cisco, Fortinet, Aruba, Pica8, Linux",
        "notes": "SNMP traps commonly use UDP 162."
    },

    {
        "service": "SNMP Trap",
        "port": "162",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "Monitoring",
        "purpose": "Asynchronous monitoring notifications from network devices.",
        "platforms": "Cisco, Fortinet, Aruba, Pica8",
        "notes": "Trap receiver normally listens on UDP 162."
    },

    {
        "service": "Syslog",
        "port": "514",
        "transport": "UDP / TCP",
        "protocol_number": "17 / 6",
        "category": "Monitoring",
        "purpose": "Centralized event and system log collection.",
        "platforms": "Cisco, Fortinet, Aruba, Linux, Palo Alto",
        "notes": "TLS-secured syslog commonly uses TCP 6514."
    },

    {
        "service": "Syslog over TLS",
        "port": "6514",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Monitoring",
        "purpose": "Encrypted centralized syslog transport.",
        "platforms": "Cisco, Fortinet, Palo Alto, Linux",
        "notes": "Provides encrypted syslog transport."
    },

    # =========================
    # Authentication / AAA
    # =========================

    {
        "service": "RADIUS Authentication",
        "port": "1812",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "AAA",
        "purpose": "Centralized authentication and authorization.",
        "platforms": "Cisco, Fortinet, Aruba, Windows",
        "notes": "Commonly used for network access authentication."
    },

    {
        "service": "RADIUS Accounting",
        "port": "1813",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "AAA",
        "purpose": "RADIUS accounting and session tracking.",
        "platforms": "Cisco, Fortinet, Aruba",
        "notes": "Used for accounting records."
    },

    {
        "service": "TACACS+",
        "port": "49",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "AAA",
        "purpose": "Centralized device administration authentication and authorization.",
        "platforms": "Cisco, Aruba, Fortinet",
        "notes": "Frequently used for administrator access to network devices."
    },

    # =========================
    # Directory Services
    # =========================

    {
        "service": "LDAP",
        "port": "389",
        "transport": "TCP / UDP",
        "protocol_number": "6 / 17",
        "category": "Directory",
        "purpose": "Directory service access and authentication.",
        "platforms": "Microsoft, Linux, Cisco, Fortinet, Palo Alto",
        "notes": "LDAP over TLS/SSL commonly uses port 636."
    },

    {
        "service": "LDAPS",
        "port": "636",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Directory",
        "purpose": "Encrypted LDAP communication.",
        "platforms": "Microsoft, Linux, Cisco, Fortinet, Palo Alto",
        "notes": "Provides TLS/SSL-protected LDAP."
    },

    # =========================
    # Management
    # =========================

    {
        "service": "SSH",
        "port": "22",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Management",
        "purpose": "Secure remote CLI administration.",
        "platforms": "Cisco, Fortinet, Aruba, Pica8, Palo Alto, Linux",
        "notes": "Preferred over Telnet for secure administration."
    },

    {
        "service": "Telnet",
        "port": "23",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Management",
        "purpose": "Remote terminal access.",
        "platforms": "Legacy network equipment",
        "notes": "Unencrypted; SSH should normally be preferred."
    },

    {
        "service": "HTTP",
        "port": "80",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Web",
        "purpose": "Unencrypted web traffic.",
        "platforms": "Network devices, servers, applications",
        "notes": "Usually redirected or replaced by HTTPS."
    },

    {
        "service": "HTTPS",
        "port": "443",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Web",
        "purpose": "Encrypted web traffic and web-based administration.",
        "platforms": "Cisco, Fortinet, Aruba, Palo Alto, servers",
        "notes": "Common port for secure management interfaces."
    },

    # =========================
    # File / Windows
    # =========================

    {
        "service": "FTP",
        "port": "20 / 21",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "File Transfer",
        "purpose": "File transfer.",
        "platforms": "Windows, Linux, network devices",
        "notes": "TCP 21 is control; TCP 20 is traditionally associated with active-mode data."
    },

    {
        "service": "SMB",
        "port": "445",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Windows",
        "purpose": "Windows file and printer sharing.",
        "platforms": "Microsoft Windows",
        "notes": "Modern SMB commonly uses TCP 445."
    },

    {
        "service": "RDP",
        "port": "3389",
        "transport": "TCP / UDP",
        "protocol_number": "6 / 17",
        "category": "Windows",
        "purpose": "Remote Desktop access.",
        "platforms": "Microsoft Windows",
        "notes": "Used for Windows remote administration."
    },

    # =========================
    # VPN / Security
    # =========================

    {
        "service": "IKE",
        "port": "500",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "VPN",
        "purpose": "IPsec Internet Key Exchange.",
        "platforms": "Cisco, Fortinet, Palo Alto, Aruba",
        "notes": "Used for IPsec tunnel negotiation."
    },

    {
        "service": "IPsec NAT-T",
        "port": "4500",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "VPN",
        "purpose": "IPsec NAT traversal.",
        "platforms": "Cisco, Fortinet, Palo Alto, Aruba",
        "notes": "Commonly used when IPsec peers traverse NAT."
    },

    {
        "service": "L2TP",
        "port": "1701",
        "transport": "UDP",
        "protocol_number": "17",
        "category": "VPN",
        "purpose": "Layer 2 tunneling.",
        "platforms": "Cisco, Windows, Linux",
        "notes": "Often combined with IPsec for encryption."
    },

    {
        "service": "GRE",
        "port": "—",
        "transport": "IP",
        "protocol_number": "47",
        "category": "VPN / Tunneling",
        "purpose": "Generic Routing Encapsulation tunneling.",
        "platforms": "Cisco, Fortinet, Palo Alto, Linux",
        "notes": "GRE does not use TCP or UDP ports."
    },

    {
        "service": "ESP",
        "port": "—",
        "transport": "IP",
        "protocol_number": "50",
        "category": "VPN / Security",
        "purpose": "IPsec Encapsulating Security Payload.",
        "platforms": "Cisco, Fortinet, Palo Alto, Aruba",
        "notes": "ESP operates directly over IP."
    },

    # =========================
    # Fortinet
    # =========================

    {
        "service": "FortiGate HTTPS Administration",
        "port": "443",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Fortinet",
        "purpose": "Web-based FortiGate administration.",
        "platforms": "FortiGate",
        "notes": "Actual administrative port can be customized."
    },

    {
        "service": "FortiGate SSH Administration",
        "port": "22",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Fortinet",
        "purpose": "CLI administration of FortiGate.",
        "platforms": "FortiGate",
        "notes": "Actual SSH administrative port can be customized."
    },

    {
        "service": "FortiManager",
        "port": "541",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Fortinet",
        "purpose": "FortiManager management communication.",
        "platforms": "FortiManager / FortiGate",
        "notes": "Verify the exact service requirement against the Fortinet version and deployment."
    },

    # =========================
    # Palo Alto
    # =========================

    {
        "service": "Palo Alto Web Management",
        "port": "443",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Palo Alto",
        "purpose": "HTTPS-based firewall administration.",
        "platforms": "Palo Alto PAN-OS",
        "notes": "Management port configuration can vary."
    },

    # =========================
    # Zscaler
    # =========================

    {
        "service": "Zscaler HTTPS",
        "port": "443",
        "transport": "TCP",
        "protocol_number": "6",
        "category": "Zscaler",
        "purpose": "Secure web and cloud security connectivity.",
        "platforms": "Zscaler",
        "notes": "Actual Zscaler connectivity requirements depend on the deployed Zscaler product and architecture."
    },

]



def get_safe_host_addresses(host):
    """
    Resolve a hostname/IP and return only globally routable addresses.

    The port checker must never be allowed to connect to localhost, private
    networks, link-local addresses, multicast, unspecified, or other
    non-public destinations.
    """
    host = host.strip()

    if not host:
        raise ValueError("Please enter a hostname or IP address.")

    if len(host) > MAX_HOSTNAME_LENGTH:
        raise ValueError("Hostname is too long.")

    try:
        # If the input is already an IP address, validate it directly.
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ValueError(
                "For security, the port checker only allows public IP addresses."
            )
        return [(socket.AF_INET6 if address.version == 6 else socket.AF_INET,
                 address.compressed)]
    except ValueError as exc:
        # A normal hostname is not an IP address. Preserve our security
        # rejection message if the input was actually a non-public IP.
        if "port checker only allows" in str(exc):
            raise

    # Resolve both IPv4 and IPv6 records. SOCK_STREAM is used because this
    # tool checks TCP connectivity.
    try:
        infos = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError(
            "Unable to resolve the hostname. Check the hostname or IP address."
        )

    public_addresses = []
    seen = set()

    for family, _, _, _, sockaddr in infos:
        resolved_ip = sockaddr[0]

        try:
            address = ipaddress.ip_address(resolved_ip)
        except ValueError:
            continue

        # Reject non-global destinations. This blocks private, loopback,
        # link-local, multicast, unspecified and other special ranges.
        if not address.is_global:
            continue

        key = (family, address.compressed)
        if key not in seen:
            seen.add(key)
            public_addresses.append(key)

    if not public_addresses:
        raise ValueError(
            "The hostname does not resolve to a public IP address."
        )

    return public_addresses


def first_and_last_host(network):
    """
    Return the first/last usable host without materializing every host.

    This avoids memory exhaustion for large IPv4/IPv6 networks.
    """
    total = network.num_addresses

    if total == 1:
        address = str(network.network_address)
        return address, address, 1

    if network.version == 4:
        if network.prefixlen >= 31:
            # /31 has two usable point-to-point addresses.
            # /32 has one address.
            return (
                str(network.network_address),
                str(network.broadcast_address),
                total,
            )

        return (
            str(network.network_address + 1),
            str(network.broadcast_address - 1),
            total - 2,
        )

    # Python's IPv6 hosts() excludes the subnet-router anycast address
    # (the first address) for normal IPv6 networks.
    return (
        str(network.network_address + 1),
        str(network.broadcast_address),
        total - 1,
    )


def subnet_details(subnet):
    first_host, last_host, usable_hosts = first_and_last_host(subnet)

    return {
        "network": str(subnet.network_address),
        "broadcast": str(subnet.broadcast_address),
        "netmask": str(subnet.netmask),
        "prefix": subnet.prefixlen,
        "first_host": first_host,
        "last_host": last_host,
        "usable_hosts": usable_hosts,
    }


def normalize_hostname(value):
    """
    Normalize normal URL-style hostname input without accepting paths,
    credentials, ports, or arbitrary URL content.
    """
    hostname = value.strip()

    if not hostname:
        raise ValueError("Please enter a hostname.")

    if len(hostname) > MAX_HOSTNAME_LENGTH:
        raise ValueError("Hostname is too long.")

    # Permit a user to paste a simple http(s) URL, as the original tool did.
    if hostname.lower().startswith(("http://", "https://")):
        hostname = hostname.split("://", 1)[1]

    # DNS lookup is intentionally limited to a hostname, not a URL/path.
    if "/" in hostname or "@" in hostname:
        raise ValueError(
            "Enter a hostname such as example.com, not a full URL or path."
        )

    # Remove a trailing DNS root dot.
    hostname = hostname.rstrip(".")

    if not hostname:
        raise ValueError("Please enter a valid hostname.")

    return hostname


# ---------------------------------------------------------------------------
# Network Diagnostic Lab helpers
# ---------------------------------------------------------------------------

def validate_diagnostic_target(value):
    """
    Validate an IP address or hostname.

    Public deployment defaults to globally routable destinations only.
    Set ALLOW_PRIVATE_DIAGNOSTICS=true locally if private/lab addressing
    is intentionally required.
    """
    value = value.strip()

    if not value:
        raise ValueError("Please enter an IP address or hostname.")

    if len(value) > MAX_HOSTNAME_LENGTH:
        raise ValueError("Target is too long.")

    try:
        address = ipaddress.ip_address(value)

        if address.is_unspecified or address.is_multicast:
            raise ValueError("Unspecified or multicast addresses are not allowed.")

        if address.is_private and os.environ.get(
            "ALLOW_PRIVATE_DIAGNOSTICS", ""
        ).lower() != "true":
            raise ValueError(
                "Private IP diagnostics are disabled on the public service."
            )

        return str(address)

    except ValueError as exc:
        if str(exc).endswith("not allowed.") or str(exc).startswith(
            "Private IP diagnostics"
        ):
            raise

    hostname = normalize_hostname(value)

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Unable to resolve the target.")

    public = []

    for info in addresses:
        resolved = info[4][0]

        try:
            address = ipaddress.ip_address(resolved)
        except ValueError:
            continue

        if address.is_unspecified or address.is_multicast:
            continue

        if address.is_global:
            public.append(str(address))
        elif (
            address.is_private
            and os.environ.get(
                "ALLOW_PRIVATE_DIAGNOSTICS", ""
            ).lower() == "true"
        ):
            public.append(str(address))

    if not public:
        raise ValueError(
            "Target does not resolve to an allowed IP address."
        )

    return hostname


def run_command(command, timeout):
    """
    Execute only internally constructed diagnostic commands.
    User input must never be inserted as a shell command string.
    """
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )

        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout[-12000:],
            "stderr": completed.stderr[-6000:],
        }

    except subprocess.TimeoutExpired:
        raise TimeoutError("Diagnostic command timed out.")


def normalize_mac(value):
    mac = re.sub(r"[^0-9A-Fa-f]", "", value.strip())

    if len(mac) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", mac):
        raise ValueError(
            "Invalid MAC address. Example: 00:11:22:33:44:55"
        )

    return ":".join(
        mac[index:index + 2]
        for index in range(0, 12, 2)
    ).upper()


def fetch_json(url, timeout=DIAGNOSTIC_TIMEOUT):
    request_obj = urllib.request.Request(
        url,
        headers={
            "User-Agent": DIAGNOSTIC_USER_AGENT,
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(
        request_obj,
        timeout=timeout
    ) as response:

        data = response.read(1024 * 1024)

        if len(data) > 1024 * 1024:
            raise ValueError("Remote response is too large.")

        return json.loads(data.decode("utf-8"))


def resolve_reverse_dns(ip):
    address = ipaddress.ip_address(ip)

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(
            str(address)
        )

        return {
            "ip": str(address),
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses,
        }

    except socket.herror:
        return {
            "ip": str(address),
            "hostname": None,
            "aliases": [],
            "addresses": [],
        }


def get_ip_information(ip):
    address = ipaddress.ip_address(ip)

    result = {
        "ip": str(address),
        "version": f"IPv{address.version}",
        "compressed": address.compressed,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_reserved": address.is_reserved,
        "is_loopback": address.is_loopback,
        "is_multicast": address.is_multicast,
    }

    try:
        rdns = socket.gethostbyaddr(str(address))
        result["reverse_dns"] = rdns[0]
    except socket.herror:
        result["reverse_dns"] = None

    return result


def ping_single_target(target, count=4, timeout=2, packet_size=32):
    start = time.perf_counter()

    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping",
            "-n",
            str(count),
            "-w",
            str(int(timeout * 1000)),
            "-l",
            str(packet_size),
            target,
        ]
    else:
        command = [
            "ping",
            "-c",
            str(count),
            "-W",
            str(timeout),
            "-s",
            str(packet_size),
            target,
        ]

    result = run_command(
        command,
        timeout=(count * timeout) + 3
    )

    elapsed = round(
        (time.perf_counter() - start) * 1000,
        2
    )

    output = result["stdout"] + result["stderr"]

    return {
        "target": target,
        "success": result["returncode"] == 0,
        "elapsed_ms": elapsed,
        "output": output,
    }


@app.route("/index.html")
def redirect_index_html():
    return redirect(url_for("home"), code=301)

@app.route(
    "/api/diagnostic/ping",
    methods=["POST"]
)
def diagnostic_ping():

    data = request.get_json(silent=True) or {}

    targets_raw = data.get("targets", "")
    count = data.get("count", 4)
    timeout = data.get("timeout", 2)
    packet_size = data.get("packet_size", 32)

    try:
        if not isinstance(targets_raw, str):
            raise ValueError("Invalid target list.")

        if len(targets_raw) > MAX_DIAGNOSTIC_INPUT:
            raise ValueError("Ping input is too large.")

        targets = [
            line.strip()
            for line in targets_raw.splitlines()
            if line.strip()
        ]

        # Remove duplicates while preserving order.
        targets = list(dict.fromkeys(targets))

        if not targets:
            raise ValueError("Enter at least one target.")

        if len(targets) > MAX_BULK_PING_TARGETS:
            raise ValueError(
                f"Maximum {MAX_BULK_PING_TARGETS} targets are allowed."
            )

        count = int(count)
        timeout = float(timeout)
        packet_size = int(packet_size)

        if not 1 <= count <= MAX_PING_PACKETS:
            raise ValueError(
                f"Packet count must be between 1 and {MAX_PING_PACKETS}."
            )

        if not 0.5 <= timeout <= 5:
            raise ValueError(
                "Timeout must be between 0.5 and 5 seconds."
            )

        if not 8 <= packet_size <= MAX_PACKET_SIZE:
            raise ValueError(
                f"Packet size must be between 8 and {MAX_PACKET_SIZE} bytes."
            )

        validated = []

        for target in targets:
            validated.append(
                validate_diagnostic_target(target)
            )

        results = []

        # Controlled concurrency rather than spawning unlimited processes.
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(10, len(validated))
        ) as executor:

            futures = [
                executor.submit(
                    ping_single_target,
                    target,
                    count,
                    timeout,
                    packet_size
                )
                for target in validated
            ]

            for future in futures:
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({
                        "target": "unknown",
                        "success": False,
                        "error": str(exc),
                    })

        reachable = sum(
            1 for item in results
            if item.get("success")
        )

        return jsonify({
            "success": True,
            "total": len(results),
            "reachable": reachable,
            "unreachable": len(results) - reachable,
            "results": results,
        })

    except (ValueError, TypeError) as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400


def generate_acl_config(
    vendor,
    rules,
):
    """
    Generate vendor-specific ACL / firewall configuration
    from multiple logical rules.

    Each rule supports:
        - multiple sources
        - multiple destinations
        - multiple ports
        - port ranges
        - TCP / UDP / ICMP / IP
        - permit / deny
    """

    if not rules:
        raise ValueError("At least one rule is required.")

    generated_rules = []

    for rule in rules:

        action = rule.get("action", "permit").strip().lower()
        protocol = rule.get("protocol", "ip").strip().lower()

        sources = rule.get("sources", [])
        destinations = rule.get("destinations", [])
        ports = rule.get("ports", [])

        description = rule.get(
            "description",
            "Generated network access rule"
        ).strip()

        if action not in {"permit", "deny"}:
            raise ValueError("Invalid action.")

        if protocol not in {"ip", "tcp", "udp", "icmp"}:
            raise ValueError("Unsupported protocol.")

        if not sources:
            sources = ["any"]

        if not destinations:
            destinations = ["any"]

        if protocol not in {"tcp", "udp"}:
            ports = ["any"]

        elif not ports:
            ports = ["any"]

        for source in sources:
            for destination in destinations:
                for port in ports:

                    generated_rules.append({
                        "action": action,
                        "protocol": protocol,
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "description": description,
                    })

    # =========================================================
    # Cisco IOS / IOS-XE
    # =========================================================

    if vendor == "cisco_ios":

        def cidr_to_wildcard(value):

            if value.lower() == "any":
                return "any"

            try:
                network = ipaddress.ip_network(
                    value,
                    strict=False
                )

                if network.version != 4:
                    return value

                return (
                    f"{network.network_address} "
                    f"{network.hostmask}"
                )

            except ValueError:
                return value

        lines = [
            "ip access-list extended GENERATED-ACL"
        ]

        for number, rule in enumerate(generated_rules, start=10):

            src = cidr_to_wildcard(rule["source"])
            dst = cidr_to_wildcard(rule["destination"])

            action = (
                "permit"
                if rule["action"] == "permit"
                else "deny"
            )

            protocol = rule["protocol"]
            port = rule["port"]

            if protocol in {"tcp", "udp"}:

                if port.lower() == "any":
                    port_part = ""

                elif "-" in port:
                    start, end = port.split("-", 1)
                    port_part = f" range {start} {end}"

                else:
                    port_part = f" eq {port}"

                command = (
                    f" {action} {protocol} "
                    f"{src} {dst}{port_part}"
                )

            elif protocol == "icmp":

                command = (
                    f" {action} icmp "
                    f"{src} {dst}"
                )

            else:

                command = (
                    f" {action} ip "
                    f"{src} {dst}"
                )

            lines.append(command)

        return {
            "vendor": "Cisco IOS / IOS-XE",
            "config": "\n".join(lines),
            "rule_count": len(generated_rules),
        }

    # =========================================================
    # Cisco ASA
    # =========================================================

    if vendor == "cisco_asa":

        def asa_network(value):

            if value.lower() == "any":
                return "any"

            try:
                network = ipaddress.ip_network(
                    value,
                    strict=False
                )

                if network.version != 4:
                    return value

                if network.prefixlen == 32:
                    return (
                        f"host "
                        f"{network.network_address}"
                    )

                return (
                    f"{network.network_address} "
                    f"{network.hostmask}"
                )

            except ValueError:
                return value

        lines = []

        for rule in generated_rules:

            src = asa_network(rule["source"])
            dst = asa_network(rule["destination"])

            action = (
                "permit"
                if rule["action"] == "permit"
                else "deny"
            )

            protocol = rule["protocol"]
            port = rule["port"]

            if protocol in {"tcp", "udp"}:

                port_part = ""

                if port.lower() != "any":

                    if "-" in port:

                        start, end = port.split("-", 1)

                        port_part = (
                            f" range {start} {end}"
                        )

                    else:

                        port_part = f" eq {port}"

                lines.append(
                    f"access-list GENERATED-ACL extended "
                    f"{action} {protocol} "
                    f"{src} {dst}{port_part}"
                )

            elif protocol == "icmp":

                lines.append(
                    f"access-list GENERATED-ACL extended "
                    f"{action} icmp "
                    f"{src} {dst}"
                )

            else:

                lines.append(
                    f"access-list GENERATED-ACL extended "
                    f"{action} ip "
                    f"{src} {dst}"
                )

        return {
            "vendor": "Cisco ASA",
            "config": "\n".join(lines),
            "rule_count": len(generated_rules),
        }

    # =========================================================
    # Aruba CX
    # =========================================================

    if vendor == "aruba_cx":

        lines = [
            "access-list ip GENERATED-ACL"
        ]

        for rule in generated_rules:

            action = (
                "permit"
                if rule["action"] == "permit"
                else "deny"
            )

            command = (
                f"    {action} "
                f"{rule['protocol']} "
                f"{rule['source']} "
                f"{rule['destination']}"
            )

            if (
                rule["protocol"] in {"tcp", "udp"}
                and rule["port"].lower() != "any"
            ):

                if "-" in rule["port"]:

                    start, end = rule["port"].split("-", 1)

                    command += (
                        f" range {start} {end}"
                    )

                else:

                    command += (
                        f" eq {rule['port']}"
                    )

            lines.append(command)

        return {
            "vendor": "Aruba CX",
            "config": "\n".join(lines),
            "rule_count": len(generated_rules),
        }

    # =========================================================
    # ArubaOS-Switch
    # =========================================================

    if vendor == "aruba_os":

        lines = [
            "ip access-list extended GENERATED-ACL"
        ]

        for rule in generated_rules:

            action = (
                "permit"
                if rule["action"] == "permit"
                else "deny"
            )

            command = (
                f"    {action} "
                f"{rule['protocol']} "
                f"{rule['source']} "
                f"{rule['destination']}"
            )

            if (
                rule["protocol"] in {"tcp", "udp"}
                and rule["port"].lower() != "any"
            ):

                if "-" in rule["port"]:

                    start, end = rule["port"].split("-", 1)

                    command += (
                        f" range {start} {end}"
                    )

                else:

                    command += (
                        f" eq {rule['port']}"
                    )

            lines.append(command)

        return {
            "vendor": "ArubaOS-Switch",
            "config": "\n".join(lines),
            "rule_count": len(generated_rules),
        }

    # =========================================================
    # Pica8 / PicOS
    # =========================================================

    if vendor == "pica8":

        lines = [
            "ip access-list extended GENERATED-ACL"
        ]

        for rule in generated_rules:

            action = (
                "permit"
                if rule["action"] == "permit"
                else "deny"
            )

            command = (
                f" {action} "
                f"{rule['protocol']} "
                f"{rule['source']} "
                f"{rule['destination']}"
            )

            if (
                rule["protocol"] in {"tcp", "udp"}
                and rule["port"].lower() != "any"
            ):

                if "-" in rule["port"]:

                    start, end = rule["port"].split("-", 1)

                    command += (
                        f" range {start} {end}"
                    )

                else:

                    command += (
                        f" eq {rule['port']}"
                    )

            lines.append(command)

        return {
            "vendor": "Pica8 / PicOS",
            "config": "\n".join(lines),
            "rule_count": len(generated_rules),
        }

    # =========================================================
    # FortiGate
    # =========================================================

    if vendor == "fortigate":

        lines = [
            "config firewall policy"
        ]

        for number, rule in enumerate(
            generated_rules,
            start=1
        ):

            action = (
                "accept"
                if rule["action"] == "permit"
                else "deny"
            )

            protocol = rule["protocol"]
            port = rule["port"]

            if protocol == "tcp":

                if port == "443":
                    service = "HTTPS"

                elif port == "22":
                    service = "SSH"

                elif port == "80":
                    service = "HTTP"

                else:
                    service = "TCP"

            elif protocol == "udp":

                if port == "53":
                    service = "DNS"

                else:
                    service = "UDP"

            elif protocol == "icmp":

                service = "PING"

            else:

                service = "ALL"

            lines.extend([
                f"    edit {number}",
                f'        set name "{rule["description"]}"',
                f'        set srcaddr "{rule["source"]}"',
                f'        set dstaddr "{rule["destination"]}"',
                f"        set action {action}",
                f'        set service "{service}"',
                '        set schedule "always"',
                "    next",
            ])

        lines.append("end")

        return {
            "vendor": "FortiGate",
            "config": "\n".join(lines),
            "rule_count": len(generated_rules),
        }

    # =========================================================
    # Palo Alto PAN-OS
    # =========================================================

    if vendor == "paloalto":

        lines = []

        for number, rule in enumerate(
            generated_rules,
            start=1
        ):

            action = (
                "allow"
                if rule["action"] == "permit"
                else "deny"
            )

            service = (
                f"{rule['protocol'].upper()}-"
                f"{rule['port']}"
                if rule["port"] != "any"
                else "ANY"
            )

            lines.extend([
                f"Rule {number}: "
                f"{rule['description']}",
                f"  Source: {rule['source']}",
                f"  Destination: {rule['destination']}",
                f"  Protocol: {rule['protocol'].upper()}",
                f"  Service: {service}",
                f"  Action: {action}",
                "",
            ])

        return {
            "vendor": "Palo Alto PAN-OS",
            "config": "\n".join(lines).rstrip(),
            "rule_count": len(generated_rules),
        }

    raise ValueError("Unsupported vendor.")


# ---------------------------------------------------------------------------
# Security response headers
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    # The production site is served over HTTPS through Cloudflare/Render.
    # We intentionally do not use includeSubDomains until all subdomains
    # have been verified to be HTTPS-only.
    response.headers["Strict-Transport-Security"] = "max-age=31536000"

    return response


# ---------------------------------------------------------------------------
# Portfolio pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/robots.txt")
def robots_txt():
    content = "\n".join([
        "User-agent: *",
        "Allow: /",
        f"Sitemap: {app.config['SITE_URL']}/sitemap.xml",
        ""
    ])
    return Response(content, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    public_endpoints = [
        "home",
        "about",
        "projects",
        "network_diagnostic_lab",
        "network_toolkit_project",
        "noida_sez_project",
        "noida_stp2_project",
        "network_toolkit",
        "ip_calculator",
        "subnet_planner",
        "ip_range",
        "dns_lookup",
        "port_checker",
        "subnet_wildcard",
        "acl_generator",
        "protocol_port_lookup",
        "command_finder",
    ]

    urls = []
    for endpoint in public_endpoints:
        urls.append(
            f"    <url><loc>{app.config['SITE_URL']}{url_for(endpoint)}</loc></url>"
        )

    xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    xml += "\n".join(urls)
    xml += "\n</urlset>\n"
    return Response(xml, mimetype="application/xml")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/projects")
def projects():
    return render_template("projects.html")


@app.route("/network-diagnostic-lab")
def network_diagnostic_lab():
    return render_template("network_diagnostic_lab.html")


@app.route("/projects/network-toolkit")
def network_toolkit_project():
    return render_template("network_toolkit_project.html")


@app.route("/projects/noida-sez-network")
def noida_sez_project():
    return render_template("noida_sez_project.html")

@app.route("/projects/noida-stp2-aruba")
def noida_stp2_project():
    return render_template("noida_stp2_aruba.html")

@app.route("/network-toolkit", methods=["GET", "POST"])
def network_toolkit():
    return render_template("network_toolkit.html")

@app.route('/healthz')
def healthz():
    """Uptime monitoring endpoint to prevent Render free-tier spin-downs."""
    return {"status": "healthy"}, 200


# ---------------------------------------------------------------------------
# Network Engineering Tools
# ---------------------------------------------------------------------------


@app.route(
    "/api/diagnostic/reverse-dns",
    methods=["POST"]
)
def diagnostic_reverse_dns():

    data = request.get_json(silent=True) or {}
    value = data.get("ip", "").strip()

    try:
        ip = ipaddress.ip_address(value)

        result = resolve_reverse_dns(ip)

        return jsonify({
            "success": True,
            "result": result,
        })

    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400


@app.route(
    "/api/diagnostic/ip-info",
    methods=["POST"]
)
def diagnostic_ip_info():

    data = request.get_json(silent=True) or {}
    value = data.get("ip", "").strip()

    try:
        network = ipaddress.ip_network(
            value,
            strict=False
        )

        first_host, last_host, usable_hosts = (
            first_and_last_host(network)
        )

        result = {
            "network": str(network),
            "version": f"IPv{network.version}",
            "network_address": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "hostmask": str(network.hostmask),
            "prefix": network.prefixlen,
            "total_addresses": network.num_addresses,
            "first_host": first_host,
            "last_host": last_host,
            "usable_hosts": usable_hosts,
        }

        return jsonify({
            "success": True,
            "result": result,
        })

    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400



@app.route(
    "/api/diagnostic/tcp",
    methods=["POST"]
)
def diagnostic_tcp():

    data = request.get_json(silent=True) or {}

    host = data.get("host", "").strip()

    try:
        port = int(data.get("port", 443))
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "error": "Invalid port."
        }), 400

    try:
        if not 1 <= port <= 65535:
            raise ValueError(
                "Port must be between 1 and 65535."
            )

        target = validate_diagnostic_target(host)

        start = time.perf_counter()

        sock = socket.create_connection(
            (target, port),
            timeout=SOCKET_TIMEOUT
        )

        sock.close()

        elapsed = round(
            (time.perf_counter() - start) * 1000,
            2
        )

        return jsonify({
            "success": True,
            "result": {
                "host": host,
                "port": port,
                "status": "OPEN",
                "latency_ms": elapsed,
            }
        })

    except Exception as exc:
        return jsonify({
            "success": True,
            "result": {
                "host": host,
                "port": port,
                "status": "CLOSED / UNREACHABLE",
                "error": str(exc),
            }
        })


@app.route(
    "/api/diagnostic/http-headers",
    methods=["POST"]
)
def diagnostic_http_headers():

    data = request.get_json(silent=True) or {}

    raw_url = data.get("url", "").strip()

    try:
        if len(raw_url) > 2048:
            raise ValueError("URL is too long.")

        parsed = urllib.parse.urlparse(raw_url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                "Only HTTP and HTTPS URLs are allowed."
            )

        if not parsed.hostname:
            raise ValueError("Invalid URL.")

        validate_diagnostic_target(parsed.hostname)

        port = parsed.port

        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                port or 443,
                timeout=DIAGNOSTIC_TIMEOUT,
                context=ssl.create_default_context()
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname,
                port or 80,
                timeout=DIAGNOSTIC_TIMEOUT
            )

        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        start = time.perf_counter()

        connection.request(
            "HEAD",
            path,
            headers={
                "User-Agent": DIAGNOSTIC_USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            }
        )

        response = connection.getresponse()

        elapsed = round(
            (time.perf_counter() - start) * 1000,
            2
        )

        headers = dict(response.getheaders())

        connection.close()

        return jsonify({
            "success": True,
            "result": {
                "url": raw_url,
                "status": response.status,
                "reason": response.reason,
                "latency_ms": elapsed,
                "headers": headers,
            }
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400



@app.route(
    "/api/diagnostic/mac-vendor",
    methods=["POST"]
)
def diagnostic_mac_vendor():

    data = request.get_json(silent=True) or {}

    try:
        mac = normalize_mac(
            data.get("mac", "")
        )

        encoded = urllib.parse.quote(mac)

        request_obj = urllib.request.Request(
            f"https://api.macvendors.com/{encoded}",
            headers={
                "User-Agent": DIAGNOSTIC_USER_AGENT
            }
        )

        with urllib.request.urlopen(
            request_obj,
            timeout=DIAGNOSTIC_TIMEOUT
        ) as response:

            vendor = response.read(
                4096
            ).decode(
                "utf-8",
                errors="replace"
            ).strip()

        if not vendor:
            raise ValueError(
                "Vendor not found."
            )

        return jsonify({
            "success": True,
            "result": {
                "mac": mac,
                "vendor": vendor,
            }
        })

    except urllib.error.HTTPError as exc:

        if exc.code == 404:
            message = "MAC vendor not found."
        elif exc.code == 429:
            message = "MAC vendor service rate limit reached."
        else:
            message = "MAC vendor lookup failed."

        return jsonify({
            "success": False,
            "error": message,
        }), 502

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400


DNS_RESOLVERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/resolve",
    "Quad9": "https://dns.quad9.net:5053/dns-query",
}


@app.route(
    "/api/diagnostic/dns-propagation",
    methods=["POST"]
)
def diagnostic_dns_propagation():

    data = request.get_json(silent=True) or {}

    hostname = normalize_hostname(
        data.get("hostname", "")
    )

    record_type = data.get(
        "record_type",
        "A"
    ).upper()

    allowed_types = {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
    }

    if record_type not in allowed_types:
        return jsonify({
            "success": False,
            "error": "Unsupported DNS record type."
        }), 400

    results = {}

    for resolver_name, resolver_url in DNS_RESOLVERS.items():

        try:
            params = urllib.parse.urlencode({
                "name": hostname,
                "type": record_type,
            })

            request_obj = urllib.request.Request(
                resolver_url + "?" + params,
                headers={
                    "User-Agent": DIAGNOSTIC_USER_AGENT,
                    "Accept": "application/dns-json",
                }
            )

            with urllib.request.urlopen(
                request_obj,
                timeout=DIAGNOSTIC_TIMEOUT
            ) as response:

                payload = json.loads(
                    response.read(
                        128 * 1024
                    ).decode(
                        "utf-8",
                        errors="replace"
                    )
                )

            answers = []

            for answer in payload.get(
                "Answer",
                []
            ):
                answers.append({
                    "name": answer.get("name"),
                    "type": answer.get("type"),
                    "ttl": answer.get("TTL"),
                    "data": answer.get("data"),
                })

            results[resolver_name] = {
                "status": "SUCCESS",
                "answers": answers,
            }

        except Exception as exc:
            results[resolver_name] = {
                "status": "ERROR",
                "error": str(exc),
            }

    return jsonify({
        "success": True,
        "hostname": hostname,
        "record_type": record_type,
        "resolvers": results,
    })


@app.route(
    "/api/diagnostic/rdap",
    methods=["POST"]
)
def diagnostic_rdap():

    data = request.get_json(silent=True) or {}
    value = data.get("query", "").strip()

    try:
        try:
            address = ipaddress.ip_address(value)
            lookup_url = (
                f"https://rdap.org/ip/{address}"
            )
        except ValueError:

            hostname = normalize_hostname(value)

            lookup_url = (
                f"https://rdap.org/domain/"
                f"{urllib.parse.quote(hostname)}"
            )

        payload = fetch_json(
            lookup_url,
            timeout=DIAGNOSTIC_TIMEOUT
        )

        return jsonify({
            "success": True,
            "result": payload,
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400


@app.route(
    "/api/diagnostic/bgp",
    methods=["POST"]
)
def diagnostic_bgp():

    data = request.get_json(silent=True) or {}
    value = data.get("query", "").strip()

    try:
        ip = ipaddress.ip_address(value)

        encoded = urllib.parse.quote(
            str(ip)
        )

        url = (
            "https://stat.ripe.net/data/"
            "network-info/data.json?resource="
            + encoded
        )

        payload = fetch_json(url)

        return jsonify({
            "success": True,
            "result": payload.get(
                "data",
                payload
            ),
        })

    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "BGP/ASN lookup failed.",
        }), 502

@app.route(
    "/api/diagnostic/traceroute",
    methods=["POST"]
)
def diagnostic_traceroute():

    data = request.get_json(silent=True) or {}

    target = data.get(
        "target",
        ""
    ).strip()

    try:
        target = validate_diagnostic_target(
            target
        )

        system = platform.system().lower()

        if system == "windows":

            command = [
                "tracert",
                "-d",
                "-h",
                str(MAX_TRACE_HOPS),
                target,
            ]

        else:

            command = [
                "traceroute",
                "-n",
                "-m",
                str(MAX_TRACE_HOPS),
                target,
            ]

        result = run_command(
            command,
            timeout=45
        )

        return jsonify({
            "success": True,
            "target": target,
            "output": (
                result["stdout"]
                + result["stderr"]
            )[-20000:],
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400






# ---------------------------------------------------------------------------
# Network Engineering Toolkit
# ---------------------------------------------------------------------------

@app.route("/ip-calculator", methods=["GET", "POST"])
def ip_calculator():
    result = None
    error = None

    if request.method == "POST":
        ip_input = request.form.get("ip_address", "").strip()

        try:
            if len(ip_input) > 50:
                raise ValueError("IP address input is too long.")

            network = ipaddress.ip_network(ip_input, strict=False)
            first_host, last_host, usable_hosts = first_and_last_host(network)

            result = {
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "netmask": str(network.netmask),
                "hostmask": str(network.hostmask),
                "first_host": first_host,
                "last_host": last_host,
                "total_addresses": network.num_addresses,
                "usable_hosts": usable_hosts,
                "prefix": network.prefixlen,
            }

        except ValueError:
            error = (
                "Invalid IP address or CIDR format. "
                "Example: 192.168.10.0/24"
            )

    return render_template(
        "ip_calculator.html",
        result=result,
        error=error
    )

@app.route("/subnet-planner", methods=["GET", "POST"])
def subnet_planner():
    subnets = None
    error = None

    if request.method == "POST":
        network_input = request.form.get("network", "").strip()
        required_subnets = request.form.get("required_subnets", "").strip()

        try:
            if len(network_input) > 50:
                raise ValueError("Network input is too long.")

            network = ipaddress.ip_network(network_input, strict=False)
            count = int(required_subnets)

            if count < 1:
                raise ValueError("Number of subnets must be at least 1.")

            if count > MAX_SUBNETS:
                raise ValueError(
                    f"Maximum {MAX_SUBNETS} subnets are allowed."
                )

            # Find the smallest subnet prefix that can create at least the
            # requested number of subnets.
            new_prefix = network.prefixlen

            while (2 ** (new_prefix - network.prefixlen)) < count:
                new_prefix += 1

            if new_prefix > network.max_prefixlen:
                raise ValueError(
                    "The requested number of subnets is too large."
                )

            # islice-like slicing is not needed because the number of
            # generated subnet objects is capped at 1024.
            subnet_list = network.subnets(new_prefix=new_prefix)

            subnets = []

            for number in range(1, count + 1):
                try:
                    subnet = next(subnet_list)
                except StopIteration:
                    raise ValueError(
                        "The requested number of subnets could not be generated."
                    )

                details = subnet_details(subnet)
                details["number"] = number
                subnets.append(details)

        except (ValueError, TypeError, OverflowError) as exc:
            error = str(exc) or "Invalid subnet planner input."

    return render_template(
        "subnet_planner.html",
        subnets=subnets,
        error=error
    )


@app.route("/ip-range", methods=["GET", "POST"])
def ip_range():
    result = None
    error = None

    if request.method == "POST":
        start_ip = request.form.get("start_ip", "").strip()
        end_ip = request.form.get("end_ip", "").strip()

        try:
            if len(start_ip) > 50 or len(end_ip) > 50:
                raise ValueError("IP address input is too long.")

            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)

            if start.version != end.version:
                raise ValueError(
                    "Start IP and End IP must use the same IP version."
                )

            if int(start) > int(end):
                raise ValueError(
                    "Start IP cannot be greater than End IP."
                )

            total_ips = int(end) - int(start) + 1

            result = {
                "start": str(start),
                "end": str(end),
                "total": total_ips,
                "version": f"IPv{start.version}",
            }

        except ValueError as exc:
            error = str(exc)

    return render_template(
        "ip_range.html",
        result=result,
        error=error
    )


@app.route("/dns-lookup", methods=["GET", "POST"])
def dns_lookup():
    result = None
    error = None

    if request.method == "POST":
        hostname_input = request.form.get("hostname", "")

        try:
            hostname = normalize_hostname(hostname_input)

            host_info = socket.gethostbyname_ex(hostname)

            canonical_name = host_info[0]
            aliases = host_info[1]
            addresses = host_info[2]

            result = {
                "hostname": hostname,
                "canonical": canonical_name,
                "aliases": aliases,
                "addresses": addresses,
            }

        except socket.gaierror:
            error = (
                "DNS lookup failed. Please check the hostname "
                "and try again."
            )

        except ValueError as exc:
            error = str(exc)

    return render_template(
        "dns_lookup.html",
        result=result,
        error=error
    )


@app.route("/port-checker", methods=["GET", "POST"])
def port_checker():
    result = None
    error = None

    if request.method == "POST":
        host = request.form.get("host", "").strip()
        port_input = request.form.get("port", "").strip()

        try:
            if len(host) > MAX_HOSTNAME_LENGTH:
                raise ValueError("Hostname or IP address is too long.")

            port = int(port_input)

            if port < 1 or port > 65535:
                raise ValueError(
                    "Port must be between 1 and 65535."
                )

            addresses = get_safe_host_addresses(host)

            connection_result = None
            successful_ip = None

            # Try each globally routable address until one succeeds.
            for family, resolved_ip in addresses:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(SOCKET_TIMEOUT)

                try:
                    if family == socket.AF_INET6:
                        connection_result = sock.connect_ex(
                            (resolved_ip, port, 0, 0)
                        )
                    else:
                        connection_result = sock.connect_ex(
                            (resolved_ip, port)
                        )

                    if connection_result == 0:
                        successful_ip = resolved_ip
                        break

                finally:
                    sock.close()

            if successful_ip:
                status = "OPEN"
                display_ip = successful_ip
            else:
                status = "CLOSED / UNREACHABLE"
                display_ip = addresses[0][1]

            result = {
                "host": host,
                "ip": display_ip,
                "port": port,
                "status": status,
            }

        except ValueError as exc:
            error = str(exc)

        except socket.gaierror:
            error = (
                "Unable to resolve the hostname. "
                "Check the hostname or IP address."
            )

        except (socket.timeout, TimeoutError):
            error = "Connection timed out."

        except OSError:
            error = "Unable to connect to the specified host."

    return render_template(
        "port_checker.html",
        result=result,
        error=error
    )


@app.route("/subnet-wildcard", methods=["GET", "POST"])
def subnet_wildcard():
    result = None
    error = None

    # IPv4 special-purpose / reserved address classifications.
    # Ordered from more specific ranges to broader ranges where needed.
    ipv4_classifications = [
        ("0.0.0.0/8", "This Network / Special Purpose", "RFC 6890"),
        ("10.0.0.0/8", "Private IPv4", "RFC 1918"),
        ("100.64.0.0/10", "Shared Address Space / CGNAT", "RFC 6598"),
        ("127.0.0.0/8", "Loopback", "RFC 1122"),
        ("169.254.0.0/16", "Link-Local", "RFC 3927"),
        ("172.16.0.0/12", "Private IPv4", "RFC 1918"),
        ("192.0.0.0/24", "IETF Protocol Assignments / Special Purpose", "RFC 6890"),
        ("192.0.2.0/24", "Documentation", "RFC 5737"),
        ("192.168.0.0/16", "Private IPv4", "RFC 1918"),
        ("198.18.0.0/15", "Benchmarking", "RFC 2544"),
        ("198.51.100.0/24", "Documentation", "RFC 5737"),
        ("203.0.113.0/24", "Documentation", "RFC 5737"),
        ("224.0.0.0/4", "Multicast", "RFC 1112"),
        ("240.0.0.0/4", "Reserved", "RFC 6890"),
    ]

    if request.method == "POST":
        cidr = request.form.get("cidr", "").strip()

        try:
            if len(cidr) > 50:
                raise ValueError("CIDR input is too long.")

            network = ipaddress.ip_network(cidr, strict=False)

            if network.version != 4:
                raise ValueError(
                    "Only IPv4 networks are supported."
                )

            first_host, last_host, usable_hosts = first_and_last_host(network)

            network_ip = network.network_address

            # Default classification for ordinary public IPv4 space.
            classification = "Global Unicast / Public IPv4"
            rfc = "RFC 6890"
            classification_range = "Global Unicast"

            # Match the network address against the classification table.
            for cidr_range, name, rfc_reference in ipv4_classifications:
                special_network = ipaddress.ip_network(
                    cidr_range
                )

                if network_ip in special_network:
                    classification = name
                    rfc = rfc_reference
                    classification_range = cidr_range
                    break

            # Limited broadcast is a single address rather than a network.
            if network_ip == ipaddress.ip_address("255.255.255.255"):
                classification = "Limited Broadcast"
                rfc = "RFC 1122"
                classification_range = "255.255.255.255/32"

            result = {
                "network": str(network.network_address),
                "cidr": str(network),
                "prefix": network.prefixlen,
                "netmask": str(network.netmask),
                "wildcard": str(network.hostmask),
                "broadcast": str(network.broadcast_address),
                "first_host": first_host,
                "last_host": last_host,
                "total_addresses": network.num_addresses,
                "usable_hosts": usable_hosts,

                # Classification information
                "classification": classification,
                "rfc": rfc,
                "classification_range": classification_range,
            }

        except (ValueError, TypeError, OverflowError) as exc:
            error = str(exc) or (
                "Invalid IPv4 address or CIDR format. "
                "Example: 192.168.10.0/24"
            )

    return render_template(
        "subnet_wildcard.html",
        result=result,
        error=error
    )




@app.route("/acl-generator", methods=["GET", "POST"])
def acl_generator():
    result = None
    error = None

    if request.method == "POST":

        vendor = request.form.get("vendor", "").strip()

        try:
            allowed_vendors = {
                "cisco_ios",
                "cisco_asa",
                "aruba_cx",
                "aruba_os",
                "pica8",
                "fortigate",
                "paloalto",
            }

            if vendor not in allowed_vendors:
                raise ValueError(
                    "Please select a supported platform."
                )

            # -------------------------------------------------
            # Read number of rules
            # -------------------------------------------------

            rule_count = int(
                request.form.get("rule_count", "1")
            )

            if rule_count < 1:
                raise ValueError(
                    "At least one rule is required."
                )

            if rule_count > 20:
                raise ValueError(
                    "Maximum 20 rules are allowed."
                )

            rules = []

            # -------------------------------------------------
            # Read each logical rule
            # -------------------------------------------------

            for index in range(rule_count):

                sources_raw = request.form.get(
                    f"sources_{index}",
                    ""
                ).strip()

                destinations_raw = request.form.get(
                    f"destinations_{index}",
                    ""
                ).strip()

                ports_raw = request.form.get(
                    f"ports_{index}",
                    ""
                ).strip()

                protocol = request.form.get(
                    f"protocol_{index}",
                    "ip"
                ).strip().lower()

                action = request.form.get(
                    f"action_{index}",
                    "permit"
                ).strip().lower()

                description = request.form.get(
                    f"description_{index}",
                    f"Generated Rule {index + 1}"
                ).strip()

                if protocol not in {
                    "ip",
                    "tcp",
                    "udp",
                    "icmp",
                }:
                    raise ValueError(
                        f"Rule {index + 1}: "
                        "Invalid protocol."
                    )

                if action not in {
                    "permit",
                    "deny",
                }:
                    raise ValueError(
                        f"Rule {index + 1}: "
                        "Invalid action."
                    )

                # -------------------------------------------------
                # Convert textarea lines into lists
                # -------------------------------------------------

                sources = [
                    item.strip()
                    for item in sources_raw.splitlines()
                    if item.strip()
                ]

                destinations = [
                    item.strip()
                    for item in destinations_raw.splitlines()
                    if item.strip()
                ]

                ports = [
                    item.strip()
                    for item in ports_raw.splitlines()
                    if item.strip()
                ]

                # -------------------------------------------------
                # Default to ANY
                # -------------------------------------------------

                if not sources:
                    sources = ["any"]

                if not destinations:
                    destinations = ["any"]

                if protocol not in {"tcp", "udp"}:
                    ports = ["any"]

                elif not ports:
                    ports = ["any"]

                # -------------------------------------------------
                # Validate IP networks
                # -------------------------------------------------

                for source in sources:

                    if source.lower() == "any":
                        continue

                    try:
                        network = ipaddress.ip_network(
                            source,
                            strict=False
                        )

                        if network.version != 4:
                            raise ValueError

                    except ValueError:

                        raise ValueError(
                            f"Rule {index + 1}: "
                            f"Invalid source network: {source}"
                        )

                for destination in destinations:

                    if destination.lower() == "any":
                        continue

                    try:
                        network = ipaddress.ip_network(
                            destination,
                            strict=False
                        )

                        if network.version != 4:
                            raise ValueError

                    except ValueError:

                        raise ValueError(
                            f"Rule {index + 1}: "
                            f"Invalid destination network: "
                            f"{destination}"
                        )

                # -------------------------------------------------
                # Validate ports
                # -------------------------------------------------

                if protocol in {"tcp", "udp"}:

                    for port in ports:

                        if port.lower() == "any":
                            continue

                        if "-" in port:

                            parts = port.split("-", 1)

                            if len(parts) != 2:
                                raise ValueError

                            try:
                                start = int(parts[0])
                                end = int(parts[1])

                            except ValueError:

                                raise ValueError(
                                    f"Rule {index + 1}: "
                                    f"Invalid port range: {port}"
                                )

                            if (
                                start < 1
                                or end > 65535
                                or start > end
                            ):
                                raise ValueError(
                                    f"Rule {index + 1}: "
                                    f"Invalid port range: {port}"
                                )

                        else:

                            try:
                                port_number = int(port)

                            except ValueError:

                                raise ValueError(
                                    f"Rule {index + 1}: "
                                    f"Invalid port: {port}"
                                )

                            if not (
                                1 <= port_number <= 65535
                            ):
                                raise ValueError(
                                    f"Rule {index + 1}: "
                                    f"Port must be between "
                                    f"1 and 65535."
                                )

                # -------------------------------------------------
                # Protect against excessive combinations
                # -------------------------------------------------

                combinations = (
                    len(sources)
                    * len(destinations)
                    * len(ports)
                )

                if combinations > 500:

                    raise ValueError(
                        f"Rule {index + 1} would generate "
                        f"{combinations} ACL entries. "
                        "Maximum is 500 per rule."
                    )

                rules.append({
                    "sources": sources,
                    "destinations": destinations,
                    "ports": ports,
                    "protocol": protocol,
                    "action": action,
                    "description": (
                        description
                        or f"Generated Rule {index + 1}"
                    ),
                })

            # -------------------------------------------------
            # Generate vendor configuration
            # -------------------------------------------------

            result = generate_acl_config(
                vendor=vendor,
                rules=rules,
            )

            # -------------------------------------------------
            # Additional summary information
            # -------------------------------------------------

            result["logical_rules"] = len(rules)

            result["source_count"] = sum(
                len(rule["sources"])
                for rule in rules
            )

            result["destination_count"] = sum(
                len(rule["destinations"])
                for rule in rules
            )

            result["port_count"] = sum(
                len(rule["ports"])
                for rule in rules
            )

        except (
            ValueError,
            TypeError,
            OverflowError,
        ) as exc:

            error = (
                str(exc)
                or "Unable to generate ACL configuration."
            )

    return render_template(
        "acl_generator.html",
        result=result,
        error=error,
    )


@app.route("/protocol-port-lookup", methods=["GET"])
def protocol_port_lookup():

    query = request.args.get(
        "q",
        ""
    ).strip().lower()

    category = request.args.get(
        "category",
        ""
    ).strip()

    results = PROTOCOL_PORT_DATABASE

    if category:
        results = [
            item
            for item in results
            if item["category"].lower() == category.lower()
        ]

    if query:

        results = [
            item
            for item in results
            if (
                query in item["service"].lower()
                or query in item["port"].lower()
                or query in item["transport"].lower()
                or query in item["category"].lower()
                or query in item["purpose"].lower()
                or query in item["platforms"].lower()
                or query in item["notes"].lower()
            )
        ]

    categories = sorted(
        {
            item["category"]
            for item in PROTOCOL_PORT_DATABASE
        }
    )

    return render_template(
        "protocol_port_lookup.html",
        results=results,
        categories=categories,
        query=query,
        selected_category=category,
    )

# ---------------------------------------------------------------------------
# Network Command Finder - Tool 10
# ---------------------------------------------------------------------------

COMMAND_FINDER_VENDORS = {
    "Cisco IOS / IOS-XE": [
        "cisco.com",
    ],
    "Cisco NX-OS": [
        "cisco.com",
    ],
    "Aruba": [
        "arubanetworking.hpe.com",
        "hpe.com",
    ],
    "Dell": [
        "dell.com",
    ],
    "Pica8": [
        "pica8.com",
    ],
    "FortiGate": [
        "fortinet.com",
    ],
    "Palo Alto": [
        "paloaltonetworks.com",
    ],
    "Check Point": [
        "checkpoint.com",
    ],
    "Juniper": [
        "juniper.net",
    ],
    "Arista": [
        "arista.com",
    ],
    "Huawei": [
        "huawei.com",
    ],
    "MikroTik": [
        "mikrotik.com",
    ],
    "Linux": [
        "kernel.org",
        "man7.org",
    ],
    "Windows": [
        "learn.microsoft.com",
    ],
}


# def search_network_commands(query, vendor="all"):
#     """
#     Search official vendor documentation through Tavily.

#     The API key is read only from the server-side environment and is
#     never exposed to the browser.
#     """

#     query = query.strip()

#     if not query:
#         raise ValueError("Please enter a command or networking topic.")

#     if len(query) > 200:
#         raise ValueError(
#             "Search query is too long. Maximum 200 characters."
#         )

#     api_key = os.environ.get("TAVILY_API_KEY")

#     if not api_key:
#         raise RuntimeError(
#             "Tavily API key is not configured on the server."
#         )

#     client = TavilyClient(api_key=api_key)

#     # Build a documentation-focused search query.
#     if vendor and vendor != "all":

#         domains = COMMAND_FINDER_VENDORS.get(vendor)

#         if not domains:
#             raise ValueError("Unsupported vendor selected.")

#         domain_query = " OR ".join(
#             f"site:{domain}"
#             for domain in domains
#         )

#         search_query = (
#             f"{query} network command configuration documentation "
#             f"({domain_query})"
#         )

#     else:

#         all_domains = []

#         for domains in COMMAND_FINDER_VENDORS.values():
#             all_domains.extend(domains)

#         # Remove duplicates while preserving order.
#         all_domains = list(dict.fromkeys(all_domains))

#         domain_query = " OR ".join(
#             f"site:{domain}"
#             for domain in all_domains
#         )

#         search_query = (
#             f"{query} network command configuration documentation "
#             f"({domain_query})"
#         )

#     response = client.search(
#         search_query,
#         search_depth="basic",
#         max_results=8,
#         include_answer=False,
#     )

#     results = []

#     for item in response.get("results", []):

#         title = str(
#             item.get("title", "")
#         ).strip()

#         url = str(
#             item.get("url", "")
#         ).strip()

#         content = str(
#             item.get("content", "")
#         ).strip()

#         if not title or not url:
#             continue

#         results.append(
#             {
#                 "title": title,
#                 "url": url,
#                 "content": content,
#             }
#         )

#     return results

def extract_command_candidates(text, search_query=""):
    """
    Extract likely CLI commands from retrieved documentation.

    This function does NOT generate commands.
    It only extracts command-like syntax that appears in the
    retrieved documentation.
    """

    if not text:
        return []

    candidates = []

    # Normalize the search query so we can prefer commands
    # related to what the user actually searched for.
    search_query = search_query.strip().lower()

    # ---------------------------------------------------------
    # Helper: validate a possible CLI command
    # ---------------------------------------------------------

    def is_valid_command(value):

        value = value.strip()

        if not value:
            return False

        # Length protection.
        if len(value) < 3 or len(value) > 180:
            return False

        lower = value.lower()

        # -----------------------------------------------------
        # Reject obvious non-command values
        # -----------------------------------------------------

        rejected_exact = {
            "ip",
            "interface",
            "interface name",
            "route-interface",
            "ip-route(8)",
            "route",
            "network",
            "address",
            "mask",
            "destination-address",
            "next-hop-address",
        }

        if lower in rejected_exact:
            return False

        # -----------------------------------------------------
        # Reject filesystem paths / URLs
        # -----------------------------------------------------

        if lower.startswith(
            (
                "/etc/",
                "/usr/",
                "/var/",
                "http://",
                "https://",
            )
        ):
            return False

        # -----------------------------------------------------
        # Reject man pages
        # -----------------------------------------------------

        if re.match(
            r"^[a-z0-9_-]+\(\d+\)$",
            lower
        ):
            return False

        # -----------------------------------------------------
        # Reject obvious parameter placeholders by themselves
        # -----------------------------------------------------

        if re.fullmatch(
            r"[<\[][a-z0-9_. -]+[>\]]",
            lower
        ):
            return False

        # -----------------------------------------------------
        # Reject ordinary documentation sentences
        # -----------------------------------------------------

        if value.endswith(
            (".", "?", "!")
        ):
            return False

        prose_prefixes = (
            "the ",
            "this ",
            "these ",
            "those ",
            "a ",
            "an ",
            "when ",
            "where ",
            "which ",
            "used ",
            "use the ",
            "displays ",
            "display the ",
            "specifies ",
            "specify ",
            "provides ",
            "allows ",
            "indicates ",
            "indicate ",
            "parameter ",
            "parameters ",
            "description ",
            "command objective ",
            "interface name ",
            "ip address ",
        )

        if lower.startswith(prose_prefixes):
            return False

        # -----------------------------------------------------
        # Reject obviously long prose
        # -----------------------------------------------------

        if len(value.split()) > 18:
            return False

        # -----------------------------------------------------
        # Strong CLI command prefixes
        # -----------------------------------------------------

        command_prefixes = (
            "show ",
            "display ",
            "get ",
            "set ",
            "configure ",
            "config ",
            "interface ",
            "router ",
            "ip route ",
            "ip address ",
            "ip access-list ",
            "ipv6 route ",
            "network ",
            "vlan ",
            "switchport ",
            "neighbor ",
            "route ",
            "no ",
            "diagnose ",
            "diagnostic ",
            "edit ",
            "delete ",
            "commit",
            "request ",
            "run ",
            "system ",
            "firewall ",
        )

        has_command_prefix = lower.startswith(
            command_prefixes
        )

        # -----------------------------------------------------
        # If it doesn't look like a command, reject it.
        # -----------------------------------------------------

        if not has_command_prefix:
            return False

        # -----------------------------------------------------
        # Reject obvious explanatory fragments.
        # -----------------------------------------------------

        if lower in {
            "show",
            "display",
            "get",
            "set",
            "configure",
            "config",
            "interface",
            "router",
            "network",
            "vlan",
            "switchport",
            "neighbor",
            "system",
            "firewall",
        }:
            return False

        return True

    # ---------------------------------------------------------
    # 1. Extract Markdown / inline code
    # ---------------------------------------------------------

    code_matches = re.findall(
        r"`([^`]+)`",
        text
    )

    for match in code_matches:

        candidate = match.strip()

        if is_valid_command(candidate):
            candidates.append(candidate)

    # ---------------------------------------------------------
    # 2. Extract command-looking lines
    # ---------------------------------------------------------

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        # Remove Markdown bullets / numbering.
        line = re.sub(
            r"^[>*+\-\d.)\s]+",
            "",
            line
        ).strip()

        # Remove surrounding code markers.
        line = line.strip("`").strip()

        if not line:
            continue

        if is_valid_command(line):
            candidates.append(line)

    # ---------------------------------------------------------
    # 3. Prefer commands containing the searched keyword.
    # ---------------------------------------------------------

    if search_query:

        search_words = [
            word
            for word in re.findall(
                r"[a-z0-9_-]+",
                search_query
            )
            if len(word) >= 2
        ]

        matching = []
        non_matching = []

        for candidate in candidates:

            candidate_lower = candidate.lower()

            if all(
                word in candidate_lower
                for word in search_words
            ):
                matching.append(candidate)
            else:
                non_matching.append(candidate)

        candidates = matching + non_matching

    # ---------------------------------------------------------
    # 4. Remove duplicates while preserving order.
    # ---------------------------------------------------------

    unique_candidates = []

    seen = set()

    for candidate in candidates:

        # Normalize whitespace.
        candidate = re.sub(
            r"\s+",
            " ",
            candidate
        ).strip()

        key = candidate.lower()

        if key in seen:
            continue

        seen.add(key)
        unique_candidates.append(candidate)

    return unique_candidates[:10]



def detect_documentation_source(url):
    """
    Identify the likely vendor/source from a documentation URL.
    """

    url_lower = url.lower()

    source_map = (
        ("cisco.com", "Cisco"),
        ("arubanetworks.com", "Aruba"),
        ("hpe.com", "HPE"),
        ("dell.com", "Dell"),
        ("pica8.com", "Pica8"),
        ("fortinet.com", "Fortinet"),
        ("fortiguard.com", "Fortinet"),
        ("paloaltonetworks.com", "Palo Alto"),
        ("juniper.net", "Juniper"),
        ("checkpoint.com", "Check Point"),
        ("arista.com", "Arista"),
        ("huawei.com", "Huawei"),
        ("mikrotik.com", "MikroTik"),
        ("microsoft.com", "Microsoft"),
        ("redhat.com", "Red Hat"),
        ("linux.org", "Linux"),
        ("kernel.org", "Linux"),
    )

    for domain, vendor_name in source_map:

        if domain in url_lower:
            return vendor_name

    return "Other Source"


def search_network_commands(query, vendor="all"):
    """
    Search official vendor documentation through Tavily and extract
    command candidates directly from the returned documentation.

    Commands are extracted from source text. They are not generated.
    """

    query = query.strip()

    if not query:
        raise ValueError(
            "Please enter a command or networking topic."
        )

    if len(query) > 200:
        raise ValueError(
            "Search query is too long. Maximum 200 characters."
        )

    api_key = os.environ.get("TAVILY_API_KEY")

    if not api_key:
        raise RuntimeError(
            "Tavily API key is not configured on the server."
        )

    client = TavilyClient(api_key=api_key)

    if vendor and vendor != "all":

        domains = COMMAND_FINDER_VENDORS.get(vendor)

        if not domains:
            raise ValueError(
                "Unsupported vendor selected."
            )

        domain_query = " OR ".join(
            f"site:{domain}"
            for domain in domains
        )

        search_query = (
            f"{query} CLI command configuration "
            f"documentation ({domain_query})"
        )

    else:

        all_domains = []

        for domains in COMMAND_FINDER_VENDORS.values():
            all_domains.extend(domains)

        all_domains = list(
            dict.fromkeys(all_domains)
        )

        domain_query = " OR ".join(
            f"site:{domain}"
            for domain in all_domains
        )

        search_query = (
            f"{query} CLI command configuration "
            f"documentation ({domain_query})"
        )

    response = client.search(
        search_query,
        search_depth="basic",
        max_results=8,
        include_answer=False,
    )

    results = []

    for item in response.get("results", []):

        title = str(
            item.get("title", "")
        ).strip()

        url = str(
            item.get("url", "")
        ).strip()

        content = str(
            item.get("content", "")
        ).strip()

        if not title or not url:
            continue

        commands = extract_command_candidates(
            content,
            search_query=query
        )

        source = detect_documentation_source(url)

        results.append(
        {
        "title": title,
        "url": url,
        "content": content,
        "commands": commands,
        "has_command": bool(commands),
        "source": source,
            }
        )

    return results


@app.route("/command-finder", methods=["GET", "POST"])
def command_finder():

    results = []
    error = None

    query = ""
    vendor = "all"

    if request.method == "POST":

        query = request.form.get(
            "query",
            ""
        ).strip()

        vendor = request.form.get(
            "vendor",
            "all"
        ).strip()

        try:

            results = search_network_commands(
                query=query,
                vendor=vendor,
            )

            if not results:
                error = (
                    "No relevant official documentation was found. "
                    "Try a different command or networking keyword."
                )

        except (ValueError, RuntimeError) as exc:

            error = str(exc)

        except Exception:

            app.logger.exception(
                "Network Command Finder search failed."
            )

            error = (
                "Unable to complete the documentation search. "
                "Please try again."
            )

    return render_template(
        "command_finder.html",
        results=results,
        error=error,
        query=query,
        selected_vendor=vendor,
        vendors=sorted(
            COMMAND_FINDER_VENDORS.keys()
        ),
    )

if __name__ == "__main__":
    # Development-only server. Render uses Gunicorn via the Procfile.
    app.run()
