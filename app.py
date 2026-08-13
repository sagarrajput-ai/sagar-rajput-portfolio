from dotenv import load_dotenv
load_dotenv(override=True)

from flask import Flask, render_template, request, Response, url_for
import ipaddress
import socket
import os

from port_scanner import port_scanner_bp




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
        "resume",
        "projects",
        "network_toolkit_project",
        "network_toolkit",
        "ip_calculator",
        "subnet_planner",
        "ip_range",
        "dns_lookup",
        "port_checker",
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


@app.route("/resume")
def resume():
    return render_template("resume.html")


@app.route("/projects")
def projects():
    return render_template("projects.html")


@app.route("/projects/network-toolkit")
def network_toolkit_project():
    return render_template("network_toolkit_project.html")


@app.route("/network-toolkit", methods=["GET", "POST"])
def network_toolkit():
    return render_template("network_toolkit.html")


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


if __name__ == "__main__":
    # Development-only server. Render uses Gunicorn via the Procfile.
    app.run()
