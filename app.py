from flask import Flask, render_template, request
import ipaddress
import socket

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

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

@app.route("/ip-calculator", methods=["GET", "POST"])
def ip_calculator():
    result = None
    error = None

    if request.method == "POST":
        ip_input = request.form.get("ip_address", "").strip()

        try:
            network = ipaddress.ip_network(ip_input, strict=False)

            result = {
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "netmask": str(network.netmask),
                "hostmask": str(network.hostmask),
                "first_host": str(next(network.hosts(), "N/A")),
                "last_host": str(
                    list(network.hosts())[-1] if network.num_addresses > 2 else "N/A"
                ),
                "total_addresses": network.num_addresses,
                "usable_hosts": max(network.num_addresses - 2, 0),
                "prefix": network.prefixlen
            }

        except ValueError:
            error = "Invalid IP address or CIDR format. Example: 192.168.10.0/24"

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
            network = ipaddress.ip_network(network_input, strict=False)
            count = int(required_subnets)

            if count < 1:
                raise ValueError("Number of subnets must be at least 1.")

            if count > 1024:
                raise ValueError("Maximum 1024 subnets are allowed.")

            # Find the smallest subnet prefix that can create
            # at least the requested number of subnets.
            new_prefix = network.prefixlen

            while (2 ** (new_prefix - network.prefixlen)) < count:
                new_prefix += 1

            if new_prefix > network.max_prefixlen:
                raise ValueError(
                    "The requested number of subnets is too large."
                )

            subnet_list = list(
                network.subnets(new_prefix=new_prefix)
            )

            subnets = []

            for number, subnet in enumerate(
                subnet_list[:count], start=1
            ):
                hosts = list(subnet.hosts())

                if hosts:
                    first_host = str(hosts[0])
                    last_host = str(hosts[-1])
                    usable_hosts = len(hosts)
                else:
                    first_host = "N/A"
                    last_host = "N/A"
                    usable_hosts = 0

                subnets.append({
                    "number": number,
                    "network": str(subnet.network_address),
                    "broadcast": str(subnet.broadcast_address),
                    "netmask": str(subnet.netmask),
                    "prefix": subnet.prefixlen,
                    "first_host": first_host,
                    "last_host": last_host,
                    "usable_hosts": usable_hosts
                })

        except ValueError as exc:
            error = str(exc)

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
                "version": f"IPv{start.version}"
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
        hostname = request.form.get("hostname", "").strip()

        try:
            if not hostname:
                raise ValueError("Please enter a hostname.")

            hostname = hostname.replace("https://", "")
            hostname = hostname.replace("http://", "")
            hostname = hostname.split("/")[0]

            host_info = socket.gethostbyname_ex(hostname)

            canonical_name = host_info[0]
            aliases = host_info[1]
            addresses = host_info[2]

            result = {
                "hostname": hostname,
                "canonical": canonical_name,
                "aliases": aliases,
                "addresses": addresses
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
            if not host:
                raise ValueError("Please enter a hostname or IP address.")

            port = int(port_input)

            if port < 1 or port > 65535:
                raise ValueError(
                    "Port must be between 1 and 65535."
                )

            # Resolve hostname first.
            ip_address = socket.gethostbyname(host)

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(3)

            connection_result = sock.connect_ex(
                (ip_address, port)
            )

            sock.close()

            if connection_result == 0:
                status = "OPEN"
            else:
                status = "CLOSED / UNREACHABLE"

            result = {
                "host": host,
                "ip": ip_address,
                "port": port,
                "status": status
            }

        except socket.gaierror:
            error = (
                "Unable to resolve the hostname. "
                "Check the hostname or IP address."
            )

        except ValueError as exc:
            error = str(exc)

        except socket.error:
            error = (
                "Unable to connect to the specified host."
            )

    return render_template(
        "port_checker.html",
        result=result,
        error=error
    )

if __name__ == "__main__":
    app.run(debug=True)
