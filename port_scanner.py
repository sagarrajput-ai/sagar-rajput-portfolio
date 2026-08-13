from dotenv import load_dotenv
load_dotenv(override=True)

from flask import Blueprint, render_template, request, session, redirect, url_for, flash

import hashlib
import ipaddress
import os
import secrets
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


port_scanner_bp = Blueprint(
    "port_scanner",
    __name__,
    url_prefix="/port-scanner"
)


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE_PATH = os.path.join(
    "instance",
    "port_scanner.db"
)

PIN_USES = 5

PIN_LENGTH = 6

PIN_EXPIRY_HOURS = 24

MAX_PORTS_PER_SCAN = 4096

MAX_WORKERS = 100

SOCKET_TIMEOUT = 0.8


# ============================================================
# DATABASE
# ============================================================

def ensure_database():
    os.makedirs("instance", exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS access_pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pin_hash TEXT NOT NULL UNIQUE,
            uses_allowed INTEGER NOT NULL DEFAULT 5,
            uses_remaining INTEGER NOT NULL DEFAULT 5,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    connection.commit()
    connection.close()


# ============================================================
# PIN HELPERS
# ============================================================

def hash_pin(pin):
    return hashlib.sha256(
        pin.encode("utf-8")
    ).hexdigest()


def generate_pin():
    return "".join(
        secrets.choice("0123456789")
        for _ in range(PIN_LENGTH)
    )


def get_admin_key():
    return os.environ.get("PORT_SCANNER_ADMIN_KEY")


def verify_admin_key(key):
    admin_key = get_admin_key()

    if not admin_key:
        return False

    return secrets.compare_digest(
        key,
        admin_key
    )


# ============================================================
# ADMIN PIN GENERATION
# ============================================================

@port_scanner_bp.route("/admin", methods=["GET", "POST"])
def admin():

    if request.method == "POST":

        admin_key = request.form.get(
            "admin_key",
            ""
        ).strip()

        if not verify_admin_key(admin_key):
            flash(
                "Invalid administrator key.",
                "error"
            )

            return render_template(
                "port_scanner_admin.html"
            )

        pin = generate_pin()

        now = datetime.now(timezone.utc)

        expires = (
            now +
            timedelta(hours=PIN_EXPIRY_HOURS)
        )

        connection = sqlite3.connect(
            DATABASE_PATH
        )

        connection.execute(
            """
            INSERT INTO access_pins
            (
                pin_hash,
                uses_allowed,
                uses_remaining,
                created_at,
                expires_at,
                active
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                hash_pin(pin),
                PIN_USES,
                PIN_USES,
                now.isoformat(),
                expires.isoformat(),
                1
            )
        )

        connection.commit()
        connection.close()

        return render_template(
            "port_scanner_admin.html",
            generated_pin=pin,
            expires_at=expires.strftime(
                "%Y-%m-%d %H:%M UTC"
            )
        )

    return render_template(
        "port_scanner_admin.html"
    )


# ============================================================
# PIN AUTHENTICATION
# ============================================================

def require_port_scanner_access(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if session.get(
            "port_scanner_authenticated"
        ):
            return function(
                *args,
                **kwargs
            )

        return redirect(
            url_for(
                "port_scanner.login"
            )
        )

    return decorated_function


@port_scanner_bp.route(
    "/",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        pin = request.form.get(
            "pin",
            ""
        ).strip()

        if not pin.isdigit() or len(pin) != PIN_LENGTH:

            flash(
                "Please enter a valid 6-digit PIN.",
                "error"
            )

            return render_template(
                "port_scanner_login.html"
            )

        connection = sqlite3.connect(
            DATABASE_PATH
        )

        connection.row_factory = sqlite3.Row

        record = connection.execute(
            """
            SELECT *
            FROM access_pins
            WHERE pin_hash = ?
              AND active = 1
            """,
            (hash_pin(pin),)
        ).fetchone()

        if not record:

            connection.close()

            flash(
                "Invalid or inactive PIN.",
                "error"
            )

            return render_template(
                "port_scanner_login.html"
            )

        now = datetime.now(timezone.utc)

        try:
            expires_at = datetime.fromisoformat(
                record["expires_at"]
            )
        except ValueError:
            expires_at = now

        if now >= expires_at:

            connection.execute(
                """
                UPDATE access_pins
                SET active = 0
                WHERE id = ?
                """,
                (record["id"],)
            )

            connection.commit()
            connection.close()

            flash(
                "This PIN has expired.",
                "error"
            )

            return render_template(
                "port_scanner_login.html"
            )

        if record["uses_remaining"] <= 0:

            connection.close()

            flash(
                "This PIN has no scans remaining.",
                "error"
            )

            return render_template(
                "port_scanner_login.html"
            )

        session["port_scanner_authenticated"] = True

        session["port_scanner_pin_id"] = record["id"]

        connection.close()

        return redirect(
            url_for(
                "port_scanner.scanner"
            )
        )

    return render_template(
        "port_scanner_login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@port_scanner_bp.route("/logout")
def logout():

    session.pop(
        "port_scanner_authenticated",
        None
    )

    session.pop(
        "port_scanner_pin_id",
        None
    )

    return redirect(
        url_for(
            "port_scanner.login"
        )
    )


# ============================================================
# TARGET VALIDATION
# ============================================================

def resolve_target(target):

    target = target.strip()

    if not target:
        raise ValueError(
            "Please enter a hostname or IP address."
        )

    if len(target) > 253:
        raise ValueError(
            "Target name is too long."
        )

    # Remove URL prefixes.
    target = target.replace(
        "https://",
        ""
    )

    target = target.replace(
        "http://",
        ""
    )

    target = target.split("/")[0]

    # Remove accidental whitespace.
    target = target.strip()

    try:
        ip_obj = ipaddress.ip_address(target)

        if ip_obj.version != 4:
            raise ValueError(
                "Only IPv4 targets are supported."
            )

        return target

    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(
            target
        )

        return resolved_ip

    except socket.gaierror:

        raise ValueError(
            "Unable to resolve the hostname."
        )


# ============================================================
# PORT PARSER
# ============================================================

def parse_ports(start_port, end_port):

    try:
        start = int(start_port)
        end = int(end_port)
    except ValueError:

        raise ValueError(
            "Ports must be numeric."
        )

    if start < 1 or end > 65535:

        raise ValueError(
            "Ports must be between 1 and 65535."
        )

    if start > end:

        raise ValueError(
            "Start port cannot be greater than end port."
        )

    total = end - start + 1

    if total > MAX_PORTS_PER_SCAN:

        raise ValueError(
            f"Maximum {MAX_PORTS_PER_SCAN} ports "
            "can be scanned per request."
        )

    return list(
        range(
            start,
            end + 1
        )
    )


# ============================================================
# COMMON SERVICES
# ============================================================

COMMON_SERVICES = {

    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS SQL",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
}


# ============================================================
# SINGLE PORT SCAN
# ============================================================

def scan_port(ip_address, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(
        SOCKET_TIMEOUT
    )

    try:

        result = sock.connect_ex(
            (
                ip_address,
                port
            )
        )

        if result == 0:

            return {
                "port": port,
                "state": "OPEN",
                "service": COMMON_SERVICES.get(
                    port,
                    "Unknown"
                )
            }

        return None

    except socket.error:

        return None

    finally:

        sock.close()


# ============================================================
# SCAN PORT RANGE
# ============================================================

def perform_scan(
    ip_address,
    ports
):

    results = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                ip_address,
                port
            ): port
            for port in ports
        }

        for future in as_completed(
            futures
        ):

            try:

                result = future.result()

                if result:

                    results.append(
                        result
                    )

            except Exception:

                continue

    results.sort(
        key=lambda item: item["port"]
    )

    return results


# ============================================================
# MAIN SCANNER
# ============================================================

@port_scanner_bp.route(
    "/scan",
    methods=["GET", "POST"]
)
@require_port_scanner_access
def scanner():

    result = None
    error = None

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    pin_id = session.get(
        "port_scanner_pin_id"
    )

    pin_record = connection.execute(
        """
        SELECT *
        FROM access_pins
        WHERE id = ?
          AND active = 1
        """,
        (pin_id,)
    ).fetchone()

    connection.close()

    if not pin_record:

        session.clear()

        return redirect(
            url_for(
                "port_scanner.login"
            )
        )

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        start_port = request.form.get(
            "start_port",
            ""
        ).strip()

        end_port = request.form.get(
            "end_port",
            ""
        ).strip()

        authorization = request.form.get(
            "authorization"
        )

        if authorization != "yes":

            error = (
                "You must confirm that you are "
                "authorized to scan this target."
            )

        else:

            # Validate target.
            try:

                resolved_ip = resolve_target(
                    target
                )

            except ValueError as exc:

                error = str(exc)

            if not error:

                # Validate ports.
                try:

                    ports = parse_ports(
                        start_port,
                        end_port
                    )

                except ValueError as exc:

                    error = str(exc)

            if not error:

                # Atomically consume exactly one scan.
                connection = sqlite3.connect(
                    DATABASE_PATH
                )

                cursor = connection.cursor()

                cursor.execute(
                    """
                    UPDATE access_pins
                    SET uses_remaining =
                        uses_remaining - 1
                    WHERE id = ?
                      AND active = 1
                      AND uses_remaining > 0
                    """,
                    (pin_id,)
                )

                if cursor.rowcount != 1:

                    connection.rollback()
                    connection.close()

                    error = (
                        "No scan credits remain "
                        "for this PIN."
                    )

                else:

                    connection.commit()

                    remaining = connection.execute(
                        """
                        SELECT uses_remaining
                        FROM access_pins
                        WHERE id = ?
                        """,
                        (pin_id,)
                    ).fetchone()[0]

                    connection.close()

                    # Perform scan.
                    open_ports = perform_scan(
                        resolved_ip,
                        ports
                    )

                    result = {
                        "target": target,
                        "ip": resolved_ip,
                        "start_port": start_port,
                        "end_port": end_port,
                        "total_scanned": len(
                            ports
                        ),
                        "open_ports": open_ports,
                        "remaining": remaining,
                    }

    return render_template(
        "port_scanner.html",
        result=result,
        error=error,
        pin_record=pin_record
    )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

ensure_database()