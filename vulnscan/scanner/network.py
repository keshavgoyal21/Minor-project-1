import socket
import ipaddress
from datetime import datetime
import re

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
TIMEOUT = 1


def parse_ports(port_arg):
    if port_arg == "common":
        return COMMON_PORTS
    return [int(p.strip()) for p in port_arg.split(",")]


def resolve_target(target):
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        try:
            return [str(ip) for ip in ipaddress.ip_network(target, strict=False)]
        except ValueError:
            return [socket.gethostbyname(target)]


def normalize_service(service, version, banner):
    if not service:
        return None

    service = service.lower()
    banner_lower = (banner or "").lower()

    vendor = None
    product = service

    if "apache" in banner_lower:
        vendor = "apache"
        product = "http_server"
    elif "nginx" in banner_lower:
        vendor = "nginx"
        product = "nginx"
    elif "openssh" in banner_lower:
        vendor = "openbsd"
        product = "openssh"

    cpe = None
    if vendor and version:
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    keyword = f"{vendor or ''} {product} {version or ''}".strip()

    return {
        "vendor": vendor,
        "product": product,
        "version": version,
        "cpe": cpe,
        "keyword": keyword
    }


def scan_port(ip, port):
    sock = socket.socket()
    sock.settimeout(TIMEOUT)
    result = sock.connect_ex((ip, port))

    banner = None
    service = None
    version = None

    if result == 0:
        try:
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore")
        except Exception:
            pass
        finally:
            sock.close()

        try:
            service = socket.getservbyport(port)
        except Exception:
            service = None

        if banner:
            match = re.search(r"([A-Za-z\-]+)[/ ]([0-9]+(\.[0-9]+)+)", banner)
            if match:
                service = match.group(1)
                version = match.group(2)

        return True, banner, service, version

    sock.close()
    return False, None, None, None


def scan_target(target, ports):
    ports = parse_ports(ports)
    ips = resolve_target(target)

    scan_data = {
        "target": target,
        "scan_time": datetime.utcnow().isoformat(),
        "hosts": []
    }

    for ip in ips:
        host = {"ip": ip, "open_ports": []}

        for port in ports:
            open_, banner, service, version = scan_port(ip, port)
            if open_:
                meta = normalize_service(service, version, banner)
                host["open_ports"].append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "banner": banner.strip() if banner else None,
                    "meta": meta
                })

        scan_data["hosts"].append(host)

    return scan_data
