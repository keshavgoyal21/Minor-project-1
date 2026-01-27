import socket
import ipaddress
from datetime import datetime

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

def scan_port(ip, port):
    sock = socket.socket()
    sock.settimeout(TIMEOUT)
    result = sock.connect_ex((ip, port))
    service = None
    version = None
    banner = None
    if result == 0:
        try:
            # Try to get banner
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                # FTP
                pass  # FTP usually sends banner on connect
            elif port == 22:
                # SSH
                pass  # SSH usually sends banner on connect
            elif port == 25:
                # SMTP
                sock.send(b"EHLO example.com\r\n")
            # else: just try to receive
            banner = sock.recv(1024).decode(errors="ignore")
        except Exception:
            banner = None
        finally:
            sock.close()

        # Service name detection
        try:
            service = socket.getservbyport(port)
        except Exception:
            service = None

        # Version detection (very basic, from banner)
        if banner:
            import re
            # Try to extract version from banner
            version_match = re.search(r"([A-Za-z0-9\-]+)[/ ]([0-9]+(\.[0-9]+)+)", banner)
            if version_match:
                service = version_match.group(1)
                version = version_match.group(2)
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
                host["open_ports"].append({
                    "port": port,
                    "banner": banner.strip() if banner else None,
                    "service": service,
                    "version": version
                })
        scan_data["hosts"].append(host)

    return scan_data
