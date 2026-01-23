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
    if result == 0:
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore")
        except Exception:
            banner = None
        sock.close()
        return True, banner
    sock.close()
    return False, None

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
            open_, banner = scan_port(ip, port)
            if open_:
                host["open_ports"].append({
                    "port": port,
                    "banner": banner.strip() if banner else None
                })
        scan_data["hosts"].append(host)

    return scan_data
