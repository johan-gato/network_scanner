import socket
import subprocess
import platform

def ping(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    return subprocess.call(command, stdout=subprocess.DEVNULL) == 0

def ping_sweep(subred):
    activos = []
    for i in range(1, 20):
        ip = f"{subred}.{i}"
        if ping(ip):
            print(f"[+] Host activo: {ip}")
            activos.append(ip)
    return activos

def scan_port(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((host, port))
        return True
    except:
        return False

def port_scan(host, ports):
    abiertos = []
    for port in ports:
        if scan_port(host, port):
            print(f"    - Puerto {port} abierto en {host}")
            abiertos.append(port)
    return abiertos

if __name__ == "__main__":
    red = "192.168.1"
    hosts = ping_sweep(red)
    for host in hosts:
        port_scan(host, [22, 80, 443])
