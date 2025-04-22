import argparse
import socket
import subprocess
import platform
import threading

# --- Utilidades ---

def ping(host, timeout=1):
    """Realiza un ping al host, devuelve True si responde."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    cmd = ['ping', param, '1', '-W', str(timeout), host]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL)
    return result.returncode == 0

def ping_sweep(network_prefix, start=1, end=254, timeout=1):
    """Escanea los hosts activos en una subred."""
    active_hosts = []

    def check_host(i):
        ip = f"{network_prefix}.{i}"
        if ping(ip, timeout):
            active_hosts.append(ip)

    threads = [threading.Thread(target=check_host, args=(i,)) for i in range(start, end+1)]
    for t in threads: t.start()
    for t in threads: t.join()
    return active_hosts

def scan_port(host, port, timeout=1):
    """Verifica si un puerto está abierto."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def port_scan(host, ports, timeout=1):
    """Escanea múltiples puertos en un host."""
    open_ports = []
    for port in ports:
        if scan_port(host, port, timeout):
            open_ports.append(port)
    return open_ports

def banner_grab(host, port, timeout=2):
    """Intenta obtener el banner del servicio en el puerto."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return s.recv(1024).decode(errors="ignore").strip()
    except:
        return None

# --- CLI Principal ---

def main():
    parser = argparse.ArgumentParser(description="Escáner de red básico.")
    parser.add_argument("-n", "--network", help="Subred (ej. 192.168.1)", type=str)
    parser.add_argument("-t", "--target", help="Host objetivo para escanear puertos", type=str)
    parser.add_argument("-p", "--ports", help="Puertos a escanear (ej. 22,80,443)", type=str)
    parser.add_argument("-b", "--banners", help="Intentar capturar banners", action="store_true")
    
    args = parser.parse_args()

    if args.network:
        print(f"\n[+] Escaneando red {args.network}.0/24...")
        hosts = ping_sweep(args.network)
        for h in hosts:
            print(f" - Activo: {h}")

    if args.target and args.ports:
        ports = list(map(int, args.ports.split(',')))
        print(f"\n[+] Escaneando puertos en {args.target}...")
        open_ports = port_scan(args.target, ports)
        for port in open_ports:
            print(f" - Puerto abierto: {port}")
            if args.banners:
                banner = banner_grab(args.target, port)
                if banner:
                    print(f"   ↳ Banner: {banner}")

if __name__ == "__main__":
    main()
