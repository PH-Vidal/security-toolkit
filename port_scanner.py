import socket

def scan_ports(host, ports):
    print(f"\n🔍 Escaneando {host}...\n")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"  ✅ Porta {port} — ABERTA")
            else:
                print(f"  ❌ Porta {port} — fechada")
            sock.close()
        except socket.gaierror:
            print("Host não encontrado.")
            break

if __name__ == "__main__":
    host = input("Digite o host (ex: scanme.nmap.org): ")
    ports = [21, 22, 23, 80, 443, 3306, 8080]
    scan_ports(host, ports)