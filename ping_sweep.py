import subprocess
import platform

def ping_sweep(network):
    print(f"\n🌐 Varrendo rede {network}.0/24...\n")
    alive = []

    for i in range(1, 255):
        ip = f"{network}.{i}"
        param = "-n" if platform.system().lower() == "windows" else "-c"

        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode == 0:
            print(f"  ✅ {ip} — ativo")
            alive.append(ip)

    print(f"\n📋 {len(alive)} host(s) encontrado(s).")

if __name__ == "__main__":
    network = input("Digite os 3 primeiros octetos da rede (ex: 192.168.1): ")
    ping_sweep(network)
