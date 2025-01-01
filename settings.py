#!/usr/bin/env python3
import sqlite3, sys, requests, os
import subprocess

def main():
    if 2 <= len(sys.argv) <= 4:
        if sys.argv[1] == "--config-interface" or sys.argv[1] == "--config-interface" and sys.argv[2] or sys.argv[1] == "--config-interface" and sys.argv[2] and sys.argv[3]:
            if len(sys.argv) == 4:
                configure_interface(sys.argv[2], sys.argv[3])
            elif len(sys.argv) == 3:
                configure_interface(sys.argv[2])
            else:
                configure_interface()
        elif sys.argv[1] == "--config-peer" and sys.argv[2] or sys.argv[1] == "--config-peer" and sys.argv[2] and sys.argv[3]:
            if len(sys.argv) == 4:
                configure_peer(sys.argv[2], sys.argv[3])
            elif len(sys.argv) == 3:
                configure_peer(sys.argv[2])
        elif sys.argv[1] == "--get-qrcode" and sys.argv[2]:
            get_qrcode(sys.argv[2])
        elif sys.argv[1] == "--help":
            get_help()
        elif sys.argv[1] == "--install":
            wireguard_install()
        elif sys.argv[1] == "--enable" or sys.argv[1] == "--enable" and sys.argv[2]:
            if len(sys.argv) == 3:
                enable_wireguard(sys.argv[2])
            else:
                enable_wireguard()
        elif sys.argv[1] == "--disable" or sys.argv[1] == "--disable" and sys.argv[2]:
            if len(sys.argv) == 3:
                disable_wireguard(sys.argv[2])
            else:
                disable_wireguard()
        elif sys.argv[1] == "--start" or sys.argv[1] == "--start" and sys.argv[2]:
            if len(sys.argv) == 3:
                start_wireguard(sys.argv[2])
            else:
                start_wireguard()
        elif sys.argv[1] == "--stop" or sys.argv[1] == "--stop" and sys.argv[2]:
            if len(sys.argv) == 3:
                stop_wireguard(sys.argv[2])
            else:
                stop_wireguard()
        else:
            print("Invalid command")
            get_help()

def run_shell_command(command):
    try:
        results = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(results.stdout)
    except subprocess.CalledProcessError as e:
        print("An Error Occurred:", e)
        print("Error Code:", e.returncode)
        print("Error Output:", e.output)
        print("Error stderr:",e.stderr)
        sys.exit(1)

def check_install(package):
    try:
        result = subprocess.run(["apt-cache", "policy", package], check=True, capture_output=True, text=True)
        result = result.stdout.split("\n")
        result = result[1].strip().split(":")
        if result[1] == "(none)":
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print("An Error Occurred:", e)
        print("Error Code:", e.returncode)
        print("Error Output:", e.output)
        print("Error stderr:",e.stderr)
        sys.exit(1)

def wireguard_install():
    installed = check_install("wireguard")
    if not installed:
        print("Updating package manager...")
        run_shell_command("apt-get update")
        print("upgrading installed packages...")
        run_shell_command("apt-get upgrade")
        print("Installing Wireguard and supporting packages...")
        run_shell_command("apt-get install wireguard wireguard-tools iptables qrencode -y")
        print("Creating database...")
        conn = sqlite3.connect('/etc/wireguard/wireguard.db')
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS interfaces(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, ip TEXT, privatekey TEXT, publickey TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS peers(id INTEGER PRIMARY KEY AUTOINCREMENT, interface_id INTEGER, name TEXT, ip TEXT, publickey TEXT, privatekey TEXT)")
        conn.commit()
        conn.close()
        sysctl_update()
        print("Wireguard installed successfully!")
        print("Open Port 51820 on your router for wireguard server")
        print("To see commands type: wireguard --help")

    else:
        print("Wireguard is already installed")
        sys.exit(0)

def configure_peer( peer_name, config="wg0"):

    peers = []
    ip = []
    conn = sqlite3.connect('/etc/wireguard/wireguard.db')
    c = conn.cursor()
    interface = c.execute("SELECT * FROM interfaces WHERE name=?", (config,))
    wireguard_interface = interface.fetchone()
    if wireguard_interface is None:
        print("Interface not found")
        sys.exit(0)
    else:
        ip.append(wireguard_interface[2])
        server_publickey = wireguard_interface[4]
        print(wireguard_interface)

    peers_list = c.execute("SELECT * FROM peers WHERE interface_id=?", (wireguard_interface[0],))
    peers_data = peers_list.fetchall()
    print(peers_data)
    for peer in peers_data:
        peers.append(peer[2])
        ip.append(peer[3])

    if peer_name in peers:
        print("Peer already configured")
        sys.exit(0)

    print("\nCreating Peer Private key and Public key...")
    run_shell_command(f"wg genkey | tee /etc/wireguard/{peer_name}-privatekey | wg pubkey > /etc/wireguard/{peer_name}-publickey")

    with open(f"/etc/wireguard/{peer_name}-publickey", "r") as f:
        public_key = f.read().strip()
        print(f"Public key: {public_key}")

    with open(f"/etc/wireguard/{peer_name}-privatekey", "r") as f:
        private_key = f.read().strip()
        print(f"Private key: {private_key}")



    ip.sort()
    split_ip = ip[-1].split(".")
    split_ip[3] = str(int(split_ip[3])+1)
    new_ip = ".".join(split_ip)
    public_ip = requests.get("https://api.ipify.org").text
    with open(f"/etc/wireguard/{config}.conf", "a") as f:
        f.write(f"\n\n[Peer]\n#{peer_name}\nPublicKey = {public_key}\nAllowedIPs = {new_ip}/32\n")

    with open(f"/etc/wireguard/{peer_name}.conf", "w") as f:
        f.write(f"[Interface]\nAddress = {new_ip}/24\nListenPort = 51820\nDNS = 8.8.8.8\nPrivateKey = {private_key}\n\n")
        f.write(f"[Peer]\nPublicKey = {server_publickey}\nEndpoint = {public_ip}:51820\nAllowedIPs = 0.0.0.0/0")

    c.execute("INSERT INTO peers(interface_id, name, ip, publickey, privatekey) VALUES (?,?,?,?,?)", (wireguard_interface[0], peer_name, new_ip, public_key, private_key))
    conn.commit()
    conn.close()

    run_shell_command(f"rm /etc/wireguard/{peer_name}-privatekey /etc/wireguard/{peer_name}-publickey")

    print("\nPeer configured successfully!")

    print(new_ip)

def configure_interface( config="wg0", network_ip="10.30.1.1"):
    conn = sqlite3.connect('/etc/wireguard/wireguard.db')
    c = conn.cursor()
    interface = c.execute("SELECT * FROM interfaces")
    wireguard_interfaces = interface.fetchall()
    for interface in wireguard_interfaces:
        if interface[1] == config:
            print("Interface already configured")
            sys.exit(0)

    for interface in wireguard_interfaces:
        if interface[2] == network_ip:
            print("Network IP already inuse")
            sys.exit(0)

    adapters = os.listdir("/sys/class/net/")

    for adapter in range(len(adapters)):
        print(adapter, adapters[adapter])

    while True:
        selected_adapter = input("Select adapter: ")

        if not selected_adapter.isdigit():
            print("Invalid adapter")
            print("enter a valid adapter number")
            continue

        if int(selected_adapter) not in range(len(adapters)):
            print("Invalid adapter")
        else:
            break

    run_shell_command("wg genkey | tee /etc/wireguard/server-privatekey | wg pubkey > /etc/wireguard/server-publickey")

    with open("/etc/wireguard/server-publickey", "r") as f:
        public_key = f.read().strip()
        print(f"Public key: {public_key}")

    with open("/etc/wireguard/server-privatekey", "r") as f:
        private_key = f.read().strip()
        print(f"Private key: {private_key}")

    print("Setting up interface...")
    with open(f"/etc/wireguard/{config}.conf", "w") as f:
        f.write(f"[Interface]\n\n#Local IP address for {config} interface\nAddress = {network_ip}/24")
        f.write(f"\nListenPort = 51820\nMTU = 1500\n\n#Private key\nPrivateKey = {private_key}\n")
        f.write(f"\nPostUp = iptables -A FORWARD -i {config} -o {adapters[int(selected_adapter)]} -j ACCEPT\n")
        f.write(f"PostUp = iptables -t nat -A POSTROUTING -o {adapters[int(selected_adapter)]} -j MASQUERADE\n")
        f.write(f"PostDown = iptables -A FORWARD -i {config} -o {adapters[int(selected_adapter)]} -j ACCEPT\n")
        f.write(f"PostDown = iptables -t nat -A POSTROUTING -o {adapters[int(selected_adapter)]} -j MASQUERADE\n")

    c.execute("INSERT INTO interfaces(name, ip, privatekey, publickey) values (?,?,?,?)", (config, network_ip, private_key, public_key))
    conn.commit()
    conn.close()
    run_shell_command("rm /etc/wireguard/server-privatekey /etc/wireguard/server-publickey")
    run_shell_command(f"chmod 600 /etc/wireguard/{config}.conf")
    print(f"\nInterface {config} configured successfully!")

def get_qrcode(peer_name):
    conn = sqlite3.connect('/etc/wireguard/wireguard.db')
    c = conn.cursor()
    peers = c.execute("SELECT name FROM peers WHERE name=?", (peer_name,))
    peer = peers.fetchone()
    if peer is None:
        print("Peer not found")
        sys.exit(0)
    else:
        print(peer)
        try:
            qr_code = subprocess.run(["qrencode", "-t", "ansiutf8", "-r", f"/etc/wireguard/{peer_name}.conf"], text=True, capture_output=True)
            print(qr_code.stdout)
        except subprocess.CalledProcessError as e:
            print("An Error Occured:", e)
            print("Error Code:", e.returncode)
            print("Error Output:", e.output)
            print("Error stderr:",e.stderr)
            sys.exit(1)

        sys.exit(0)

def get_help():
    print("Usage: wireguard [options] [arguments]")
    print("Options:")
    print("  --config-interface [interface name] [network ip]")
    print("  --config-peer [peer name] [interface name]")
    print("  --disable [interface name]")
    print("  --enable [interface name]")
    print("  --help [interface name]")
    print("  --install")
    print("  --get-qrcode [peer name]")
    print("  --stop [interface name]")
    print("  --start [interface name]")


def enable_wireguard(config="wg0"):
    run_shell_command("systemctl enable wg-quick@" + config)
    print(
        f"Wireguard server {config} enabled successfully!"
    )
def disable_wireguard(config="wg0"):
    run_shell_command("systemctl disable wg-quick@" + config)
    print(
        f"Wireguard server {config} disabled successfully!"
    )
def start_wireguard(config="wg0"):
    run_shell_command("systemctl start wg-quick@" + config)
    print(
        f"Wireguard server {config} started successfully!"
    )
    print("Be sure to forward port 51820 to your router for Wireguard Server")
def stop_wireguard(config="wg0"):
    run_shell_command("systemctl stop wg-quick@" + config)
    print(
        f"Wireguard server {config} stopped successfully!"
    )

def sysctl_update():
    try:
        with open("/etc/sysctl.conf", "r") as f:
           lines = f.readlines()
        new_lines = []
        for line in lines:
            if "#net.ipv4.ip_forward" in line:
                new_lines.append("net.ipv4.ip_forward=1\n")
            else:
                continue
            new_lines.append(line)

        with open("/etc/sysctl.conf", "w") as f:
            for line in new_lines:
                f.write(line)

        run_shell_command("sysctl -p")
        forward_ip = run_shell_command("cat /proc/sys/net/ipv4/ip_forward")

    except Exception as e:
        print("Error occurred while updating sysctl.conf file:", e)



if __name__ == "__main__":
    main()
