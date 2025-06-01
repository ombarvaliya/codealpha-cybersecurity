import scapy.all as scapy
import psutil
from prettytable import PrettyTable
import subprocess
import re
import time
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether  # For Ethernet layer


def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface]).decode()
        match = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", output)
        return match.group(0) if match else None
    except subprocess.CalledProcessError:
        return None


def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface]).decode()
        match = re.search(r"inet (addr:)?(\d{1,3}(?:\.\d{1,3}){3})", output)
        return match.group(2) if match else None
    except subprocess.CalledProcessError:
        return None


def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
    for iface, _ in addrs.items():
        mac = get_current_mac(iface)
        ip = get_current_ip(iface)
        if ip and mac:
            t.add_row([iface, mac, ip])
        elif mac:
            t.add_row([iface, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([iface, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def packet_callback(packet):
    packet_details = f"{Fore.CYAN}=== Packet Captured ==={Style.RESET_ALL}\n"

    if Ether in packet:
        packet_details += f"{Fore.MAGENTA}Ethernet Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source MAC: {packet[Ether].src} -> Destination MAC: {packet[Ether].dst}\n"
        packet_details += f"Type: {packet[Ether].type}\n"

    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        packet_details += f"ID: {packet[IP].id} ; TTL: {packet[IP].ttl} ; Protocol: {packet[IP].proto}\n"
        packet_details += f"Flags: {packet[IP].flags} ; Checksum: {packet[IP].chksum}\n"

    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
        packet_details += f"Seq: {packet[TCP].seq} ; Ack: {packet[TCP].ack} ; Window: {packet[TCP].window}\n"
        packet_details += f"Checksum: {packet[TCP].chksum} ; Flags: {packet[TCP].flags}\n"

    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}\n"
        packet_details += f"Length: {packet[UDP].len}\n"

    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type} ; Code: {packet[ICMP].code} ; Checksum: {packet[ICMP].chksum}\n"

    print(packet_details)


def sniff(interface):
    print(f"{Fore.BLUE}[+] Sniffing on interface: {interface}...{Style.RESET_ALL}")
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print(f"{Fore.RED}[!] Permission Denied. Run the script as root (use sudo).{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error during sniffing: {e}{Style.RESET_ALL}")


def main():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer on Kali Linux{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Tip: You may want to run an ARP Spoofing attack in parallel for more detailed packets [***]{Style.RESET_ALL}\n")

    try:
        ip_table()
        interface = input(f"{Fore.CYAN}[*] Enter the interface name (e.g., eth0, wlan0): {Style.RESET_ALL}")
        
        ip = get_current_ip(interface)
        mac = get_current_mac(interface)

        if ip:
            print(f"{Fore.GREEN}[+] IP Address: {ip}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] No IP address found for {interface}.{Style.RESET_ALL}")

        if mac:
            print(f"{Fore.GREEN}[+] MAC Address: {mac}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] No MAC address found for {interface}.{Style.RESET_ALL}")

        sniff(interface)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Stopping the sniffer...{Style.RESET_ALL}")
        time.sleep(2)


if __name__ == "__main__":
    main()
