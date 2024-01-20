import scapy.all as scapy
import pyfiglet
import argparse
import sys

def Get_Elements():
    parser = argparse.ArgumentParser()
    parser.add_argument ("-i", "--interface", dest="interface", help="Choose interface to work with")
    options = parser.parse_args()
    if not options.interface in ["eth0", "wlan0"]:
        sys.exit("[!!] Please specify specefic interface or Use --help for more information.")
    return options


def get_Mac(ip):
    arp_Request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_Request_broadcast = broadcast / arp_Request
    answered_List = scapy.srp(arp_Request_broadcast, timeout=1, verbose=False)[0]
    return answered_List[0][1].hwsrc

def sniff (interface) :
    scapy.sniff (iface= interface ,store=False, prn = process_discover)


def process_discover (packet) :
    if packet.haslayer (scapy.ARP) and packet[scapy.ARP].op == 2 :
        first_mac = get_Mac (packet[scapy.ARP].psrc)
        sec_mac = packet[scapy.ARP].hwsrc
        if first_mac != sec_mac :
            print("[!!] Possibility of MITM Attack !!")


if __name__ == "__main__" :
    banner = pyfiglet.figlet_format("OntyFire")
    print(banner)
    print("-"*29+ "By MedAmyyne" + "-"*29)
    print("="*70)
    print("Listening Mode ...")
    option = Get_Elements()
    sniff(option.interface)
