import argparse
from scapy.all import *

def craft_dhcp_discover(giaddr=None):
    # Define the DHCP Discover packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=RandMAC(), xid=RandInt(), flags=0x8000) / \
                    DHCP(options=[("message-type", "discover"),
                                 ("param_req_list", [1, 3, 6, 15, 26, 28, 51, 58, 59]),
                                 ("end")])

    # Modify the packet to include the giaddr if provided
    if giaddr:
        dhcp_discover[BOOTP].giaddr = giaddr

    return dhcp_discover

def main():
    parser = argparse.ArgumentParser(
        description="Craft and send DHCP Discover packets with optional giaddr.",
        epilog="Example usage: python dhcpdiscover.py --giaddr 192.168.1.1 --num 5"
    )
    parser.add_argument('--giaddr', type=str, help='Gateway IP Address (giaddr) for the DHCP Discover packet')
    parser.add_argument('--num', type=int, default=1, help='Number of DHCP Discover packets to send (default: 1)')

    args = parser.parse_args()

    # Loop to send the specified number of DHCP Discover packets
    for _ in range(args.num):
        packet = craft_dhcp_discover(args.giaddr)
        sendp(packet)
        print(f"Sent DHCP Discover packet with giaddr={args.giaddr}")

if __name__ == "__main__":
    main()
