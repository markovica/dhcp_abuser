import argparse
from scapy.all import *

def send_dhcp_discover(giaddr, iface):
    # Construct DHCPDISCOVER packet
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr="12:34:56:78:9a:bc", giaddr=giaddr) / \
                    DHCP(options=[("message-type", "discover"), "end"])

    # Send the packet
    sendp(dhcp_discover, iface=iface)
    print("Sent DHCPDISCOVER with fake giaddr:", giaddr)

def send_dhcp_request(offer_packet, iface):
    # Extract information from the offer
    client_mac = offer_packet[BOOTP].chaddr
    offered_ip = offer_packet[BOOTP].yiaddr
    server_ip = offer_packet[IP].src
    xid = offer_packet[BOOTP].xid

    # Construct DHCPREQUEST packet
    dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(op=1, yiaddr=offered_ip, siaddr=server_ip, giaddr=offer_packet[BOOTP].giaddr, chaddr=client_mac, xid=xid) / \
                    DHCP(options=[("message-type", "request"),
                                  ("requested_addr", offered_ip),
                                  ("server_id", server_ip),
                                  ("end")])

    # Send the DHCPREQUEST packet
    sendp(dhcp_request, iface=iface)
    print(f"Sent DHCPREQUEST to {server_ip} with MAC {client_mac} and xid {hex(xid)}")

def handle_packet(packet, iface):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:  # DHCP Offer
        print("Received DHCPOFFER from server:", packet[IP].src)
        print(packet.summary())
        # Craft and send your custom response here
        send_dhcp_request(packet, iface)

def main():
    parser = argparse.ArgumentParser(
        description="DHCP Sniffer and Packet Sender",
        epilog="Example usage: python sniffer.py --giaddr 10.10.15.1 --iface ens33"
    )
    parser.add_argument('--giaddr', type=str, required=True, help='Fake Gateway IP Address (giaddr)')
    parser.add_argument('--iface', type=str, required=True, help='Network interface to use')

    args = parser.parse_args()

    # Send DHCPDISCOVER packet
    send_dhcp_discover(args.giaddr, args.iface)

    # Sniff for DHCP packets
    sniff(iface=args.iface, filter="udp and (port 67 or port 68)", prn=lambda packet: handle_packet(packet, args.iface), store=0)

if __name__ == "__main__":
    main()
