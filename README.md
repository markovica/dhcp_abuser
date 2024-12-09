# dhcp_abuser

Intended use: occupy a DHCP range for testing purposes.

1) fakes the gateway address
2) intercepts packets in promiscuous mode destined for other subnets
3) crafts fake DHCPREQUEST

# Usage 

Step 1: Put network interface in promiscuous mode
`ip link set ens33 promisc on
`or
`ifconfig ens33 promisc
`

Step 2: Run the sniffer.py to intercept traffic and answer to DHCPOFFERs
`python sniffer.py --giaddr 10.10.15.1 --iface ens33
`

Step 3: Run discover.py to generate DHCPDISCOVER packages
`python3 dhcpdiscover.py --giaddr 10.10.15.1 --num 5
`You can rerun dhcpdiscover.py to ask for additional leases while sniffer is running, and it will take care the offer is accepted by the fake client. 

Step 4: When finished, exit promiscuous mode
`ip link set ens33 promisc off
`or
`ifconfig ens33 -promisc
`

# IMPORTANT!!! 

Make sure you have the authorisation to run tests against the DHCP server. 
