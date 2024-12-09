# dhcp_abuser

Intended use: occupy a DHCP range for testing purposes.

1) fakes the gateway address
2) intercepts packets in promiscuous mode destined for other subnets
3) crafts fake DHCPREQUEST

# Usage 

1. Put network interface in promiscuous mode
   
ip link set ens33 promisc on
or
ifconfig ens33 promisc

3. run the sniffer.py

4. rn discover.py to generate DHCPDISCOVER packages

python3 dhcpdiscover.py --giaddr 10.10.15.1 --num 5
You can rerun dhcpdiscover.py to ask for additional leases while sniffer is running, and it will take care the offer is accepted by the fake client. 

6. When finished, exit promiscuous mode

ip link set ens33 promisc off
or
ifconfig ens33 -promisc


# IMPORTANT!!! 

Make sure you have the authorisation to run tests against the DHCP server. 
