# dhcp_abuser

Intended use: occupy a DHCP range for testing purposes.

1) fakes the gateway address
2) intercepts packets in promiscuous mode destined for other subnets
3) crafts fake DHCPREQUEST

# IMPORTANT!!! 

Make sure you have the authorisation to run tests against the DHCP server. This app has elements of a Denial Of Service tool.
