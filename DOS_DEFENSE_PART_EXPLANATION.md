# Code explanation for DOS attacking (SYN flooding)


This document explains the python defence code for SYN flooding

We assume that the host being attacked by SYN flooding does not 
have a firewall turned on.

Our defence method is to detect the number of packets per unit of 
time to determine whether the host is being attacked by SYN flooding. 
If a SYN flooding attack is detected, then activate the firewall.