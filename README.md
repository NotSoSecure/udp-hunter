# What is UDP Hunter?
UDP Scanning has always been a slow and painful exercise, and if you add IPv6 on top of UDP, the tool choices get pretty limited. UDP Hunter is a python based open source network assessment tool focused on UDP Service Scanning. With UDP Hunter, we have focused on providing auditing of widely known UDP protocols for IPv6 and IPv4 hosts. As of today, UDP Hunter supports 19 different service probes. The tool allows you to do bulk scanning of large networks as well as targeted host scanning for specific ports and more. Once an open service is discovered, UDP Hunter takes it one step further and even provides you guidance on how you can possibly exploit the discovered services. UDP Hunter provides reports in a neat text format, however, support for more formats is under way.

# How does UDP Hunter work?
UDP Hunter creates a list of IPs when any IP range is provided to it.  It also supports domain names which will be resolved and the IP will be added to the list. Once the list has been created internally by UDP Hunter, it will send UDP probes to all listed IPs. If the host is running a UDP service, it will respond. UDP Hunter basically sniffs network particularly for UDP traffic, then reads all UDP packets coming to the target host. All UDP probes received after running UDP Hunter will be reported. However, there is an option (by setting --noise=false) to ignore irrelevant UDP packets and only observe the UDP traffic of interest originated from the hosts and services/ports which are mentioned in the target list. The idea behind creating UDP Hunter was initially inspired by udp-proto-scanner. I heartily thank Portcullis Labs for it and also Anant and Sumit Siddharth(Sid) for their valuable inputs while working on UDP Hunter.

# Supported UDP Probes:
As of today, we support the following UDP service probes on their default ports:
* ike - 500 port
* rpc / RPCCheck - 111 port
* ntp / NTPRequest - 123 port 
* snmp-public / SNMPv3GetRequest - 161 port
* ms-sql / ms-sql-slam - 1434 port
* netop - 6502 port
* tftp - 69 port
* db2 - 523 port 
* citrix - 1604 port 
* echo - 7 port 
* chargen - 19 port 
* systat -  11 port 
* daytime / time - 13 port 
* DNSStatusRequest / DNSVersionBindReq - 53 port 
* NBTStat - 137 port 
* xdmcp - 177 port
* net-support - 5405 port 
* mdns-zeroconf - 5353 port 
* gtpv1 - 2123 port  

# Setup:
#### Download the tool from [here](https://github.com/NotSoSecure/udp-hunter) or Clone the repository:
git clone https://github.com/NotSoSecure/udp-hunter

#### Requirements:
* Python 3.x
* Python Modules - also mentioned in “requirements.txt” file
  * netaddr
  * colorama
  * argparse
  * ifaddr
  * datetime

#### This should help you with the initial setup:
Install all required modules:
pip3 install -r requirements.txt 

#### Configuration files required: 
* udp.txt             - This file contains UDP probes
* udphelp.txt      - This file contains list of tools, suggestions for each UDP probes or services

##### You can also change configuration files by using command line argument:

“--configfile ” and “--probehelp ”

##### Verify the configurations by running following command:

python udp-hunter.py

Note: It should display following help details, if this throws any error check your configurations or connect with me for any tool specific errors.

#### Features / Options:

##### UDP Hunter v0.1beta has the following features:

###### Mandatory Options:
* --host            - Single Host  - Required
or 
* --file           - File of ips  - Required

###### Optional:
* --output         - Output file - Required
* --probes         - Name of probe or 'all' (default: all probes) (Optional)
  * Probe list       - ike, rpc, ntp, snmp-public, ms-sql, ms-sql-slam, netop, tftp, db2, citrix, echo, chargen, systat, daytime, time, RPCCheck, DNSStatusRequest, DNSVersionBindReq, NBTStat, NTPRequest, SNMPv3GetRequest, xdmcp, net-support, mdns-zeroconf, gtpv1
* --ports          - List of ports or 'all' (default: all ports) (Optional)
* --retries        - Number of packets to send to each host.  Default 2 (Optional)
* --noise          - To filter output from non-listed IPs  (Optional)
* --verbose        - verbosity,  will show sniffer output also --- please keep this a true, by default this is true. This will help us to analyze output.
* --timeout        - Timeout 1.0, 2.0 in minutes (Optional)
* --lhost6         - Provide IPv6 of listner interface
* --lhost4         - Provide IPv4 of listner interface
* --configfile     - Configuration file location - default is 'udp.txt' in same directory
* --probehelp      - Help file location - default is 'udphelp.txt' in same directory

###### Usage:

Usage: python udp-hunter.py --file=inputfile.txt --output=outputfile.txt [optional arguments]
Usage: python udp-hunter.py --file=inputfile.txt --output=outputfile.txt [--probes=NTPRequest,SNMPv3GetReques] [--ports=123,161,53] [--retries=3] [--noise=true] [--verbose=false] [--timeout=1.0] [--configfile]

# Credits:
The UDP probes are mainly taken from [amap](https://github.com/vanhauser-thc/THC-Archive/tree/master/Tools), [ike-scan](https://github.com/royhills/ike-scan), [nmap](https://nmap.org/book/scan-methods-udp-scan.html) and [udp-proto-scanner](https://github.com/portcullislabs/udp-proto-scanner). Inspiration for the scanning code was drawn from [udp-proto-scanner](https://github.com/portcullislabs/udp-proto-scanner).

# Future Work:
* Addition of more UDP probes
* Different reporting formats
* Update exploitation-related helps

# Read More:
* [UDP Hunter - An Open Source Network Assessment Tool](https://www.gadhiyasavan.com/2020/02/udp-hunter.html)
* [Setup Steps for UDP Hunter](https://asciinema.org/a/305052)
* [Sample Execution of UDP Hunter](https://asciinema.org/a/305053)

