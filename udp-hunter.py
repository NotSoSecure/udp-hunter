import sys
import socket
import os
import struct
import threading
import base64
import binascii
import netaddr
import select
import json
import argparse
import ifaddr

from colorama import Fore, Back, Style
from time import gmtime, strftime, sleep
from datetime import datetime
from netaddr import IPNetwork,IPAddress
from ctypes import *

localips = []

def getlocaladdress():
        adapters = ifaddr.get_adapters()
        i=1
        for adapter in adapters:
                localips.append((str(adapter.nice_name), str(adapter.ips[0].ip[0]),str(adapter.ips[1].ip)))
        for localip in localips:
                print(i,localip[0],": IPv6",localip[1],": IPv4",localip[2])
                i+=1

def gethostdata(name):
	try:
		print(socket.gethostbyname(name))
	except socket.gaierror as err:
	  	print("Cannot resolve hostname: ", name, err)
	sys.exit()

banner = "UDP Hunter v0.1beta - Updated on 26 February 2020"
hostipv4 = ""
hostipv6 = "::"
pack = []
port_list = []
probe_list = []
argerror = ""
target = []
failedtarget = []
filename = ""
helpdata=[]
output = []
output_tuple = []
outputfilestr = ""
outputfilename = ""
probemasterfile = "udp.txt"
probehelp = "udphelp.txt"
probehelplist = []
probemaster = []
noise = "False"
timeout = 1.0
probedisplaylist = []
probedisplaystr = ""

fd = open(probemasterfile,"r")
for line in fd:
	if line!="\n":
		temp = line.rstrip('\n')
		if temp[:1]!="#":
			tempp = [x.strip() for x in temp.split(',')]
			probedisplaylist.append(tempp[1])
probedisplaystr = ", ".join(probedisplaylist)

print(banner)
print("""
ooooo     ooo oooooooooo.   ooooooooo.        ooooo   ooooo                             .                      
`888'     `8' `888'   `Y8b  `888   `Y88.      `888'   `888'                           .o8                      
 888       8   888      888  888   .d88'       888     888  oooo  oooo  ooo. .oo.   .o888oo  .ooooo.  oooo d8b 
 888       8   888      888  888ooo88P'        888ooooo888  `888  `888  `888P"Y88b    888   d88' `88b `888""8P 
 888       8   888      888  888               888     888   888   888   888   888    888   888ooo888  888     
 `88.    .8'   888     d88'  888               888     888   888   888   888   888    888 . 888    .o  888     
   `YbodP'    o888bood8P'   o888o             o888o   o888o  `V88V"V8P' o888o o888o   "888" `Y8bod8P' d888b    
....................NotSoSecure (c) 2020 | Developed by Savan Gadhiya - www.gadhiyasavan.com...................
           
Usage: python udp.py --file=inputfile.txt --output=outputfile.txt [optional arguments] 
Usage: python udp.py --file=inputfile.txt --output=outputfile.txt [--probes=NTPRequest,SNMPv3GetReques] [--ports=123,161,53] [--retries=3] [--noise=true] [--verbose=false] [--timeout=1.0] [--configfile]
--host 		 - Single Host  - Required
--file 		 - File of ips  - Required
--output 	 - Output file - Required
--probes 	 - Name of probe or 'all' (default: all probes) (Optional)
""")
print("Probe list       - " + probedisplaystr)
print("""
--ports 	 - List of ports or 'all' (default: all ports) (Optional)
--retries 	 - Number of packets to send to each host.  Default 2 (Optional)
--noise 	 - To filter output from non-listed IPs  (Optional)
--verbose	 - verbosity,  will show sniffer output also --- please keep this a true, by default this is true. This will help us to analyze output.
--timeout 	 - Timeout 1.0, 2.0 in minutes (Optional)
--lhost6         - Provide IPv6 of listner interface
--lhost4         - Provide IPv4 of listner interface
--configfile     - Configuration file location - default is 'udp.txt' in same directory
--probehelp      - Help file location - default is 'udphelp.txt' in same directory
""")

parser = argparse.ArgumentParser(description='UDP Hunter',epilog='UDP Hunter')
parser.add_argument("--hosts",help="Provide host names by commas",dest='host',required=False)
parser.add_argument("--file",help="Provide file input",dest='filename',required=False)
parser.add_argument("--output",help="Provide output",dest='output',required=False,default='udphunter-output.txt')
parser.add_argument("--verbose",help="Ignore verbose output --verbose=false",dest='verbose',required=False)
parser.add_argument("--ports",help="Provide port(s)",dest='ports',required=False)
parser.add_argument("--probes",help="Provide probe(s)",dest='probes',required=False)
parser.add_argument("--retries",help="Provide retries",dest='retries',required=False,type=int,default=3)
parser.add_argument("--noise",help="Provide noise",dest='noise',required=False)
parser.add_argument("--timeout",help="Provide noise",dest='timeout',required=False,type=float,default=0.3)
parser.add_argument("--lhost4",help="Provide IPv4 of listner interface",dest='lhost4',required=False)
parser.add_argument("--lhost6",help="Provide IPv6 of listner interface",dest='lhost6',required=False)
parser.add_argument("--configfile",help="Provide port(s)",dest='configfile',required=False,default='udp.txt')
parser.add_argument("--probehelp",help="Provide port(s)",dest='probehelp',required=False,default='udphelp.txt')
args = parser.parse_args() #print(args.accumulate(args.integers))

if (args.lhost4 == None) or (args.lhost6 == None):
        if os.name == "posix":
                if args.lhost4 == None:
                        hostipv4 = ""
                else:
                        hostipv4 = args.lhost4
                if args.lhost6 == None:
                        hostipv6 = "::"
                else:
                        hostipv6 = args.lhost6
        else:
                print(getlocaladdress())
                inputval = input("Select a network adapter to set IPv4 and IPv6 listening hosts:\n")
                if args.lhost6 == None:
                        hostipv6 = localips[int(inputval)-1][1]
                else:
                        hostipv6 = args.lhost6
                if args.lhost4 == None:
                        hostipv4 = localips[int(inputval)-1][2]
                else:
                        hostipv4 = args.lhost4
else:
        hostipv4 = args.lhost4
        hostipv6 = args.lhost6

if hostipv4=="":
        print("Listening IPs were set to IPv6 - ",hostipv6," and IPv4 - Default",hostipv4)
else:
        print("Listening IPs were set to IPv6 - ",hostipv6," and IPv4 - ",hostipv4)
if args.configfile:
	probemasterfile = args.configfile
if args.probehelp:
	probehelp = args.probehelp

fhelp = open(probehelp,"r")
for line in fhelp:
	if line!="\n":
		temp = line.rstrip('\n')
		tempp = [x.strip() for x in temp.split(',')]
		flag='valid'
		for i in range(len(probehelplist)):
			if tempp[0]==probehelplist[i][0]:
				flag='invalid'
				probehelplist[i][1].append(tempp[1])
				break
		if flag=='valid':
			probehelplist.append([tempp[0],[tempp[1]]])

f = open(probemasterfile,"r")
for line in f:
	if line!="\n":
		temp = line.rstrip('\n')
		if temp[:1]!="#":
			tempp = [x.strip() for x in temp.split(',')]
			flag = 'valid'
			for i in range(len(probemaster)):
				if int(probemaster[i][0])==int(tempp[0]):
					probemaster[i][1].append((tempp[1],tempp[2]))
					flag = 'invalid'
					break
			if flag=='valid':
				probemaster.append((int(tempp[0]),[(tempp[1],tempp[2])]))

if args.host==args.filename:
	print('--host or --filename required')
	sys.exit()

if args.host:
	hosts = args.host
	target = hosts.split(",")
if args.filename:
	filename = args.filename
	f = open(filename,"r")
	for line in f:
                if line!="\n":
                        sline = line.rstrip('\n')
                if "/" in sline:
                        for ip in IPNetwork(sline):
                                target.append(str(ip))
                else:
                        target.append(sline)
if args.ports:
	ports = args.ports
	port_list = ports.split(",")
if args.probes:
	probe_list = args.probes
	probe_list = probe_list.split(",")
if args.output:
	outputfilename = args.output
if args.retries:
	retries = args.retries
if args.noise != None:
	noise = args.noise
if args.timeout != "True" and args.timeout != None:
	timeout = args.timeout

##### Create a pack/list which will include the probes and ports to be scanned with probe, servicename, port number etc.
if args.ports or args.probes:
	for i1 in range(len(probemaster)):
		for ports in port_list:
			if probemaster[i1][0]==int(ports):
				for i2 in range(len(probemaster[i1][1])):
					pack.append((probemaster[i1][0],probemaster[i1][1][i2][0],probemaster[i1][1][i2][1],binascii.unhexlify(probemaster[i1][1][i2][1])))
		#print probe_list,port_list
		for probes in probe_list:
			if 1==1:
				for i2 in range(len(probemaster[i1][1])):
					if probemaster[i1][1][i2][0]==probes:
						pack.append((probemaster[i1][0],probemaster[i1][1][i2][0],probemaster[i1][1][i2][1],binascii.unhexlify(probemaster[i1][1][i2][1])))
else:
	for i1 in range(len(probemaster)):
		for i2 in range(len(probemaster[i1][1])):
			pack.append((probemaster[i1][0],probemaster[i1][1][i2][0],probemaster[i1][1][i2][1],binascii.unhexlify(probemaster[i1][1][i2][1])))
##### END OF --- Create a pack/list which will include the probes and ports to be scanned with probe, servicename, port number etc.

print("\nStarting UDP Hunter at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()))
print("\nCommand with arguments  : " + " ".join(sys.argv))
print("-----------------------------------------------------------------------------")
if len(filename)>0:
	print("Input File for Ips      : " + filename)
if len(port_list)>0:
	print("Port List               : " + str(port_list))
elif len(probe_list)>0:
	print("Probe List              : " + str(probe_list))
else:
	print("Probe List              : ALL")
printips = (str(", ".join(target))[:75] + '..') if len(str(", ".join(target))) > 75 else str(", ".join(target))
print("Scanning report for IPs : " + printips)
probelist = ""

for probe in pack:
	probelist += probe[1]+", "
print("Sending probe(s)        : %s to %s IP(s)" % (probelist[:-2],str(len(target))))
print("-----------------------------------------------------------------------------")

target_v4=[]
target_v6=[]

for hostdata in target:
	if "." in hostdata:
		try:
			target_v4.append(socket.gethostbyname(hostdata))
		except socket.gaierror as err:
                        failedtarget.append(str(hostdata) + " : Could not resolve hostname: " + str(err))
	else:
		target_v6.append(hostdata)

target = target_v4

sock_add_family = socket.AF_INET
sock_ip_proto = socket.IPPROTO_IP

f = open(outputfilename, 'a+')
f.write("\n\n##### File was updated at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()) + " #####\n\n"+banner)
f.truncate()
f.close()

def udp_sender(target,pack):
	for ip in target:
		for probe in pack:
			try:
				sender = socket.socket(sock_add_family, socket.SOCK_DGRAM)
				sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				for retry in range(retries):
					sender.sendto(probe[3],(ip,probe[0]))   #sender.sendto(probe[2],(ip,port))
			except Exception as e:
                                failedtarget.append(str(ip) + " : Could not send probe: " + str(e))
                                pass

print("\nPlease note that output file " + outputfilestr + " will be appended ... \n")
def getsniffer(host):
	outputfilestr = ""
	sniffer = socket.socket(sock_add_family, socket.SOCK_RAW, socket.IPPROTO_UDP)
	sniffer.bind((host, 0))
	sniffer.setsockopt(sock_ip_proto, socket.IP_HDRINCL, 1)
	sniffer.settimeout(int(float(timeout)*60)) ### Set timeout - 60 seconds

	f = open(outputfilename, 'a+') #a+
	f.write("Scanning following IPs: \n\n" + str(target) + "\n\n")
	f.truncate()
	f.close()

	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) ## might be not necessary in this case

	t = threading.Thread(target=udp_sender,args=(target,pack))
	t.start()
	printflag = "false"

	try:
		while True:
			raw_buffer = sniffer.recvfrom(65565)
			snif = binascii.hexlify(raw_buffer[0])
			source_ip = raw_buffer[1][0]
			destination_ip = ""
			if "." in source_ip:
				port = str(int(snif[40:44],16)) ### FOR IPv4
			elif ":" in source_ip:
				port = str(int(snif[0:4],16)) ### FOR IPv6
			
			if snif!="" and printflag=="false":
				print("%-40s %-10s %-5s %s" % ("IP","PORT(UDP)","STAT","SERVICE"))
				printflag = "true"
			printservice = ""
			for i in range(len(probemaster)):
				if int(probemaster[i][0])==int(port):
					for ii in range(len(probemaster[i][1])):
						if printservice != "":					
							printservice += "/"
						printservice += probemaster[i][1][ii][0]
			if printservice == "":
				printservice = "Unknown Service"
			noisyport = "true"
			pack_port = []
			for i in range(len(pack)):
				pack_port.append(str(pack[i][0]))
			if '%' in str(source_ip):
				source_ip = str(source_ip)[0:str(source_ip).index('%')]
			if (((port in pack_port) and (str(source_ip) in target) and (noise in ["False","false"])) or (noise in ["True","true"])) and ((str(source_ip),port) not in output_tuple):
				if str(source_ip) != "::1":
					print("%-40s %-10s open  %s" % (str(source_ip),port,printservice))
				output.append([str(source_ip),port,printservice,snif])
				output_tuple.append((str(source_ip),port))
				if args.verbose not in ["false","False"]:
					outputfilestr = "Host: "+str(source_ip)+"; PORT: "+str(port)+";"+' STATE: open'+"; UDP Service:"+str(printservice)+"; "+str(snif)+" \n\n"
				else:
					outputfilestr = "Host: "+str(source_ip)+"; PORT: "+str(port)+";"+' STATE: open'+"; UDP Service:"+str(printservice)+" \n\n"
				if args.output:
					f = open(outputfilename, 'a+')
					f.write(outputfilestr)
					f.truncate()
					f.close()

	except socket.timeout:
                if float(timeout) >= 1.0:
                        print("\nINFO: Sniffer timeout was set to " + str(timeout) + " minutes")
                else:
                        print("\nINFO: Sniffer timeout was set to " + str(float(timeout)*60) + " seconds")

	except Exception as e:
		print("\nError occured: 20001, More information: :" + str(e))

	#handle CTRL-C
	except KeyboardInterrupt:
		#Windows turn off promiscuous mode
		if os.name == "nt":
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

	finally:
		for phdata in probehelplist:
			for odata in output:
				if odata[1]==phdata[0]:
					helpdata.append(str(odata[2])+"(port "+str(odata[1])+"):"+str(phdata[1]))
try:
	if len(target)==0:
		pass
	else:
		getsniffer(hostipv4)
except Exception as e:
	print("Error occured: 30001, More information: " + str(e))
finally:
	if len(target_v6)!=0:
		print("Starting testing of IPv6 IP address...")
		target = target_v6
		sock_add_family = socket.AF_INET6
		sock_ip_proto = socket.IPPROTO_IPV6
		getsniffer(hostipv6)
	f = open(outputfilename, 'a+')
	helpdata=list(dict.fromkeys(helpdata))
	if len(helpdata)!=0:
                f.write("\n\nFew known tools/script/commands/references for identified services.......\n" + "\n".join(helpdata))
	failedtarget=list(dict.fromkeys(failedtarget))
	if len(failedtarget)!=0:
                f.write("\n\nFailed Target(s): \n" + "\n".join(failedtarget))
	f.write("\n\n##### File updation ended at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()) + " ##### \n\n")
	f.truncate()
	f.close()
	if len(helpdata)!=0:
                print("\n\nFew known tools/script/commands/references for identified services.......\n" + "\n".join(helpdata))
	if len(failedtarget)!=0:
                print("\nFailed target list will be appended to the output file...")
	print("\nYour feedbacks are welcome...\n\nEnd of UDP Hunter at " + strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()))
