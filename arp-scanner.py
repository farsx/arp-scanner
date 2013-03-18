#!/usr/bin/env python
import multiprocessing
import subprocess
import sys
import socket
import os
from netaddr import *
from netifaces import interfaces, ifaddresses, AF_INET


def get_ip_list(ip_network):
	ip_list = []
	for ip in ip_network.iter_hosts():
		ip_list.append(str(ip))
	
	return ip_list

def call_arping(ip):
	try:
		arping_output = subprocess.check_output(["/usr/sbin/arping", "-r", "-c1", ip])
	except subprocess.CalledProcessError:
		return

	try:
		hostname = socket.gethostbyaddr(ip)[0]
	except socket.herror:
		hostname = ""

	for mac_string in arping_output.splitlines():
		mac = EUI(mac_string)
	
		try:
			vendor = mac.oui.registration().org

		except NotRegisteredError:
			vendor = ""

		return ip, str(mac), vendor, hostname

def scan_interface(ifcName):
	for ipinfo in ifaddresses(ifcName)[AF_INET]:
		address = ipinfo['addr']
		netmask = ipinfo['netmask']

		ip = IPNetwork('%s/%s' % (address, netmask))

		pool = multiprocessing.Pool(len(ip))
		rval = pool.map_async(call_arping, get_ip_list(ip))
		results = rval.get()
		pool.close()
		
		# Filter out bad entries 
		results = filter(None, results)
	
	return results

def dump_results_stdout(ifcName, results):
	sys.stdout.write("|------------------------------------------------- Interface %5s --------------------------------------------------|\n" %(ifcName))
	# Sort by IP Address
	for entry in sorted(results, key=lambda item: socket.inet_aton(item[0])):
		sys.stdout.write("| %14s | %17s | %40s | %34s |\n" %(entry[0], entry[1], entry[2], entry[3]))

	sys.stdout.write("|--------------------------------------------------------------------------------------------------------------------|\n")

if not os.geteuid()==0:
	sys.exit("Only root can run this script")


for ifcName in interfaces():
	if ifaddresses(ifcName).has_key(AF_INET) and not ifcName == "lo":
		dump_results_stdout(ifcName, scan_interface(ifcName))
	else:
		continue
