#!/usr/bin/env python
import multiprocessing
import subprocess
import getopt
import sys
import socket
import os
from netaddr import *
from netifaces import interfaces, ifaddresses, AF_INET
import pygtk
pygtk.require('2.0')
import gtk

class ArpScannerGui:
	def __init__(self):
		self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window.set_title("ARP scanner")
		self.window.connect("delete_event", lambda w,e: gtk.main_quit())
		self.window.set_position(gtk.WIN_POS_CENTER)
		self.window.set_geometry_hints(min_width=500, min_height=300)

		vbox = gtk.VBox(False, 0)
		self.window.add(vbox)

		hbox = gtk.HBox(False, 0)
		vbox.pack_start(hbox, False, False, 0)

		self.combobox = gtk.combo_box_new_text()
                for ifc in interfaces():
                        if ifaddresses(ifc).has_key(AF_INET) and not ifc == "lo":
				self.combobox.append_text(ifc)
			else:
                                continue
		self.combobox.set_active(0)
		hbox.pack_start(self.combobox, False, False, 0 )

		scan_button = gtk.Button("Scan")
		hbox.pack_start(scan_button, False, False, 0 )
		image = gtk.Image()
		image.set_from_stock(gtk.STOCK_REFRESH, gtk.ICON_SIZE_BUTTON)
		scan_button.set_image(image)
		image.show()
		scan_button.connect("clicked", self.scan_ifc)

		self.scrolledwindow = gtk.ScrolledWindow()
		self.scrolledwindow.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
		vbox.add(self.scrolledwindow)
		self.model = gtk.ListStore (str, str, str, str)
		COL_IP, COL_MAC, COL_VENDOR, COL_HOSTNAME = range(4)
		self.treeview = gtk.TreeView(self.model)

		cell = gtk.CellRendererText ()
		column = gtk.TreeViewColumn ("IP Address", cell, text = COL_IP)
		column.set_resizable (True)
		column.set_sort_column_id(COL_IP)
		self.treeview.append_column (column)
		column = gtk.TreeViewColumn ("MAC Address", cell, text = COL_MAC)
		column.set_resizable (True)
		column.set_sort_column_id(COL_MAC)
		self.treeview.append_column (column)
		column = gtk.TreeViewColumn ("MAC Vendor", cell, text = COL_VENDOR)
		column.set_resizable (True)
		column.set_sort_column_id(COL_VENDOR)
		self.treeview.append_column (column)
		column = gtk.TreeViewColumn ("Hostname", cell, text = COL_HOSTNAME)
		column.set_resizable (True)
		column.set_sort_column_id(COL_HOSTNAME)
		self.treeview.append_column (column)

		self.scrolledwindow.add(self.treeview)
		self.window.show_all()

	def scan_ifc(self, button):
		ifc = self.combobox.get_active_text()

		# Clear previous results
		self.model.clear()

		# TODO "Scanning" progress bar 

		results = scan_interface(ifc)
		for item in results:
			self.model.append(item)

		self.window.show_all()

	def main(self):
		gtk.main()

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

		# TODO - Handle also multiple entries
		return ip, str(mac), vendor, hostname

def scan_interface(ifcName):
	results = []
	for ipinfo in ifaddresses(ifcName)[AF_INET]:
		address = ipinfo['addr']
		netmask = ipinfo['netmask']

		ip = IPNetwork('%s/%s' % (address, netmask))

		pool = multiprocessing.Pool(len(ip))
		rval = pool.map_async(call_arping, get_ip_list(ip))
		results.extend(rval.get())
		pool.close()
	
	return filter(None,results)

def dump_results_stdout(ifc, results):
	sys.stdout.write("|------------------------------------------------- Interface %5s --------------------------------------------------|\n" %(ifc))
	sys.stdout.write("| %14s | %17s | %40s | %34s |\n" %("IP Address", "MAC Address", "MAC Vendor", "Hostname"))
	sys.stdout.write("|--------------------------------------------------------------------------------------------------------------------|\n")
	# Sort by IP Address
	for entry in sorted(results, key=lambda item: socket.inet_aton(item[0])):
		sys.stdout.write("| %14s | %17s | %40s | %34s |\n" %(entry[0], entry[1], entry[2], entry[3]))

	sys.stdout.write("|--------------------------------------------------------------------------------------------------------------------|\n")

def usage(msg):
	sys.stderr.write(str(msg))
	sys.stderr.write("\nUsage:\n\n"
			"  -t, --text                 Command line interface\n"
			"  -i, --interface=<ifc>      Specify an interface to scan\n"
			"  -h, --help                 Show usage\n")

def main(argv=None):
	# Default arguments
	ifc = None
	use_gui = True

	if argv is None:
		argv = sys.argv

	if not os.geteuid()==0:
		usage("Only root can run this script");
		return 1

	# Parse arguments
	try:
		opts, args = getopt.getopt(argv[1:], "hti:", ["help", "text", "interface="])
	except getopt.error, msg:
		usage(msg)
		return 2

	for opt, arg in opts:
		if opt in  ('-i', '--interface'):
			ifc = arg
			if (ifc not in interfaces()) or not ifaddresses(ifc).has_key(AF_INET):
				usage("ERROR: Interface %s not available or without IP address\n" %(ifc))
				return 3
		elif opt in ('-t', '--text'):
			use_gui = False

	if use_gui:
		gui = ArpScannerGui()
		gui.main()
		return 0

	if ifc:
		scan_interface(ifc)
		dump_results_stdout(ifc, scan_interface(ifc))
	else: 	# Scan every interface if none specified
		for ifc in interfaces():
			if ifaddresses(ifc).has_key(AF_INET) and not ifc == "lo":
				dump_results_stdout(ifc, scan_interface(ifc))
			else:
				continue

if __name__ == "__main__":
	main()
