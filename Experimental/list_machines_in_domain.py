# http://timgolden.me.uk/python/win32_how_do_i/list_machines_in_a_domain.html
#
# From a post to python-win32 by D.W.Harks
# http://mail.python.org/pipermail/python-win32/2003-July/001179.html
#
from __future__ import generators
import os, sys
import socket
import win32com.client
import win32net

def machines_in_domain (domain_name):
	adsi = win32com.client.Dispatch ("ADsNameSpaces")
	nt = adsi.GetObject ("","WinNT:")
	result = nt.OpenDSObject ("WinNT://%s" % domain_name, "", "", 0)
	result.Filter = ["computer"]
	for machine in result:
		yield machine.Name

# pywintypes.error: (2453, 'NetGetDCName', 'Could not find domain controller for this domain.')
def my_domain_name():
	domain_controller = win32net.NetGetDCName (None, None)
	domain_name = win32net.NetUserModalsGet (domain_controller, 2)['domain_name']
	return domain_name

def print_machines_in_domain(domain_name):
	print "Listing machines in", domain_name
	for machine in machines_in_domain (domain_name):
		print machine

# This works and returns "RCHATEAU-HP"
print_machines_in_domain("WORKGROUP")

dom = my_domain_name()
print_machines_in_domain(dom)