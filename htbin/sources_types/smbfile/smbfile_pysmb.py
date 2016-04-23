#!/usr/bin/python

import re
import os
import sys
import subprocess

import rdflib

import lib_common
import lib_smb
from lib_properties import pc

try:
	# https://bugzilla.samba.org/show_bug.cgi?id=11181
	# I installed pysmp but
	import pysmb as smb
except ImportError:
	try:
		import smb
	except ImportError:
		lib_common.ErrorMessageHtml("pysmb module not installed")

# import tempfile
from smb.SMBConnection import SMBConnection

def Main():
	cgiEnv = lib_common.CgiEnv()
	# Top directory, not just the share name.
	# smbFile= cgiEnv.GetId("//DUOLNX/IncomingCopied/")
	# xid=smbfile.Id=////londata002/westdev/westdocs/testdata
	smbFile= cgiEnv.GetId()

	nodeSmbShr,smbShr,smbDir = lib_smb.SmbBothUriSplit(smbFile)
	if nodeSmbShr is None:
		lib_common.ErrorMessageHtml("This is not a shared file:"+smbFile)




	# There will be some mechanism to capture userID, password, client_machine_name, server_name and server_ip
	# client_machine_name can be an arbitary ASCII string
	# server_name should match the remote machine name, or else the connection will be rejected
	conn = SMBConnection("xx", "yy", client_machine_name, server_name, use_ntlm_v2 = True)
	assert conn.connect(server_ip, 139)

	file_obj = tempfile.NamedTemporaryFile()
	file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', file_obj)

	# Retrieved file contents are inside file_obj
	# Do what you need with the file_obj and then close it
	# Note that the file obj is positioned at the end-of-file,
	# so you might need to perform a file_obj.seek() if you need
	# to read from the beginning
	file_obj.close()


	for x in z:
		shareNode = lib_common.gUriGen.SmbShareUri( "//" + smbServer + "/" + x )

		grph.add( ( nodeSmbShr, pc.property_smbshare, shareNode ) )


if __name__ == '__main__':
	Main()





