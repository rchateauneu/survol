#!/usr/bin/python

# Output example:
#> net share C$
#Share name        C$
#Path              C:\
#Remark            Default share
#Maximum users     No limit
#Users
#Caching           Manual caching of documents
#Permission        Everyone, FULL
#
#The command completed successfully.

import re
import sys
import subprocess

import rdflib
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv( "SMB informations returned by NET SHARE")
# Ex: "//LONW00052257.euro.net.intra/D$"
smbShr = cgiEnv.GetId()

if not lib_util.isPlatformWindows:
	lib_common.ErrorMessageHtml("NET command on Windows only")

# If called fron cgiserver.py, double slashes are collapsed into one.
shrMatch = re.match( "/?/([^/]+)/([^/]+)",smbShr)
if not shrMatch:
	lib_common.ErrorMessageHtml("Invalid share name:%s"%shrMatch)

#sys.stderr.write("smbShr=%s\n"%smbShr)
shrNam = shrMatch.group(2)

nodeSmbShr = lib_common.gUriGen.SmbShareUri( smbShr )

grph = rdflib.Graph()

net_share_cmd = [ "net", "share", shrNam ]

net_share_pipe = subprocess.Popen(net_share_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

( net_share_last_output, net_share_err ) = net_share_pipe.communicate()

# Converts to string for Python3.
asstr = net_share_last_output.decode("utf-8")
#print("Str="+asstr)
lines = asstr.split('\n')

shrPath = "UndefinedPath"
for lin in lines:
	if lin.startswith("Path"):
		shrPath = lin[18:]

#print("Path+"+shrPath)

mountNode = lib_common.gUriGen.FileUri( "//" + lib_util.currentHostname + "/" + shrPath )
grph.add( ( nodeSmbShr, pc.property_smbmount, mountNode ) )

cgiEnv.OutCgiRdf(grph)

