#!/usr/bin/python

"""
MySql servers
"""

# This lists SQL servers from the credentials list.
# It does not attempt to connect to a server,
# and therefore does not need the appropriated packages.
# TODO: Detect servers with nmap.

import os
import sys
import re

import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	credNames = lib_credentials.GetCredentialsNames( "MySql" )
	sys.stderr.write("Mysql servers\n")

    #"primhilltcsrvdb1.mysql.db": [
    #  "primhilltcsrvdb1",
    #  "xyz"
    #],

	for hostMySql in credNames:
		sys.stderr.write("WbemServersList urlMySql=%s\n"%(urlMySql))

		Creer un node pour le host.


	try:
		pass
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("tnsnam="+tnsnam+" err="+str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
