#!/usr/bin/python

"""
Installed Windows applications.
"""

import sys
import socket
import rdflib
import psutil
import lib_common
import lib_util
from lib_properties import pc
import wmi
from sources_types import Win32_Product

# Necessary otherwise it is displayed on Linux machines,
# as it does not import any Windows-specific module.
Usable = lib_util.UsableWindows

# Meme chose que enumerate.user.py mais ca permettra plus facilement de s'affranchir de psutil.

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# http://stackoverflow.com/questions/2077902/proper-reliable-way-to-get-all-installed-windows-programs-in-python

	# TODO: Add the host address to the connection.
	# TODO: Cache for the connection ?
	# wmiCnnct = wmi.WMI(cimomSrv)
	wmiCnnct = wmi.WMI()

	# TODO: This works but is very slow (About 30 seconds).
	for winProd in wmiCnnct.Win32_Product():
		# instance of Win32_Product
		# {
		#         AssignmentType = 1;
		#         Caption = "Microsoft Web Deploy 3.5";
		#         Description = "Microsoft Web Deploy 3.5";
		#         IdentifyingNumber = "{69A998C5-00A9-42CA-AB4E-C31CFFCD9251}";
		#         InstallDate = "20150709";
		#         InstallSource = "C:\\ProgramData\\Package Cache\\{69A998C5-00A9-42CA-AB4E-C31CFFCD9251}v3.1237.1763\\packages\\WebDeploy\\";
		#
		#         InstallState = 5;
		#         Language = "1033";
		#         LocalPackage = "C:\\windows\\Installer\\8a43794.msi";
		#         Name = "Microsoft Web Deploy 3.5";
		#         PackageCache = "C:\\windows\\Installer\\8a43794.msi";
		#         PackageCode = "{28DAC33F-DD0E-4293-9BB0-5585B4D89CB9}";
		#         PackageName = "WebDeploy_x64.msi";
		#         Vendor = "Microsoft Corporation";
		#         Version = "3.1237.1763";
		#         WordCount = 2;
		# };

		try:
			productNode = Win32_Product.MakeUri( winProd.Caption )
			grph.add( (productNode, pc.property_information, rdflib.Literal(winProd.Description) ) )
			grph.add( (productNode, lib_common.MakeProp("IdentifyingNumber"), rdflib.Literal(winProd.IdentifyingNumber) ) )

			grph.add( ( lib_common.nodeMachine, lib_common.MakeProp("Win32_Product"), productNode ) )

		except:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Caught:%s"%str(exc))
			# grph.add( ( node, pc.property_information, rdflib.Literal(str(exc)) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()














