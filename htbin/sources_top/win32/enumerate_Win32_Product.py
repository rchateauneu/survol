#!/usr/bin/python

"""
Installed Windows applications
"""

import sys
import socket
import rdflib
import psutil
import lib_common
import lib_util
from lib_properties import pc
from sources_types import Win32_Product

from collections import namedtuple
from ctypes import byref, create_unicode_buffer, windll
from ctypes.wintypes import DWORD
from itertools import count

# defined at http://msdn.microsoft.com/en-us/library/aa370101(v=VS.85).aspx
UID_BUFFER_SIZE = 39
ERROR_NO_MORE_ITEMS = 259

# Necessary otherwise it is displayed on Linux machines,
# as it does not import any Windows-specific module.
Usable = lib_util.UsableWindows

# Meme chose que enumerate.user.py mais ca permettra plus facilement de s'affranchir de psutil.

# http://stackoverflow.com/questions/2077902/proper-reliable-way-to-get-all-installed-windows-programs-in-python
# Not used yet, very slow.
def DoRemote(grph,cimomSrv):
	import wmi
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
		# {69A998C5-00A9-42CA-AB4E-C31CFFCD9251}
		# Product(Language=u'1033', ProductName=u'Microsoft Web Deploy 3.5', PackageCode=u'{28DAC33F-DD0E-4293-9BB0-5585B4D89CB9}', Transforms
		# =u'', AssignmentType=u'1', PackageName=u'WebDeploy_x64.msi', InstalledProductName=u'Microsoft Web Deploy 3.5', VersionString=u'3.123
		# 7.1763', RegCompany=u'', RegOwner=u'', ProductID=u'', ProductIcon=u'C:\\windows\\Installer\\{69A998C5-00A9-42CA-AB4E-C31CFFCD9251}\\
		# MSDeployIcon.exe', InstallLocation=u'', InstallSource=u'C:\\ProgramData\\Package Cache\\{69A998C5-00A9-42CA-AB4E-C31CFFCD9251}v3.123
		# 7.1763\\packages\\WebDeploy\\', InstallDate=u'20150709', Publisher=u'Microsoft Corporation', LocalPackage=u'C:\\windows\\Installer\\
		# 8a43794.msi', HelpLink=u'', HelpTelephone=u'', URLInfoAbout=u'', URLUpdateInfo=u'')

		try:
			productNode = Win32_Product.MakeUri( winProd.Caption )
			grph.add( (productNode, pc.property_information, rdflib.Literal(winProd.Description) ) )
			grph.add( (productNode, lib_common.MakeProp("IdentifyingNumber"), rdflib.Literal(winProd.IdentifyingNumber) ) )

			grph.add( ( lib_common.nodeMachine, lib_common.MakeProp("Win32_Product"), productNode ) )

		except:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Caught:%s"%str(exc))
			# grph.add( ( node, pc.property_information, rdflib.Literal(str(exc)) ) )


def get_installed_products_uids():
    """Returns a list with all the different uid of the installed apps."""
    # enum will return an error code according to the result of the app
    products = []
    for i in count(0):
        uid_buffer = create_unicode_buffer(UID_BUFFER_SIZE)
        result = windll.msi.MsiEnumProductsW(i, uid_buffer)
        if result == ERROR_NO_MORE_ITEMS:
            # done interating over the collection
            break
        products.append(uid_buffer.value)
    return products


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	for puid in get_installed_products_uids():
		#sys.stderr.write("puid=%s\n"%puid)
		winProd = Win32_Product.populate_product(puid)
		# Must be encode("utf-8") before printing.
		# "winProd.InstalledProductName=Visual Studio 2012 Ú®ùÞ¡ë SDK - cht"
		#try:
		#	sys.stderr.write("winProd.InstalledProductName=%s\n"%winProd.InstalledProductName)
		#except:
		#	sys.stderr.write("winProd.InstalledProductName=%s\n"%winProd.InstalledProductName.encode("utf-8"))
		productNode = Win32_Product.MakeUri( puid )

		try:
			grph.add( (productNode, pc.property_information, rdflib.Literal(winProd.InstalledProductName) ) )
			grph.add( (productNode, lib_common.MakeProp("Version"), rdflib.Literal(winProd.VersionString) ) )
			grph.add( ( lib_common.nodeMachine, lib_common.MakeProp("Win32_Product"), productNode ) )

		except:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Caught:%s"%str(exc))


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()














