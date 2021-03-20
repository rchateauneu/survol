#!/usr/bin/env python

"""
Installed Windows applications
"""

import sys
import socket
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

# Similar to enumerate_user.py but uses less the module psutil.


# http://stackoverflow.com/questions/2077902/proper-reliable-way-to-get-all-installed-windows-programs-in-python
# Not used yet, very slow.
def DoRemote(grph, cimomSrv):
    import wmi
    # TODO: Add the host address to the connection.
    # TODO: Cache for the connection ?
    # wmi_cnnct = wmi.WMI(cimomSrv)
    wmi_cnnct = wmi.WMI()

    # TODO: This works but is very slow (About 30 seconds).
    for win_prod in wmi_cnnct.Win32_Product():
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
            product_node = Win32_Product.MakeUri(win_prod.Caption)
            grph.add((product_node, pc.property_information, lib_util.NodeLiteral(win_prod.Description)))
            grph.add((product_node, lib_common.MakeProp("IdentifyingNumber"), lib_util.NodeLiteral(win_prod.IdentifyingNumber)))
            Win32_Product.AddInstallSource(grph, product_node, win_prod)

            grph.add((lib_common.nodeMachine, lib_common.MakeProp("Win32_Product"), product_node))

        except Exception as exc:
            lib_common.ErrorMessageHtml("Caught:%s" % str(exc))


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
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    prop_win32_version = lib_common.MakeProp("Version")
    prop_win32_product = lib_common.MakeProp("Win32_Product")
    prop_win32_package = lib_common.MakeProp("Package Name")
    prop_identifying_number = lib_common.MakeProp("IdentifyingNumber")

    for puid in get_installed_products_uids():
        #sys.stderr.write("puid=%s\n"%puid)
        win_prod = Win32_Product.populate_product(puid)
        # Must be encode("utf-8") before printing.
        # "win_prod.InstalledProductName=Visual Studio 2012 CARACTERES BIZARRES SDK - cht"
        #try:
        #    sys.stderr.write("win_prod.InstalledProductName=%s\n"%win_prod.InstalledProductName)
        #except:
        #    sys.stderr.write("win_prod.InstalledProductName=%s\n"%win_prod.InstalledProductName.encode("utf-8"))

        # BEWARE: WE STRIP THE "{}" AROUND THE PUID
        ############  NOT ANYMORE puid = puid[1:-1]
        product_node = Win32_Product.MakeUri(puid)

        try:
            grph.add((product_node, pc.property_information, lib_util.NodeLiteral(win_prod.InstalledProductName)))
            grph.add((product_node, prop_win32_version, lib_util.NodeLiteral(win_prod.VersionString)))
            grph.add((product_node, prop_win32_package, lib_util.NodeLiteral(win_prod.PackageName)))
            grph.add((product_node, prop_identifying_number, lib_util.NodeLiteral(puid)))

            grph.add((lib_common.nodeMachine, prop_win32_product, product_node))

        except Exception as exc:
            lib_common.ErrorMessageHtml("Caught:%s" % str(exc))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prop_win32_product])


if __name__ == '__main__':
    Main()

