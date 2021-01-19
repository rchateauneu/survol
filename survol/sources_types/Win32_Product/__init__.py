"""
Windows software product
"""

import sys
import six
import logging
import lib_util
import lib_common
from lib_properties import pc

# http://ashishpython.blogspot.co.uk/2013/12/listing-all-installed-applications-on.html

# This scripts allows to get a list of all installed products in a windows
# machine. The code uses ctypes becuase there were a number of issues when
# trying to achieve the same win win32com.client
from collections import namedtuple
from ctypes import byref, create_unicode_buffer, windll
from ctypes.wintypes import DWORD

# defined at http://msdn.microsoft.com/en-us/library/aa370101(v=VS.85).aspx
PROPERTY_BUFFER_SIZE = 256
ERROR_MORE_DATA = 234
ERROR_SUCCESS = 0

# http://ashishpython.blogspot.co.uk/2013/12/listing-all-installed-applications-on.html
# {7818198F-3A26-442D-B34D-1664D3ABC979}
# Product(Language=u'1033', ProductName=u'Microsoft Visual Studio 2013 Diagnostic Tools - amd64', PackageCode=u'{1B281E27-9648-4A28-9F
# 58-E515354C096B}', Transforms=u'', AssignmentType=u'1', PackageName=u'PerfTools_CORE_amd64.msi', InstalledProductName=u'Microsoft Vi
# sual Studio 2013 Diagnostic Tools - amd64', VersionString=u'12.0.31101', RegCompany=u'', RegOwner=u'', ProductID=u'', ProductIcon=u'
# ', InstallLocation=u'', InstallSource=u'C:\\ProgramData\\Package Cache\\{7818198F-3A26-442D-B34D-1664D3ABC979}v12.0.31101\\packages\
# \PerfTools_CORE\\amd64\\', InstallDate=u'20150709', Publisher=u'Microsoft Corporation', LocalPackage=u'C:\\windows\\Installer\\8a439
# 70.msi', HelpLink=u'', HelpTelephone=u'', URLInfoAbout=u'', URLUpdateInfo=u'')
# {DE0E8FAF-9758-4BFD-A16E-009DB4B8C912}


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



# diff properties of a product, not all products have all properties
PRODUCT_PROPERTIES = ['Language',
                      'ProductName',
                      'PackageCode',
                      'Transforms',
                      'AssignmentType',
                      'PackageName',
                      'InstalledProductName',
                      'VersionString',
                      'RegCompany',
                      'RegOwner',
                      'ProductID',
                      'ProductIcon',
                      'InstallLocation',
                      'InstallSource',
                      'InstallDate',
                      'Publisher',
                      'LocalPackage',
                      'HelpLink',
                      'HelpTelephone',
                      'URLInfoAbout',
                      'URLUpdateInfo',]

# class to be used for python users :)
Product = namedtuple('Product', PRODUCT_PROPERTIES)


def _get_property_for_product(product, property, buf_size=PROPERTY_BUFFER_SIZE):
    property_buffer = create_unicode_buffer(buf_size)
    size = DWORD(buf_size)
    result = windll.msi.MsiGetProductInfoW(product, property, property_buffer, byref(size))
    if result == ERROR_MORE_DATA:
        return _get_property_for_product(product, property, 2 * buf_size)
    elif result == ERROR_SUCCESS:
        return property_buffer.value
    else:
        return str(result)


def populate_product(uid):
    # sys.stderr.write("populate_product uid=%s type=%s\n" % (uid,type(uid)))
    properties = []
    for the_property in PRODUCT_PROPERTIES:
        properties.append(_get_property_for_product(uid, the_property))
    return Product(*properties)


def EntityOntology():
    """A product is not identified by its caption because it would be too slow and not unique."""
    return (["IdentifyingNumber"],)


# TODO: Is the caption the best key ?
def MakeUri(productIdentifyingNumber):
    return lib_common.gUriGen.UriMake("Win32_Product",productIdentifyingNumber)


_prop_product_install_source = lib_common.MakeProp("InstallSource")


def AddInstallSource(grph, node, win_prod):
    """Windows file name, with backslashes replaced by convention in this software."""
    clean_install_source = win_prod.InstallSource

    clean_install_source += win_prod.PackageName

    node_install_source = lib_common.gUriGen.FileUri( clean_install_source )
    grph.add((node, _prop_product_install_source, node_install_source))


def AddInfo(grph, node, entity_ids_arr):
    product_identifying_number = six.u(entity_ids_arr[0])

    logging.debug("productIdentifyingNumber=%s",str(product_identifying_number))
    try:
        win_prod = populate_product(product_identifying_number)

        logging.debug("win_prod=%s",str(win_prod))

        AddInstallSource(grph,node,win_prod)

        node_local_package = lib_common.gUriGen.FileUri(win_prod.LocalPackage)
        grph.add((node, lib_common.MakeProp("LocalPackage"), node_local_package))

        if win_prod.RegCompany:
            grph.add((node, lib_common.MakeProp("Vendor"), lib_util.NodeLiteral(win_prod.RegCompany)))
        grph.add((node, lib_common.MakeProp("Version"), lib_util.NodeLiteral(win_prod.VersionString)))
        grph.add((node, lib_common.MakeProp("Name"), lib_util.NodeLiteral(win_prod.ProductName)))

        if win_prod.RegOwner:
            grph.add((node, lib_common.MakeProp("RegOwner"), lib_util.NodeLiteral(win_prod.RegOwner)))
        if win_prod.ProductID:
            grph.add((node, lib_common.MakeProp("ProductID"), lib_util.NodeLiteral(win_prod.ProductID)))

        if win_prod.ProductIcon:
            node_product_icon = lib_common.gUriGen.FileUri(win_prod.ProductIcon)
            grph.add((node, lib_common.MakeProp("ProductIcon"), node_product_icon))

        grph.add((node, lib_common.MakeProp("PackageName"), lib_util.NodeLiteral(win_prod.PackageName)))
        grph.add((node, lib_common.MakeProp("PackageCode"), lib_util.NodeLiteral(win_prod.PackageCode)))

        if win_prod.Transforms:
            grph.add((node, lib_common.MakeProp("Transforms"), lib_util.NodeLiteral(win_prod.Transforms)))
        grph.add((node, lib_common.MakeProp("AssignmentType"), lib_util.NodeLiteral(win_prod.AssignmentType)))

        if win_prod.InstallDate:
            txt_date = win_prod.InstallDate[0:4] + "-" + win_prod.InstallDate[4:6] + "-" + win_prod.InstallDate[6:8]
            grph.add((node, lib_common.MakeProp("InstallDate"), lib_util.NodeLiteral(txt_date)))

        grph.add((node, lib_common.MakeProp("Publisher"), lib_util.NodeLiteral(win_prod.Publisher)))

        if win_prod.HelpLink:
            grph.add((node, lib_common.MakeProp("HelpLink"), lib_common.NodeUrl(win_prod.HelpLink)))
        if win_prod.HelpTelephone:
            grph.add((node, lib_common.MakeProp("HelpTelephone"), lib_util.NodeLiteral(win_prod.HelpTelephone)))

        try:
            if win_prod.URLInfoAbout:
                # This is an URL so we make it clickable
                grph.add((node, lib_common.MakeProp("URLInfoAbout"), lib_common.NodeUrl(win_prod.URLInfoAbout)))
        except AttributeError:
            pass
        try:
            if win_prod.URLUpdateInfo:
                # This is an URL so we make it clickable
                grph.add((node, lib_common.MakeProp("URLUpdateInfo"), lib_common.NodeUrl(win_prod.URLUpdateInfo)))
        except AttributeError:
            pass

    except Exception as exc:
        grph.add((node, pc.property_information, lib_util.NodeLiteral(str(exc))))


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo_DEPRECATED(grph,node,entity_ids_arr):
    productCaption = entity_ids_arr[0]

    try:
        # http://ashishpython.blogspot.co.uk/2013/12/listing-all-installed-applications-on.html
        # {7818198F-3A26-442D-B34D-1664D3ABC979}
        # Product(Language=u'1033', ProductName=u'Microsoft Visual Studio 2013 Diagnostic Tools - amd64', PackageCode=u'{1B281E27-9648-4A28-9F
        # 58-E515354C096B}', Transforms=u'', AssignmentType=u'1', PackageName=u'PerfTools_CORE_amd64.msi', InstalledProductName=u'Microsoft Vi
        # sual Studio 2013 Diagnostic Tools - amd64', VersionString=u'12.0.31101', RegCompany=u'', RegOwner=u'', ProductID=u'', ProductIcon=u'
        # ', InstallLocation=u'', InstallSource=u'C:\\ProgramData\\Package Cache\\{7818198F-3A26-442D-B34D-1664D3ABC979}v12.0.31101\\packages\
        # \PerfTools_CORE\\amd64\\', InstallDate=u'20150709', Publisher=u'Microsoft Corporation', LocalPackage=u'C:\\windows\\Installer\\8a439
        # 70.msi', HelpLink=u'', HelpTelephone=u'', URLInfoAbout=u'', URLUpdateInfo=u'')
        # {DE0E8FAF-9758-4BFD-A16E-009DB4B8C912}


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

        # '\ninstance of Win32_Product\n{\n\tAssignmentType = 1;\n\tCaption = "Google Drive";\n\tDescription = "Google Drive";\n\tHelpLink = "
        # http://www.google.com";\n\tHelpTelephone = "http://www.google.com";\n\tIdentifyingNumber = "{709316AD-161C-4D5C-9AE7-0B3A822DA271}";
        # \n\tInstallDate = "20160601";\n\tInstallSource = "C:\\\\Program Files (x86)\\\\Google\\\\Update\\\\Install\\\\{E58B84A7-4841-45CD-A6
        # 1E-0B6E97019F39}\\\\";\n\tInstallState = 5;\n\tLanguage = "1033";\n\tLocalPackage = "C:\\\\windows\\\\Installer\\\\134c5e.msi";\n\tN
        # ame = "Google Drive";\n\tPackageCache = "C:\\\\windows\\\\Installer\\\\134c5e.msi";\n\tPackageCode = "{C145E38E-68C7-4D92-A576-2D70B
        # 93E112E}";\n\tPackageName = "gsync.msi";\n\tURLInfoAbout = "http://www.google.com";\n\tURLUpdateInfo = "http://www.google.com";\n\tV
        # endor = "Google, Inc.";\n\tVersion = "1.30.2170.0459";\n\tWordCount = 2;\n};\n'

        # TODO: This is horribly slow.
        wmiCnnct = wmi.WMI()

        # TODO: Very slow. Is this the fastest key ?
        winProds = wmiCnnct.Win32_Product(Caption=productCaption)

        nbProds = len(winProds)
        logging.debug("nbProds=%d", nbProds)
        if nbProds > 0:
            winProd = winProds[0]
            nodeInstallSource = lib_common.gUriGen.FileUri( winProd.InstallSource )
            grph.add((node, lib_common.MakeProp("InstallSource"), nodeInstallSource ) )

            nodeLocalPackage = lib_common.gUriGen.FileUri( winProd.LocalPackage)
            grph.add((node, lib_common.MakeProp("LocalPackage"), nodeLocalPackage))

            nodePackageCache = lib_common.gUriGen.FileUri( winProd.PackageCache)
            grph.add((nodePackageCache, lib_common.MakeProp("PackageName"), lib_util.NodeLiteral(winProd.PackageName)))
            grph.add((nodePackageCache, lib_common.MakeProp("PackageCode"), lib_util.NodeLiteral(winProd.PackageCode)))
            grph.add((node, lib_common.MakeProp("LocalPackage"), nodePackageCache ) )

            grph.add((node, lib_common.MakeProp("Vendor"), lib_util.NodeLiteral(winProd.Vendor)))
            grph.add((node, lib_common.MakeProp("Version"), lib_util.NodeLiteral(winProd.Version)))
            grph.add((node, lib_common.MakeProp("Name"), lib_util.NodeLiteral(winProd.Name)))

            try:
                grph.add((node, lib_common.MakeProp("URLInfoAbout"), lib_util.NodeLiteral(winProd.URLInfoAbout)))
            except AttributeError:
                pass
            try:
                grph.add((node, lib_common.MakeProp("URLUpdateInfo"), lib_util.NodeLiteral(winProd.URLUpdateInfo)))
            except AttributeError:
                pass

    except Exception as exc:
        grph.add((node, pc.property_information, lib_util.NodeLiteral(str(exc))))


