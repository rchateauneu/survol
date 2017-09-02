import sys
import lib_common
import lib_util
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
# PRODUCT_PROPERTIES = [six.u('Language'),
#                       six.u('ProductName'),
#                       six.u('PackageCode'),
#                       six.u('Transforms'),
#                       six.u('AssignmentType'),
#                       six.u('PackageName'),
#                       six.u('InstalledProductName'),
#                       six.u('VersionString'),
#                       six.u('RegCompany'),
#                       six.u('RegOwner'),
#                       six.u('ProductID'),
#                       six.u('ProductIcon'),
#                       six.u('InstallLocation'),
#                       six.u('InstallSource'),
#                       six.u('InstallDate'),
#                       six.u('Publisher'),
#                       six.u('LocalPackage'),
#                       six.u('HelpLink'),
#                       six.u('HelpTelephone'),
#                       six.u('URLInfoAbout'),
#                       six.u('URLUpdateInfo'),]
PRODUCT_PROPERTIES = [u'Language',
                      u'ProductName',
                      u'PackageCode',
                      u'Transforms',
                      u'AssignmentType',
                      u'PackageName',
                      u'InstalledProductName',
                      u'VersionString',
                      u'RegCompany',
                      u'RegOwner',
                      u'ProductID',
                      u'ProductIcon',
                      u'InstallLocation',
                      u'InstallSource',
                      u'InstallDate',
                      u'Publisher',
                      u'LocalPackage',
                      u'HelpLink',
                      u'HelpTelephone',
                      u'URLInfoAbout',
                      u'URLUpdateInfo',]

# class to be used for python users :)
Product = namedtuple('Product', PRODUCT_PROPERTIES)


def get_property_for_product(product, property, buf_size=PROPERTY_BUFFER_SIZE):
    property_buffer = create_unicode_buffer(buf_size)
    size = DWORD(buf_size)
    result = windll.msi.MsiGetProductInfoW(product, property, property_buffer, byref(size))
    if result == ERROR_MORE_DATA:
        return get_property_for_product(product, property, 2 * buf_size)
    elif result == ERROR_SUCCESS:
        return property_buffer.value
    else:
        return str(result)
        # return None


def populate_product(uid):
    # sys.stderr.write("populate_product uid=%s type=%s\n" % (uid,type(uid)))
    properties = []
    for property in PRODUCT_PROPERTIES:
        properties.append(get_property_for_product(uid, property))
    return Product(*properties)

#	"symbol"              : ( ["Name","File"], ),
def EntityOntology():
    return ( ["IdentifyingNumber"], )

# TODO: Is the caption the best key ?
def MakeUri(productIdentifyingNumber):
    return lib_common.gUriGen.UriMake("Win32_Product",productIdentifyingNumber)

propProductInstallSource = lib_common.MakeProp("InstallSource")

def AddInstallSource(grph,node,winProd):
	# Windows file name, with backslashes replaced by convention in this software.
	# cleanInstallSource = winProd.InstallSource.replace("\\","/")
	cleanInstallSource = winProd.InstallSource

	cleanInstallSource += winProd.PackageName

	nodeInstallSource = lib_common.gUriGen.FileUri( cleanInstallSource )
	grph.add( (node, propProductInstallSource, nodeInstallSource ) )

def AddInfo(grph,node,entity_ids_arr):
	# BEWARE: "{}" have been stripped because they crash graphviz
	# ... but they did not in the "past". Why ?
	##### NOT ANYMORE BECAUSE OF WMI productIdentifyingNumber = "{" + six.u(entity_ids_arr[0]) + "}"
	productIdentifyingNumber = lib_common.six_u(entity_ids_arr[0])


	sys.stderr.write("productIdentifyingNumber=%s\n"%str(productIdentifyingNumber))
	try:
		winProd = populate_product(productIdentifyingNumber)

		sys.stderr.write("winProd=%s\n"%str(winProd))

		AddInstallSource(grph,node,winProd)

		nodeLocalPackage = lib_common.gUriGen.FileUri( winProd.LocalPackage )
		grph.add( (node, lib_common.MakeProp("LocalPackage"), nodeLocalPackage ) )

		if winProd.RegCompany:
			grph.add( (node, lib_common.MakeProp("Vendor"), lib_common.NodeLiteral(winProd.RegCompany) ) )
		grph.add( (node, lib_common.MakeProp("Version"), lib_common.NodeLiteral(winProd.VersionString) ) )
		grph.add( (node, lib_common.MakeProp("Name"), lib_common.NodeLiteral(winProd.ProductName) ) )

		if winProd.RegOwner:
			grph.add( (node, lib_common.MakeProp("RegOwner"), lib_common.NodeLiteral(winProd.RegOwner) ) )
		if winProd.ProductID:
			grph.add( (node, lib_common.MakeProp("ProductID"), lib_common.NodeLiteral(winProd.ProductID) ) )

		if winProd.ProductIcon:
			nodeProductIcon = lib_common.gUriGen.FileUri( winProd.ProductIcon )
			grph.add( (node, lib_common.MakeProp("ProductIcon"), nodeProductIcon ) )

		grph.add( (node, lib_common.MakeProp("PackageName"), lib_common.NodeLiteral(winProd.PackageName) ) )
		grph.add( (node, lib_common.MakeProp("PackageCode"), lib_common.NodeLiteral(winProd.PackageCode) ) )

		if winProd.Transforms:
			grph.add( (node, lib_common.MakeProp("Transforms"), lib_common.NodeLiteral(winProd.Transforms) ) )
		grph.add( (node, lib_common.MakeProp("AssignmentType"), lib_common.NodeLiteral(winProd.AssignmentType) ) )

		if winProd.InstallDate:
			txtDate = winProd.InstallDate[0:4] + "-" + winProd.InstallDate[4:6] + "-" + winProd.InstallDate[6:8]
			grph.add( (node, lib_common.MakeProp("InstallDate"), lib_common.NodeLiteral(txtDate) ) )

		grph.add( (node, lib_common.MakeProp("Publisher"), lib_common.NodeLiteral(winProd.Publisher) ) )

		if winProd.HelpLink:
			grph.add( (node, lib_common.MakeProp("HelpLink"), lib_common.NodeUrl(winProd.HelpLink) ) )
		if winProd.HelpTelephone:
			grph.add( (node, lib_common.MakeProp("HelpTelephone"), lib_common.NodeLiteral(winProd.HelpTelephone) ) )

		try:
			if winProd.URLInfoAbout:
				# This is an URL so we make it clickable
				grph.add( (node, lib_common.MakeProp("URLInfoAbout"), lib_common.NodeUrl(winProd.URLInfoAbout) ) )
		except AttributeError:
			pass
		try:
			if winProd.URLUpdateInfo:
				# This is an URL so we make it clickable
				grph.add( (node, lib_common.MakeProp("URLUpdateInfo"), lib_common.NodeUrl(winProd.URLUpdateInfo) ) )
		except AttributeError:
			pass

	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, lib_common.NodeLiteral(str(exc)) ) )



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
		sys.stderr.write("nbProds=%d\n"%nbProds)
		if nbProds > 0:
			winProd = winProds[0]
			nodeInstallSource = lib_common.gUriGen.FileUri( winProd.InstallSource )
			grph.add( (node, lib_common.MakeProp("InstallSource"), nodeInstallSource ) )

			nodeLocalPackage = lib_common.gUriGen.FileUri( winProd.LocalPackage )
			grph.add( (node, lib_common.MakeProp("LocalPackage"), nodeLocalPackage ) )

			nodePackageCache = lib_common.gUriGen.FileUri( winProd.PackageCache )
			grph.add( (nodePackageCache, lib_common.MakeProp("PackageName"), lib_common.NodeLiteral(winProd.PackageName) ) )
			grph.add( (nodePackageCache, lib_common.MakeProp("PackageCode"), lib_common.NodeLiteral(winProd.PackageCode) ) )
			grph.add( (node, lib_common.MakeProp("LocalPackage"), nodePackageCache ) )

			grph.add( (node, lib_common.MakeProp("Vendor"), lib_common.NodeLiteral(winProd.Vendor) ) )
			grph.add( (node, lib_common.MakeProp("Version"), lib_common.NodeLiteral(winProd.Version) ) )
			grph.add( (node, lib_common.MakeProp("Name"), lib_common.NodeLiteral(winProd.Name) ) )

			try:
				grph.add( (node, lib_common.MakeProp("URLInfoAbout"), lib_common.NodeLiteral(winProd.URLInfoAbout) ) )
			except AttributeError:
				pass
			try:
				grph.add( (node, lib_common.MakeProp("URLUpdateInfo"), lib_common.NodeLiteral(winProd.URLUpdateInfo) ) )
			except AttributeError:
				pass

	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, lib_common.NodeLiteral(str(exc)) ) )


