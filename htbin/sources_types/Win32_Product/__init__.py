import sys
import rdflib
import psutil
import lib_common
import lib_util
from lib_properties import pc

import wmi

# TODO: Is the caption the best key ?
def MakeUri(productCaption):
	return lib_common.gUriGen.UriMake("Win32_Product",productCaption)

# New style of entity-specific code which is now in the
# module ENTITY.py instead of lib_entities/lib_entity_ENTITY.py
# which was not a very 'pythonic' architecture.

# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	productCaption = entity_ids_arr[0]

	try:
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
			grph.add( (nodePackageCache, lib_common.MakeProp("PackageName"), rdflib.Literal(winProd.PackageName) ) )
			grph.add( (nodePackageCache, lib_common.MakeProp("PackageCode"), rdflib.Literal(winProd.PackageCode) ) )
			grph.add( (node, lib_common.MakeProp("LocalPackage"), nodePackageCache ) )

			grph.add( (node, lib_common.MakeProp("Vendor"), rdflib.Literal(winProd.Vendor) ) )
			grph.add( (node, lib_common.MakeProp("Version"), rdflib.Literal(winProd.Version) ) )
			grph.add( (node, lib_common.MakeProp("Name"), rdflib.Literal(winProd.Name) ) )

			try:
				grph.add( (node, lib_common.MakeProp("URLInfoAbout"), rdflib.Literal(winProd.URLInfoAbout) ) )
			except AttributeError:
				pass
			try:
				grph.add( (node, lib_common.MakeProp("URLUpdateInfo"), rdflib.Literal(winProd.URLUpdateInfo) ) )
			except AttributeError:
				pass

	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, rdflib.Literal(str(exc)) ) )


