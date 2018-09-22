#!/usr/bin/python

"""
WMI class portal
"""

import sys
import cgi
import urllib
import lib_util
import lib_common
import lib_wmi
from lib_properties import pc

# Adds an extra nodes to make things more interesting.
def AddExtraNodes(grph,rootNode):
	objtypeNode = lib_common.NodeUrl( lib_util.uriRoot + '/objtypes.py' )
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, objtypeNode ) )

def Main():
	paramkeyEnumInstances = "Enumerate instances"

	cgiEnv = lib_common.CgiEnv(	parameters = { paramkeyEnumInstances : False })

	flagEnumInstances = bool(cgiEnv.GetParameters( paramkeyEnumInstances ))

	grph = cgiEnv.GetGraph()

	( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()
	DEBUG("nameSpace=%s className=%s entity_namespace_type=%s", nameSpace,className,entity_namespace_type)

	cimomUrl = cgiEnv.GetHost()

	rootNode = lib_util.EntityClassNode( className, nameSpace, cimomUrl, "WMI" )

	AddExtraNodes(grph,rootNode)

	# Not sure why, but sometimes backslash replaced by slash, depending where we come from ?
	nameSpace = nameSpace.replace("/","\\")

	# Must remove "root\" at the beginning of "root\Cli" or "root\CIMv2"
	#if nameSpace[0:5] == "root\\":
	#	nameSpace = nameSpace[5:]
	#else:
	#	lib_common.ErrorMessageHtml("cimomUrl=%s entity_namespace_type=%s nameSpace=%s wrong prefix\n" % ( cimomUrl, nameSpace, entity_namespace_type ) )

	# HP Windows 7 ... ET ... Toshiba Windows 8 seulement.
	# connWmi = lib_wmi.WmiConnect(cimomUrl, nameSpace)
	# Toshiba Windows 8
	# connWmi = lib_wmi.WmiConnect(cimomUrl, "root\\" + nameSpace)
	try:
		connWmi = lib_wmi.WmiConnect(cimomUrl, nameSpace)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("WMI Connecting to cimomUrl=%s nameSpace=%s Caught:%s\n" % ( cimomUrl, nameSpace, str(exc) ) )

	# http://rchateau-hp:8000/survol/class_wmi.py?xid=\\rchateau-HP\root\CIMV2%3ACIM_Directory.
	# http://rchateau-hp:8000/survol/class_wmi.py?xid=\rchateau-HP\root\CIMV2%3ACIM_Directory.&mode=html

	lib_wmi.WmiAddClassQualifiers( grph, connWmi, rootNode, className, True )

	# Inutilisable pour:
	# root/CIMV2/CIM_LogicalFile
	# car il y en a beaucoup trop.
	# TODO: pEUT-ETRE QUE wql POURRAQIT PERMETTRE UNE LIMITE ??
	# Ou bien arguments: De 1 a 100 etc... mais ca peut nous obliger de creer des liens bidons
	# pour aller aux elements suivants ou precedents. Notons que ca revient a creer des scripts artificiels.

	# Et aussi, revenir vers l'arborescence des classes dans ce namespace.

	try:
		wmiClass = getattr( connWmi, className )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("class_wmi.py cimomUrl=%s tp=%s nameSpace=%s className=%s Caught:%s\n" % ( cimomUrl, entity_namespace_type, nameSpace, className, str(exc) ) )

	# wmiClass=[Abstract, Locale(1033): ToInstance, UUID("{8502C55F-5FBB-11D2-AAC1-006008C78BC7}"): ToInstance]
	# class CIM_Directory : CIM_LogicalFile
	# {
	# };
	DEBUG("wmiClass=%s",str(wmiClass))

	for k in wmiClass():
		sys.stderr.write("k\n")
		break

	# Some examples of WMI queries.
	# http://timgolden.me.uk/python/wmi/tutorial.html
	#
	# logical_disk = wmi.WMI(moniker="//./root/cimv2:Win32_LogicalDisk")
	# c_drive = wmi.WMI(moniker='//./root/cimv2:Win32_LogicalDisk.DeviceID="C:"')
	# c = wmi.WMI("MachineB", user=r"MachineB\fred", password="secret")
	#
	# A WMI class can be "called" with simple equal-to parameters to narrow down the list.
	# This filtering is happening at the WMI level.
	# for disk in c.Win32_LogicalDisk(DriveType=3):
	# for service in c.Win32_Service(Name="seclogon"):
	#
	# Arbitrary WQL queries can be run, but apparently WQL selects first all elements from WMI,
	# then only does its filtering:
	# for disk in wmi.WMI().query("SELECT Caption, Description FROM Win32_LogicalDisk WHERE DriveType <> 3"):
	#
	if flagEnumInstances:


		# Biggest difficulty is the impossibility to limit the numbers of results fetched by WMI.
		# Many classes have to many elements to display them.
		# This makes it virtually impossible to select their elements.
		if lib_wmi.WmiTooManyInstances( className ):
			lib_common.ErrorMessageHtml("Too many elements in className=%s\n" % ( className ) )

		try:
			lstObj = wmiClass()
		except Exception:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Caught when getting list of %s\n" % className )


		numLstObj = len( lstObj )
		sys.stderr.write("className=%s type(wmiClass)=%s len=%d\n" % ( className, str(type(wmiClass)), numLstObj ) )

		if numLstObj == 0:
			grph.add( ( rootNode, pc.property_information, lib_common.NodeLiteral("No instances in this class") ) )

		for wmiObj in lstObj:
			# Full natural path: We must try to merge it with WBEM Uris.
			# '\\\\RCHATEAU-HP\\root\\cimv2:Win32_Process.Handle="0"'
			# https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"

			try:
				fullPth = str( wmiObj.path() )
			except UnicodeEncodeError:
				# UnicodeEncodeError: 'ascii' codec can't encode characters in position 104-108: ordinal not in range(128)
				exc = sys.exc_info()[1]
				WARNING("Exception %s",str(exc))
				continue

			# sys.stderr.write("fullPth=%s\n" % fullPth)

			if fullPth == "":
				sys.stderr.write("WARNING Empty path wmiObj=%s\n" % str(wmiObj))
				# The class Win32_PnPSignedDriver (Maybe others) generates dozens of these messages.
				# This is not really an issue as this class should be hidden from applications.
				# WARNING Empty path wmiObj=
				# instance of Win32_PnPSignedDriver
				# {
				# 		ClassGuid = NULL;
				# 		CompatID = NULL;
				# 		Description = NULL;
				# 		DeviceClass = "LEGACYDRIVER";
				# 		DeviceID = "ROOT\\LEGACY_LSI_FC\\0000";
				# 		DeviceName = "LSI_FC";
				# 		DevLoader = NULL;
				# 		DriverName = NULL;
				# 		DriverProviderName = NULL;
				# 		DriverVersion = NULL;
				# 		FriendlyName = NULL;
				# 		HardWareID = NULL;
				# 		InfName = NULL;
				# 		Location = NULL;
				# 		Manufacturer = NULL;
				# 		PDO = NULL;
				# };
				continue

			# fullPth=\\RCHATEAU-HP\root\CIMV2:Win32_SoundDevice.DeviceID="HDAUDIO\\FUNC_01&VEN_10EC&DEV_0221&SUBSYS_103C18E9&REV_1000\\4&3BC582&0&0001"
			fullPth = fullPth.replace("&","&amp;")
			wmiInstanceUrl = lib_util.EntityUrlFromMoniker( fullPth )
			DEBUG("wmiInstanceUrl=%s",wmiInstanceUrl)

			wmiInstanceNode = lib_common.NodeUrl(wmiInstanceUrl)

			# infos = lib_wbem_cim.get_inst_info(iname, klass, include_all=True, keys_only=True)

			grph.add( ( rootNode, pc.property_class_instance, wmiInstanceNode ) )

	# TODO: On pourrait rassembler par classes, et aussi afficher les liens d'heritages des classes.

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_class_instance])

	# TODO: Prev/Next like class_wbem.py

if __name__ == '__main__':
	Main()
