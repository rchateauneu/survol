#!/usr/bin/python

"""
WBEM instance
Display generic properties of a WBEM object.
"""

import sys
import lib_common
import lib_util
from lib_properties import pc

try:
	import pywbem
	import lib_wbem
except ImportError:
	lib_common.ErrorMessageHtml("Pywbem Python library not installed")


# If ExecQuery is not supported like on OpenPegasus, try to build one instance.
def WbemPlainExecQuery( conn, className, splitMonik, nameSpace ):
	aQry = lib_util.SplitMonikToWQL(splitMonik,className)
	DEBUG("WbemPlainExecQuery nameSpace=%s aQry=%s", nameSpace,aQry)
	# aQry = 'select * from CIM_System'
	# aQry = 'select * from CIM_ComputerSystem'
	try:
		# This does not work on OpenPegasus.
		return conn.ExecQuery("WQL", aQry, nameSpace)
	except Exception:
		exc = sys.exc_info()[1]

		# Problem on Windows with OpenPegasus.
		# aQry=select * from CIM_UnitaryComputerSystem where CreationClassName="PG_ComputerSystem"and Name="rchateau-HP". ns=root/cimv2. Caught:(7, u'CIM_ERR_NOT_SUPPORTED')
		msgExcFirst = str(exc)
		WARNING("WbemPlainExecQuery aQry=%s Exc=%s", aQry, msgExcFirst )
		return None


# If ExecQuery is not supported like on OpenPegasus, try to build one instance.
def WbemNoQueryOneInst( conn, className, splitMonik, nameSpace ):
	try:
		keyBnds = pywbem.cim_obj.NocaseDict( splitMonik )

		# FIXME: Problem with parameters: msgExcFirst=CIMError: header-mismatch, PGErrorDetail:
		# Empty CIMObject value. wbemInstName=root/CIMv2:CIM_ComputerSystem.Name="rchateau-HP".
		# ns=. Caught:(4, u'CIM_ERR_INVALID_PARAMETER: Wrong number of keys')

		# wbemInstName = pywbem.CIMInstanceName( className, keybindings = keyBnds, host = cimomUrl, namespace = nameSpace )
		wbemInstName = pywbem.CIMInstanceName( className, keybindings = keyBnds, namespace = "root/CIMv2" )
		DEBUG("keyBnds=%s wbemInstName=%s", str(keyBnds),str(wbemInstName))

		wbemInstObj = conn.GetInstance( wbemInstName )

		return [ wbemInstObj ]
	except:
		exc = sys.exc_info()[1]
		# lib_common.ErrorMessageHtml("msgExcFirst="+msgExcFirst+" wbemInstName=" + str(wbemInstName) + ". ns="+nameSpace+". Caught:"+str(exc))
		WARNING("WbemNoQueryOneInst className=" + str(className) + ". ns="+nameSpace+".\nCaught:"+str(exc))
		return None

# If ExecQuery is not supported like on OpenPegasus, read all instances and filters the good ones. VERY SLOW.
def WbemNoQueryFilterInstances( conn, className, splitMonik, nameSpace ):
	try:
		# TODO: namespace is hard-coded.
		nameSpace = "root/CIMv2"
		instNamesList = conn.EnumerateInstanceNames(ClassName=className,namespace=nameSpace)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("EnumerateInstanceNames: nameSpace="+nameSpace+" className="+className+". Caught:"+str(exc))

	listInsts = []
	for instNam in instNamesList:
		keysToCheck = []
		isDifferent = False
		for monikKey in splitMonik:
			# TODO: We could check that once only for the whole class, maybe ?
			if instNam.has_key(monikKey):
				instNamVal = instNam.get( monikKey )
				if instNamVal != splitMonik[ monikKey ]:
					isDifferent = True
					break
			else:
				keysToCheck.append( monikKey )

		if isDifferent:
			continue

		# Now we have to load the instance anyway and compare some keys which are not in the InstanceName.
		wbemInst = conn.GetInstance( instNam )

		isDifferent = False
		for monikKey in keysToCheck:

			if wbemInst.has_key(monikKey):
				instNamVal = wbemInst.get( monikKey )
				if instNamVal != splitMonik[ monikKey ]:
					isDifferent = True
					break

		if isDifferent:
			continue
		listInsts.append( instNam )

	return listInsts

# This adds a link to the namespace of this WBEM class: It shows its inheritance graph.
def AddNamespaceLink(grph, rootNode, nameSpace, cimomUrl, className):
	urlNamespace = lib_wbem.NamespaceUrl( nameSpace, cimomUrl, className )
	nodNamespace = lib_common.NodeUrl( urlNamespace )
	grph.add( ( rootNode, pc.property_cim_subnamespace , nodNamespace ) )

def Main():

	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	entity_id = cgiEnv.GetId()
	DEBUG("entity_id=%s", entity_id)
	if entity_id == "":
		lib_common.ErrorMessageHtml("No entity_id")


	# Just the path, shorter than cgiEnv.GetParameters("xid")
	cimomUrl = cgiEnv.GetHost()

	( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()
	DEBUG("entity_wbem.py cimomUrl=%s nameSpace=%s className=%s", cimomUrl,nameSpace,className)

	if nameSpace == "":
		nameSpace = "root/cimv2"
		INFO("Setting namespace to default value\n")


	if className == "":
		lib_common.ErrorMessageHtml("No class name. entity_id=%s" % entity_id)

	grph = cgiEnv.GetGraph()

	conn = lib_wbem.WbemConnection(cimomUrl)

	rootNode = lib_util.EntityClassNode( className, nameSpace, cimomUrl, "WBEM" )
	klaDescrip = lib_wbem.WbemClassDescription(conn,className,nameSpace)
	if not klaDescrip:
		klaDescrip = "Undefined class %s %s" % ( nameSpace, className )
	grph.add( ( rootNode, pc.property_information, lib_common.NodeLiteral(klaDescrip ) ) )

	splitMonik = lib_util.SplitMoniker( cgiEnv.m_entity_id )

	DEBUG("entity_wbem.py nameSpace=%s className=%s cimomUrl=%s",nameSpace,className,cimomUrl)

	# This works:
	# conn = pywbem.WBEMConnection("http://192.168.0.17:5988",("pegasus","toto"))
	# conn.ExecQuery("WQL","select * from CIM_System","root/cimv2")
	# conn.ExecQuery("WQL",'select * from CIM_Process  where Handle="4125"',"root/cimv2")
	#
	# select * from CIM_Directory or CIM_DataFile does not return anything.


	instLists = WbemPlainExecQuery( conn, className, splitMonik, nameSpace )
	DEBUG("entity_wbem.py instLists=%s",str(instLists))
	if instLists is None:
		instLists = WbemNoQueryOneInst( conn, className, splitMonik, nameSpace )
		if instLists is None:
			instLists = WbemNoQueryFilterInstances( conn, className, splitMonik, nameSpace )

	# TODO: Some objects are duplicated.
	# 'CSCreationClassName'   CIM_UnitaryComputerSystem Linux_ComputerSystem
	# 'CreationClassName'     PG_UnixProcess            TUT_UnixProcess
	numInsts = len(instLists)

	# If there are duplicates, adds a property which we hope is different.
	propDiscrim = "CreationClassName"

	# TODO!! WHAT OF THIS IS NOT THE RIGHT ORDER ???
	# Remove the double-quotes around the argument. WHAT IF THEY ARE NOT THERE ??
	# arrVals = [ ChopEnclosingParentheses( splitMonik[qryKey] ) for qryKey in splitMonik ]

	for anInst in instLists:

		# TODO: Use the right accessor for better performance.
		# On peut peut etre mettre tout ca dans une fonction sauf l execution de la query.
		dictInst = dict(anInst)

		# This differentiates several instance with the same properties.


		if numInsts > 1:
			# TODO: Should check if this property is different for all instances !!!
			withExtraArgs = { propDiscrim : dictInst[ propDiscrim ] }
			allArgs = splitMonik.copy()
			allArgs.update(withExtraArgs)
			dictProps = allArgs
		else:
			dictProps = splitMonik

		hostOnly = lib_util.EntHostToIp(cimomUrl)
		if lib_util.IsLocalAddress(hostOnly):
			uriInst = lib_common.gUriGen.UriMakeFromDict(className, dictProps)
		else:
			uriInst = lib_common.RemoteBox(hostOnly).UriMakeFromDict(className, dictProps)

		grph.add( ( rootNode, lib_common.MakeProp(className), uriInst ) )

		AddNamespaceLink(grph, rootNode, nameSpace, cimomUrl, className)

		# None properties are not printed.
		for inameKey in dictInst:
			# Do not print twice values which are in the name.
			if inameKey in splitMonik:
				continue
			inameVal = dictInst[inameKey]
			# TODO: If this is a reference, create a Node !!!!!!!
			if not inameVal is None:
				grph.add( ( uriInst, lib_common.MakeProp(inameKey), lib_common.NodeLiteral(inameVal) ) )

		# TODO: Should call Associators(). Same for References().

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
