#!/usr/bin/python

# NOT USED YET BECAUSE WE MIGHT USE ONLY THE SAME SCRIPT FOR EVERYONE.
# This is experimental to ensure that we can process WBEM objects.
# It cannot harm and will be kept.

"""
Display a WBEM instance.
"""

import sys
import lib_common
import lib_util
import rdflib
from lib_properties import pc

try:
	import pywbem
	import lib_wbem
except ImportError:
	lib_common.ErrorMessageHtml("Pywbem Python library not installed")

cgiEnv = lib_common.CgiEnv("WBEM instance", can_process_remote = True)

entity_id = cgiEnv.GetId()
if entity_id == "":
	lib_common.ErrorMessageHtml("No entity_id")


# Just the path, shorter than cgiEnv.GetParameters("xid")
cimomUrl = cgiEnv.GetHost()

( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()
sys.stderr.write("nameSpace=%s className=%s\n" % (nameSpace,className))

if className == "":
	lib_common.ErrorMessageHtml("No class name. entity_id=%s" % entity_id)

rootNode = lib_util.EntityClassNode( className, nameSpace, cimomUrl, "WBEM" )

splitMonik = lib_util.SplitMoniker( cgiEnv.m_entity_id )

conn = lib_wbem.WbemConnection(cimomUrl)
sys.stderr.write("nameSpace=%s className=%s cimomUrl=%s\n" %(nameSpace,className,cimomUrl))

# If ExecQuery is not supported like on OpenPegasus, try to build one instance.
def WbemPlainExecQuery( conn, className, splitMonik, nameSpace ):
	aQry = lib_util.SplitMonikToWQL(splitMonik,className)
	# aQry = 'select * from CIM_System'
	try:
		# This does not work on OpenPegasus.
		return conn.ExecQuery("WQL", aQry, nameSpace)
	except Exception:
		exc = sys.exc_info()[1]

		# Problem sur le PC avec OpenPegasus.
		# aQry=select * from CIM_UnitaryComputerSystem where CreationClassName="PG_ComputerSystem"and Name="rchateau-HP". ns=root/cimv2. Caught:(7, u'CIM_ERR_NOT_SUPPORTED')
		# Pourquoi ? Alors qu il y a un objet. Meme chose en retirant "CreationClassName"
		msgExcFirst = str(exc)
		sys.stderr.write("WbemPlainExecQuery aQry=%s Exc=%s\n" % ( aQry, msgExcFirst ) )
		return None


# If ExecQuery is not supported like on OpenPegasus, try to build one instance.
def WbemNoQueryOneInst( conn, className, splitMonik, nameSpace ):
	try:
		keyBnds = pywbem.NocaseDict( splitMonik )

		# CA NE MARCHE PAS VRAIMENT CAR ON NE RESPECTE PAS LES PARAMETRES: msgExcFirst=CIMError: header-mismatch, PGErrorDetail:
		# Empty CIMObject value. wbemInstName=root/CIMv2:CIM_ComputerSystem.Name="rchateau-HP".
		# ns=. Caught:(4, u'CIM_ERR_INVALID_PARAMETER: Wrong number of keys')

		# wbemInstName = pywbem.CIMInstanceName( className, keybindings = keyBnds, host = cimomUrl, namespace = nameSpace )
		wbemInstName = pywbem.CIMInstanceName( className, keybindings = keyBnds, namespace = "root/CIMv2" )
		sys.stderr.write("keyBnds=%s wbemInstName=%s\n" %(str(keyBnds),str(wbemInstName)))

		wbemInstObj = conn.GetInstance( wbemInstName )

		return [ wbemInstObj ]
	except:
		exc = sys.exc_info()[1]
		# lib_common.ErrorMessageHtml("msgExcFirst="+msgExcFirst+" wbemInstName=" + str(wbemInstName) + ". ns="+nameSpace+". Caught:"+str(exc))
		sys.stderr.write("WbemNoQueryOneInst wbemInstName=" + str(wbemInstName) + ". ns="+nameSpace+". Caught:"+str(exc) + "\n")
		return None

# If ExecQuery is not supported like on OpenPegasus, read all instances and filters the good ones. VERY SLOW.
def WbemNoQueryFilterInstances( conn, className, splitMonik, nameSpace ):
	try:
		# TODO: Fix the namespace !!!!
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


instLists = WbemPlainExecQuery( conn, className, splitMonik, nameSpace )
if instLists is None:
	instLists = WbemNoQueryOneInst( conn, className, splitMonik, nameSpace )
	if instLists is None:
		instLists = WbemNoQueryFilterInstances( conn, className, splitMonik, nameSpace )

# ATTENTION: Si les lignes de titres sont trop longues, graphviz supprime des lignes de la table HTML !!!!!!! ????
# ET CA NE TIEN TPAS LA CHARGE !!!!!!!!!!!!!!!
# maxCnt = 70
# HARDCODE_LIMIT
maxCnt = 7000

# TODO: ET AUSSI ALLER CHERCHER L INFO SUR LA CLASSES COMME LE FAIT YAWN.

grph = rdflib.Graph()

# HELAS, ON A UN PROBLEME D OBJECTS DUPLIQUES:
# 'CSCreationClassName'   CIM_UnitaryComputerSystem Linux_ComputerSystem
# 'CreationClassName'     PG_UnixProcess            TUT_UnixProcess
# TODO: Dans un premier temps on va virer le provider
# qui cree des obstacles peut-etre artificiels, en tout cas irrealistes.
numInsts = len(instLists)

# If there are duplicates, adds a property which we hope is different.
propDiscrim = "CreationClassName"

# If the moniker comes straight out WBEM, values are surrounded by parentheses.
# Otherwise, not, because we forgot them. It might be good to always add them. Will see.
#def ChopEnclosingParentheses(wrd):
#	if len(wrd) > 0 and wrd[0] == '"' and wrd[-1] == '"':
#		return wrd[1:-1]
#	else:
#		return wrd

# TODO!! WHAT OF THIS IS NOT THE RIGHT ORDER ???
# Remove the double-quotes around the argument. WHAT IF THEY ARE NOT THERE ??
# arrVals = [ ChopEnclosingParentheses( splitMonik[qryKey] ) for qryKey in splitMonik ]

for anInst in instLists:

	# TODO: Use the right accessor for better performance.
	# On peut peut etre mettre tout ca dans une fonction sauf l execution de la query.
	dictInst = dict(anInst)

	# This differentiates several instance with the same properties.
	#if numInsts > 1:
	#	# TODO: Should check if this property is different for all instances !!!
	#	extraArgs = { propDiscrim : dictInst[ propDiscrim ] }
	#	uriInst = lib_util.EntityUriDupl( className, *arrVals, **extraArgs )
	#else:
	#	uriInst = lib_util.EntityUri( className, *arrVals )

	if numInsts > 1:
		# TODO: Should check if this property is different for all instances !!!
		withExtraArgs = { propDiscrim : dictInst[ propDiscrim ] }
		allArgs = splitMonik.copy()
		allArgs.update(withExtraArgs)
		uriInst = lib_util.EntityUriFromDict( className, allArgs  )
	else:
		uriInst = lib_util.EntityUriFromDict( className, splitMonik  )

	# PEUT-ETRE UTILISER LA VERITABLE CLASSE,
	# MAIS IL FAUT PART LA SUITE ATTEINDRE LA CLASSE DE BASE.
	grph.add( ( rootNode, rdflib.Literal(className), uriInst ) )

	for inameKey in dictInst:
		# Do not print twice values which are in the name.
		if inameKey in splitMonik:
			continue
		inameVal = dictInst[inameKey]
		# TODO: If this is a reference, create a Node !!!!!!!
		grph.add( ( uriInst, rdflib.Literal(inameKey), rdflib.Literal(inameVal) ) )

cgiEnv.OutCgiRdf(grph)
