#!/usr/bin/env python

"""
WMI object types
"""

import sys
import lib_util
import lib_kbase
import lib_common
from lib_properties import pc

try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("Python package WMI is not available")
import lib_wmi

# Manages a cache so nodes are created once only.
def ClassToNode(wmiNamespace, cimomUrl, clsNam):
	global dictClassToNode
	try:
		wmiNode = dictClassToNode[ clsNam ]
	except KeyError:
		wmiUrl = lib_wmi.ClassUrl(wmiNamespace,cimomUrl,clsNam)
		wmiNode = lib_common.NodeUrl( wmiUrl )

		dictClassToNode[ clsNam ] = wmiNode
	return wmiNode

def WmiNamespaceNode( wmiNamespace, cimomUrl, clsNam ):
	# objtypes_wmi.py
	wmiUrl = lib_wmi.NamespaceUrl( wmiNamespace, cimomUrl, clsNam )
	return lib_common.NodeUrl( wmiUrl )

doneNode = set()

def DrawFromThisBase(rootNode, wmiNamespace, cimomUrl,clsNam,grph,clsDeriv):
	global doneNode
	wmiNode = ClassToNode(wmiNamespace, cimomUrl,clsNam)

	# The class is the starting point when displaying the class tree of the namespace.
	wmiNodeSub = WmiNamespaceNode(wmiNamespace, cimomUrl,clsNam)
	grph.add( ( wmiNode, pc.property_rdf_data_nolist1, wmiNodeSub ) )

	nodeGeneralisedClass = lib_util.EntityClassNode(clsNam,wmiNamespace,cimomUrl,"WMI")
	grph.add( ( wmiNode, pc.property_rdf_data_nolist2, nodeGeneralisedClass) )
	grph.add( ( wmiNode, pc.property_information, lib_kbase.MakeNodeLiteral(clsNam) ) )

	doneNode.add( clsNam )

	previousNode = wmiNode

	# TODO: Collapse the two case into one, for cleanliness.
	if len(clsDeriv) == 0:
		grph.add( ( rootNode, pc.property_cim_subclass, previousNode ) )
	else:
		# sys.stderr.write("clsNam=%s clsDeriv=%s\n" % ( clsNam, str(clsDeriv) ))
		for baseClassNam in clsDeriv:

			wmiBaseNode = ClassToNode(wmiNamespace, cimomUrl, baseClassNam)

			grph.add( ( wmiBaseNode, pc.property_cim_subclass, previousNode ) )
			grph.add( ( wmiBaseNode, pc.property_information, lib_kbase.MakeNodeLiteral(baseClassNam) ) )
			previousNode = wmiBaseNode
			if baseClassNam in doneNode:
				break

			doneNode.add( baseClassNam )

def GetDerivation(connWmi, clsNam):
	wmi_class = getattr(connWmi, clsNam)
	return  wmi_class.derivation ()

cacheDerivations = {}

# Not sure this is faster.
def GetDerivationWithCache(connWmi, clsNam):
	global cacheDerivations
	try:
		return cacheDerivations[ clsNam ]
	except KeyError:
		pass

	deriv = GetDerivation(connWmi, clsNam)
	cacheDerivations[ clsNam ] = deriv
	for idx in range(0,len(deriv)):
		loopClass = deriv[idx]
		if loopClass in cacheDerivations:
			break
		cacheDerivations[ loopClass ] = deriv[idx+1:]

	return deriv


def Main():
	global 	dictClassToNode

	dictClassToNode = dict()

	paramkeyMaxDepth = "Maximum depth"

	cgiEnv = lib_common.CgiEnv(can_process_remote = True,
									parameters = { paramkeyMaxDepth : 3 })

	maxDepth = int(cgiEnv.get_parameters( paramkeyMaxDepth ))

	( wmiNamespace, entity_type, entity_namespace_type ) = cgiEnv.get_namespace_type()

	DEBUG("wmiNamespace=%s entity_type=%s", wmiNamespace,entity_type)

	cimomUrl = cgiEnv.GetHost()

	# If wmiNamespace, this is not an issue, it is set to "root/CIMV2" by default.

	grph = cgiEnv.GetGraph()

	try:
		connWmi = lib_wmi.WmiConnect(cimomUrl,wmiNamespace)
	except:
		exc = sys.exc_info()[1]
		# wmiNamespace=root\directory\\LDAP Caught:
		# x_wmi: Unexpected COM Error (-2147217375, 'OLE error 0x80041021', None, None)
		lib_common.ErrorMessageHtml("wmiNamespace=%s Caught:%s" % ( wmiNamespace, str(exc) ) )

	rootNode = ClassToNode(wmiNamespace, cimomUrl, entity_type)

	# rootNodeNameSpace = WmiNamespaceNode(entity_type)
	# grph.add( ( rootNode, pc.property_rdf_data_nolist2, lib_common.NodeLiteral(rootNodeNameSpace) ) )
	# def EntityClassNode(entity_type, entity_namespace = "", entity_host = "", category = ""):
	rootGeneralisedClass = lib_util.EntityClassNode(entity_type,wmiNamespace,cimomUrl,"WMI")
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, rootGeneralisedClass ) )

	# TODO: Should add a link to the upper class.
	if entity_type == "":
		for clsNam in connWmi.classes:
			clsDeriv = GetDerivation(connWmi, clsNam)

			if len(clsDeriv) < maxDepth:
				DrawFromThisBase(rootNode, wmiNamespace, cimomUrl, clsNam,grph, clsDeriv)
	else:
		# Normally this cache contains nodes to classes, but this is the top one.
		dictClassToNode[entity_type] = rootNode

		# This also points to its closest base class or to the namespace.
		topClsDeriv = GetDerivation(connWmi, entity_type)
		if len(topClsDeriv) == 0:
			topNode = WmiNamespaceNode(wmiNamespace, cimomUrl, "")
		else:
			topNode = WmiNamespaceNode(wmiNamespace, cimomUrl, topClsDeriv[0])
		grph.add( ( topNode, pc.property_cim_subclass, rootNode ) )

		for clsNam in connWmi.subclasses_of(entity_type):
			clsDeriv =  GetDerivation(connWmi, clsNam)

			#sys.stderr.write("entity_type=%s clsNam=%s clsDeriv=%s\n" % (entity_type, clsNam, str(clsDeriv)))
			idxClass = clsDeriv.index(entity_type)
			invertIdx = len(clsDeriv)-idxClass
			# sys.stderr.write("clsNam=%s idxClass=%d invertIdx=%d clsDeriv=%s\n" % (clsNam, idxClass, invertIdx, str(clsDeriv)))
			# This tree can be very deep so there is a maximum depth.
			if len(clsDeriv) < maxDepth + invertIdx:
				# derivation starts by the lowest level to the top.
				DrawFromThisBase(rootNode, wmiNamespace, cimomUrl, clsNam,grph, clsDeriv[:idxClass])

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_cim_subclass])
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
