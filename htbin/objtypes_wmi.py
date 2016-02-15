#!/usr/bin/python

"""
WMI classes of a given namespace
"""

import sys
import lib_util
import lib_common
import rdflib
from lib_properties import pc

try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("Python package WMI is not available")
import lib_wmi

paramkeyMaxDepth = "Maximum depth"

cgiEnv = lib_common.CgiEnv("WMI classes in namespace", can_process_remote = True,
								parameters = { paramkeyMaxDepth : "4" })

maxDepth = int(cgiEnv.GetParameters( paramkeyMaxDepth ))

( wmiNamespace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

sys.stderr.write("wmiNamespace=%s entity_type=%s\n" % (wmiNamespace,entity_type))

cimomUrl = cgiEnv.GetHost()

if str(wmiNamespace) == "":
	lib_common.ErrorMessageHtml("WMI namespace should not be empty. entity_namespace_type="+entity_namespace_type)

grph = rdflib.Graph()

try:
	connWmi = lib_wmi.WmiConnect(cimomUrl,wmiNamespace)
except:
	exc = sys.exc_info()[1]
	# wmiNamespace=root\directory\\LDAP Caught:
	# x_wmi: Unexpected COM Error (-2147217375, 'OLE error 0x80041021', None, None)
	lib_common.ErrorMessageHtml("wmiNamespace=%s Caught:%s" % ( wmiNamespace, str(exc) ) )

def WmiNamespaceNode( clsNam ):
	wmiUrl = lib_wmi.NamespaceUrl( wmiNamespace, cimomUrl, clsNam )
	return rdflib.term.URIRef( wmiUrl )

rootNode = WmiNamespaceNode(entity_type)

dictClassToNode = dict()

# Manages a cache so nodes are created once only.
def ClassToNode(clsNam):
	global dictClassToNode
	try:
		wmiNode = dictClassToNode[ clsNam ]
	except KeyError:
		wmiMoniker = lib_wmi.BuildWmiMoniker( cimomUrl, wmiNamespace, clsNam )
		wmiUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True )
		wmiNode = rdflib.term.URIRef( wmiUrl )
		dictClassToNode[ clsNam ] = wmiNode
	return wmiNode


doneNode = set()

def DrawFromThisBase(clsNam,grph,clsDeriv):

	wmiNode = ClassToNode(clsNam)

	# The class is the starting point when displaying the class tree of the namespace.
	wmiNodeSub = WmiNamespaceNode(clsNam)

	grph.add( ( wmiNode, pc.property_rdf_data_nolist, rdflib.Literal(wmiNodeSub) ) )

	doneNode.add( clsNam )

	previousNode = wmiNode

	# TODO: Collapse the two case into one, for cleanliness.
	if len(clsDeriv) == 0:
		grph.add( ( rootNode, pc.property_cim_subclass, previousNode ) )
	else:
		# sys.stderr.write("clsNam=%s clsDeriv=%s\n" % ( clsNam, str(clsDeriv) ))
		for baseClassNam in clsDeriv:

			wmiBaseNode = ClassToNode(baseClassNam)

			grph.add( ( wmiBaseNode, pc.property_cim_subclass, previousNode ) )
			previousNode = wmiBaseNode
			if baseClassNam in doneNode:
				break

			doneNode.add( baseClassNam )

def GetDerivation(clsNam):
	wmi_class = getattr(connWmi, clsNam)
	return  wmi_class.derivation ()

cacheDerivations = {}

# Not sure this is faster.
def GetDerivationWithCache(clsNam):
	try:
		return cacheDerivations[ clsNam ]
	except KeyError:
		pass

	deriv = GetDerivation(clsNam)
	cacheDerivations[ clsNam ] = deriv
	for idx in range(0,len(deriv)):
		loopClass = deriv[idx]
		if loopClass in cacheDerivations:
			break
		cacheDerivations[ loopClass ] = deriv[idx+1:]

	return deriv

# TODO: Commencer a afficher a partir de entity_type si il est la.
# TODO: Pour la classe d'en haut, ajouter un lien pour remonter d'une position.
if entity_type == "":
	for clsNam in connWmi.classes:
		clsDeriv = GetDerivation(clsNam)

		# Pour limiter la profondeur, on part de la classe X et on en descend pas a plus de N niveaux.
		if len(clsDeriv) < maxDepth:
			DrawFromThisBase(clsNam,grph, clsDeriv)
else:
	# Normally this cache contains nodes to classes, but this is the top one.
	dictClassToNode[entity_type] = rootNode

	# This also points to its closest base class or to the namespace.
	topClsDeriv = GetDerivation(entity_type)
	if len(topClsDeriv) == 0:
		topNode = WmiNamespaceNode("")
	else:
		topNode = WmiNamespaceNode(topClsDeriv[0])
	grph.add( ( topNode, pc.property_cim_subclass, rootNode ) )

	for clsNam in connWmi.subclasses_of(entity_type):
		clsDeriv =  GetDerivation(clsNam)

		#sys.stderr.write("entity_type=%s clsNam=%s clsDeriv=%s\n" % (entity_type, clsNam, str(clsDeriv)))
		idxClass = clsDeriv.index(entity_type)
		invertIdx = len(clsDeriv)-idxClass
		# sys.stderr.write("clsNam=%s idxClass=%d invertIdx=%d clsDeriv=%s\n" % (clsNam, idxClass, invertIdx, str(clsDeriv)))
		# Pour limiter la profondeur, on part de la classe X et on en descend pas a plus de N niveaux.
		if len(clsDeriv) < maxDepth + invertIdx:
			# derivation starts by the lowest level to the top.
			DrawFromThisBase(clsNam,grph, clsDeriv[:idxClass])


cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[pc.property_cim_subclass])
# cgiEnv.OutCgiRdf(grph)

