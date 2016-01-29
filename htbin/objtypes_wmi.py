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

cgiEnv = lib_common.CgiEnv("WMI classes in namespace", can_process_remote = True)

( wmiNamespace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

# TODO: Voir s'il y a une classe qui sert de point de depart.'

cimomUrl = cgiEnv.GetHost()

maxDepth = 2

if str(wmiNamespace) == "":
	lib_common.ErrorMessageHtml("WMI namespace should not be empty. entity_namespace_type="+entity_namespace_type)

grph = rdflib.Graph()

# wmiNamespace = "root\directory\LDAP"
try:
	connWmi = lib_wmi.WmiConnect(cimomUrl,wmiNamespace)
except:
	exc = sys.exc_info()[1]
	# wmiNamespace=root\directory\\LDAP Caught:
	# x_wmi: Unexpected COM Error (-2147217375, 'OLE error 0x80041021', None, None)
	lib_common.ErrorMessageHtml("wmiNamespace=%s Caught:%s" % ( wmiNamespace, str(exc) ) )


wmiUrl = lib_wmi.NamespaceUrl( wmiNamespace, cimomUrl )
rootNode = rdflib.term.URIRef( wmiUrl )

dictClassToNode = dict()

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

def DrawFromThisBase(clsNam,grph):

	wmi_class = getattr (connWmi, clsNam)

	# ON CONSTATE QUE L ORDRE D INSERTION DES ARETES COMPTE ENORMEMENT POUR L ALGO !!!!
	# ICI ca duplique les aretes. Essayons autrement.
	clsDeriv =  wmi_class.derivation ()

	if len(clsDeriv) >= maxDepth:
		return

	wmiNode = ClassToNode(clsNam)




	# Pour memoire.

	#def NamespaceUrl(nskey,cimomUrl):
	#	wmiMoniker = BuildWmiMoniker( cimomUrl, nskey )
	#	wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True, True )
	#	return wmiInstanceUrl

	# TODO: Ajouter la sous-classe qui sera le point de depart.
	# On ne devrait ajouter ce lien que si il y a des classes derivees mais on ne peut pas le savoir.
	wmiUrlSub = lib_wmi.NamespaceUrl( wmiNamespace, cimomUrl )
	wmiNodeSub = rdflib.term.URIRef( wmiUrlSub )

	# ON Y EST PRESQUE SAUF LES TROIS POINTS et TAGADA.
	grph.add( ( wmiNode, pc.property_rdf_data_nolist, rdflib.Literal(wmiNodeSub) ) )
	# grph.add( ( wmiNode, pc.property_information, rdflib.Literal("Troulala") ) ) # Ca met juste le texte





	previousNode = wmiNode

	for baseClassNam in clsDeriv:

		# TODO: ICI, pour limiter la profondeur,
		# On part de la classe X et on en descend pas a plus de N niveaux.

		wmiBaseNode = ClassToNode(baseClassNam)

		if baseClassNam in doneNode:
			break
		doneNode.add( baseClassNam )

		grph.add( ( wmiBaseNode, pc.property_cim_subclass, previousNode ) )

		previousNode = wmiBaseNode
	grph.add( ( rootNode, pc.property_cim_subclass, previousNode ) )

def DrawClassesNoDup(connWmi,grph):

	# On affiche le SVG sans probleme dans IE et Firefox.
	# 520 OK. 530, bloque avec le message "Transferring data".
	# En ensuite message d'erreur SVG mal forme, comme s'il etait tronque.
	# Toutefois le fichier .log reste en attente comme si on etait bloque a la fin de l'execution du "dot".
	for clsNam in connWmi.classes:
		DrawFromThisBase(clsNam,grph)


# TODO: Commencer a afficher a partir de entity_type si il est la.
# TODO: Pour la classe d'en haut, ajouter un lien pour remonter d'une position.
DrawClassesNoDup(connWmi,grph)

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[pc.property_cim_subclass])
# cgiEnv.OutCgiRdf(grph)

