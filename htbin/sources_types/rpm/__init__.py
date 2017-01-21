"""
RedHat Package Manager
"""

import rdflib
from rdflib.namespace import XSD

import rpm
import lib_common

def EntityOntology():
	return ( ["Rpm",], )

def MakeUri(rpmName):
	return lib_common.gUriGen.UriMakeFromDict("rpm", { "Rpm" : rpmName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0]


def RpmProps():
	listProps = ["epoch", "version", "release", "arch"]

	# Add a dot, so they come first.
	rpmProps = { propKey: lib_common.MakeProp("."+propKey) for propKey in listProps }

	return rpmProps


def AddInfo(grph,node,entity_ids_arr):
	rpmName = entity_ids_arr[0]

	rpmProps = RpmProps()

	ts = rpm.TransactionSet()
	mi = ts.dbMatch('name',rpmName)
	for h in mi:
		for propKey in rpmProps:
			propRpm = rpmProps[propKey]
			# The value might be None.
			propVal = h[ propKey ] or ""
			grph.add( ( node, propRpm, rdflib.Literal(propVal, datatype=XSD.string) ) )




