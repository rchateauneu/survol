#!/usr/bin/python

"""
Display all instances of a given WBEM class
"""

import sys
import cgi
import rdflib
import urllib
import lib_util
import lib_common
import lib_wbem
import lib_wbem_cim
from lib_properties import pc

import pywbem # Might be pywbem or python3-pywbem.

# This can process remote hosts because it does not call any script, just shows them.
cgiEnv = lib_common.CgiEnv("WBEM class portal", can_process_remote = True)

grph = rdflib.Graph()

( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()
sys.stderr.write("nameSpace=%s className=%s entity_namespace_type=%s\n" % ( nameSpace, className, entity_namespace_type ) )

entity_host = cgiEnv.GetHost()

rootNode = lib_util.EntityClassNode( nameSpace, className, entity_host, "WBEM" )

conn = lib_wbem.WbemConnection(entity_host)

try:
	klass = conn.GetClass(className,
			namespace=nameSpace,
			LocalOnly=False,
			IncludeQualifiers=True)
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("GetClass: url="+entity_host+" ns="+nameSpace+" class="+className+". Caught:"+str(exc))

try:
	inst_names = conn.EnumerateInstanceNames(ClassName=className,namespace=nameSpace)
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("EnumerateInstanceNames: nameSpace="+nameSpace+" className="+className+". Caught:"+str(exc))

# ATTENTION: Si les lignes de titres sont trop longues, graphviz supprime des lignes de la table HTML !!!!!!!
# ET CA NE TIEN TPAS LA CHARGE !!!!!!!!!!!!!!!
# maxCnt = 70
# HARDCODE_LIMIT
maxCnt = 7000

for iname in inst_names:
	if maxCnt == 0:
		break
	maxCnt -= 1

	# Should not be pywbem.CIMInstance.
	if not isinstance(iname, pywbem.CIMInstanceName):
		lib_common.ErrorMessageHtml("EnumerateInstanceNames: Instance should be an CIMInstanceName")
		# otherwise path = iname.path

	# TODO: Virer TUT_UNixProcess de Fedora, inutile par PG_Process est la.
	entity_id = ",".join( [ "%s=%s" % ( k, iname[k] ) for k in iname.keys() ])

	wbemInstanceUrl = lib_util.ScriptizeCimom("/entity.py", entity_namespace_type, entity_id, entity_host )
	wbemInstanceNode = rdflib.term.URIRef(wbemInstanceUrl)

	grph.add( ( rootNode, pc.property_information, wbemInstanceNode ) )

	for key,val in iname.iteritems():
		grph.add( ( wbemInstanceNode, rdflib.Literal(key), rdflib.Literal(val) ) )


# TODO: On pourrait rassembler par classes,
# et aussi afficher les liens d'heritages des classes.


cgiEnv.OutCgiRdf(grph)

