#!/usr/bin/python

"""
Display all instances of a given WMI class
"""

import sys
import cgi
import rdflib
import urllib
import lib_util
import lib_common
import lib_wmi
from lib_properties import pc

# This can process remote hosts because it does not call any script, just shows them.
cgiEnv = lib_common.CgiEnv("WMI class portal", can_process_remote = True)

grph = rdflib.Graph()

( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()

entity_host = cgiEnv.GetHost()

# TODO: Fix this, embed the cimom server in the host.
# cgiUrl="http://192.168.1.88:5988"
cimomUrl = entity_host

rootNode = lib_util.EntityClassNode( className, nameSpace, cimomUrl, "WMI" )

# Must remove "root\" at the beginning of "root\Cli" or "root\CIMv2"
if nameSpace[0:5] == "root\\":
	nameSpace = nameSpace[5:]
else:
	lib_common.ErrorMessageHtml("cimomUrl=%s Cannot truncate nameSpace=%s entity_namespace_type=%s\n" % ( cimomUrl, nameSpace, entity_namespace_type ) )

connWmi = lib_wmi.WmiConnect(cimomUrl,nameSpace)

lib_wmi.WmiAddClassQualifiers( grph, connWmi, rootNode, className, True )

# Inutilisable pour:
# root/CIMV2/CIM_LogicalFile
# car il y en a beaucoup trop.
# TODO: pEUT-ETRE QUE wql POURRAQIT PERMETTRE UNE LIMITE ??
# Ou bien arguments: De 1 a 100 etc... mais ca peut nous obliger de creer des liens bidons
# pour aller aux elements suivants ou precedents. Notons que ca revient a creer des scripts artificiels.

# Et aussi, revenir vers l'arborescence des classes dans ce namespace.

# lib_common.ErrorMessageHtml("Too many elements in className=%s\n" % ( className ) )

# Il y a d autres classes hardcodees de cette facon.
if lib_wmi.WmiTooManyInstances( className ):
	lib_common.ErrorMessageHtml("Too many elements in className=%s\n" % ( className ) )

try:
	wmiClass = getattr( connWmi, className )
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("cimomUrl=%s %s nameSpace=%s className=%s Caught:%s\n" % ( cimomUrl, entity_namespace_type, nameSpace, className, str(exc) ) )

try:
	lstObj = wmiClass()
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Caught when getting list of %s\n" % className )

sys.stderr.write("className=%s type(wmiClass)=%s len=%d\n" % ( className, str(type(wmiClass)), len( lstObj ) ) )

for wmiObj in lstObj:
	# Full natural path: We must try to merge it with WBEM Uris.
	# '\\\\RCHATEAU-HP\\root\\cimv2:Win32_Process.Handle="0"'
	# https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"

	fullPth = str( wmiObj.path() )
	# sys.stderr.write("fullPth=%s\n" % fullPth)

	if fullPth == "":
		sys.stderr.write("WARNING Empty path wmiObj=%s\n" % str(wmiObj))
		continue

	wmiInstanceUrl = lib_util.EntityUrlFromMoniker( fullPth )
	wmiInstanceNode = rdflib.term.URIRef(wmiInstanceUrl)

	# infos = lib_wbem_cim.get_inst_info(iname, klass, include_all=True, keys_only=True)

	grph.add( ( rootNode, pc.property_class_instance, wmiInstanceNode ) )

# TODO: On pourrait rassembler par classes, et aussi afficher les liens d'heritages des classes.

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[pc.property_class_instance])

