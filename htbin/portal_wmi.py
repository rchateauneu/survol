#!/usr/bin/python

"""
Portal for all WMI related things.
"""

import rdflib
import lib_wmi
import lib_common
from lib_properties import pc

# This can process remote hosts because it does not call any script, just shows them.
cgiEnv = lib_common.CgiEnv("WMI portal")

grph = rdflib.Graph()

entity_type = cgiEnv.m_entity_type
entity_host = cgiEnv.GetHost()
entity_host = lib_wmi.NormalHostName(entity_host)


# TODO: We may also loop on all machines which may describe this object.
wmiurl = lib_wmi.GetWmiUrl( entity_host, "", "", "" )
if not wmiurl is None:
	wmiNode = rdflib.term.URIRef(wmiurl)

	hostNode = lib_common.gUriGen.HostnameUri( entity_host )
	grph.add( ( hostNode, pc.property_information, wmiNode ) )

cgiEnv.OutCgiRdf(grph)