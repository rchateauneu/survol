"""
Network adapter
"""

import lib_common

def EntityOntology():
    return ( ["Name"], )

def MakeUri(naNam):
	return lib_common.gUriGen.UriMakeFromDict("CIM_NetworkAdapter",{ "Name":naNam })
