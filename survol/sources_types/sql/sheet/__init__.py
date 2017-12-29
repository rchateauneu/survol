"""
Abstract SQL table/view
"""

import lib_common

def EntityOntology():
	return ( ["Name"], )

def MakeUri(sheetNam):
	return lib_common.gUriGen.UriMakeFromDict("sql/sheet",{ "Name":sheetNam })

