"""
PE file section
"""

import os
import lib_common

def EntityOntology():
	return ( ["Name","Section"], )

def EntityName(entity_ids_arr):
	fileName = entity_ids_arr[0]
	sectionName = entity_ids_arr[1]

	# A file name can be very long, so it is truncated.
	fileNameBase = os.path.basename(fileName)
	return fileNameBase + ":" + sectionName

def MakeUri(fileName, sectionName):
	return lib_common.gUriGen.UriMakeFromDict("CIM_DataFile/portable_executable/section", { "Name" : fileName, "Section" : sectionName } )
