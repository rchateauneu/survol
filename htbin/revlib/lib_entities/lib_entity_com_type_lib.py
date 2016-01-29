import lib_common
from lib_properties import pc


def AddInfo(grph,node,entity_ids_arr):
	# TODO: We should use something like lib_common.ComTypeLibExtract( entity_id )
	dllFileName = entity_ids_arr[0]

	fileNode = lib_common.gUriGen.FileUri( dllFileName )
	grph.add( ( fileNode, pc.property_com_dll, node ) )
