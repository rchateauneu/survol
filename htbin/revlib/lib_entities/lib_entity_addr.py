import lib_common
from lib_properties import pc


def AddInfo(grph,node,entity_ids_arr):
	socketNam = entity_ids_arr[0]
	socketSplit = socketNam.split(':')
	socketAddr = socketSplit[0]

	nodeHost = lib_common.gUriGen.HostnameUri( socketAddr )
	# Should be the otherway round, but it makes the graph ugly.
	grph.add( ( node, pc.property_has_socket, nodeHost ) )
