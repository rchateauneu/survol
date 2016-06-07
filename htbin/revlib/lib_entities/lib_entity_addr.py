import sys
import socket
import lib_common
from lib_properties import pc


def AddInfo(grph,node,entity_ids_arr):
	socketNam = entity_ids_arr[0]
	#sys.stderr.write("socketNam=%s\n"%socketNam)
	socketSplit = socketNam.split(':')
	socketAddr = socketSplit[0]
	#sys.stderr.write("socketAddr=%s\n"%socketAddr)
	sockIP = socket.gethostbyname(socketAddr)
	#sys.stderr.write("sockIP=%s\n"%sockIP)

	nodeHost = lib_common.gUriGen.HostnameUri( sockIP )
	# Should be the otherway round, but it makes the graph ugly.
	grph.add( ( node, pc.property_has_socket, nodeHost ) )
