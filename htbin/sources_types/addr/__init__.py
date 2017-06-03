"""
IP socket address
"""

import sys
import rdflib
import socket
import threading
import time
import socket
import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["Id"],)

# This returns a nice name given the parameter of the object.
def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	return entity_id

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

# Add the real url corresponding to this socket so we can nicely click on it.
# This is a bit expeimental.
def DecorateSocketNode(grph, socketNode, host, port, proto):
	socketNode = lib_common.gUriGen.AddrUri( host, port, proto )

	# sys.stderr.write("port=%s proto=%s\n"%(str(port),str(proto)))

	nodUrl = None

	if port == 80 and proto == "tcp":
		strUrl = "http://%s" % host
		nodUrl = rdflib.URIRef(strUrl)
		grph.add( ( nodUrl, pc.property_information, rdflib.Literal("HTTP url") ) )

		# Aller chercher des infos idealement ??

	if nodUrl:
		grph.add( ( socketNode, lib_common.MakeProp("port"), nodUrl ) )


################################################################################

def JoinThreads(threads):
	sys.stderr.write("JoinThreads: %d threads to return.\n" % len(threads))
	for thread in threads:
		# sys.stderr.write('Joining %s\n' % thread.getName())
		thread.join()

# This returns retrieves the host information corresponding to a network address.
# It might take a long time due to DNS delay, therefore one thread is started per host.
def GetHost(addr):
	try:
		return socket.gethostbyaddr(addr)
	except socket.herror:
		return [ addr, [] ]

# Different interfaces according to the Python version.
def SocketToPair(connect):
	if sys.version_info >= (3,):
		larray = connect.local_address
		rarray = connect.remote_address
	else:
		larray = connect.laddr
		rarray = connect.raddr
	return (larray,rarray)

# This asynchronously adds a RDF relation between a process and a socket.
# As it is asychronous, we can make a DNS query.
class PsutilAddSocketThread(threading.Thread):
	def __init__(self, node_process,connect,grph,grph_lock):
		self.node_process = node_process
		self.connect = connect
		self.grph = grph
		self.grph_lock = grph_lock

		threading.Thread.__init__(self)

	# TODO: We might, in the future, have one single object instead of two.
	# For example "socket_pair". Not sure.
	def run(self):
		# Now we create a node in rdflib, and we need a mutex for that.
		try:
			self.grph_lock.acquire()
			( larray, rarray ) = SocketToPair(self.connect)

			lhost = GetHost(larray[0])[0]
			lsocketNode = lib_common.gUriGen.AddrUri( lhost, larray[1] )

			try:
				rhost = GetHost(rarray[0])[0]
				rsocketNode = lib_common.gUriGen.AddrUri( rhost, rarray[1] )
				self.grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )
			except IndexError:
				pass

			# PAS CERTAIN: Qu'est ce qui dit qu une des sockets aboutit au host ?
			self.grph.add( ( self.node_process, pc.property_has_socket, lsocketNode ) )
			self.grph.add( ( lsocketNode, pc.property_information, rdflib.Literal(self.connect.status) ) )
		finally:
			self.grph_lock.release()
		# Some throttling, in case there are thousands of nodes.
		time.sleep(0.001)

def PsutilAddSocketToGraphAsync(node_process,connects,grph,flagShowUnconnected):
	threadsArr = []
	grph_lock = threading.Lock()

	for cnt in connects:
		if( ( cnt.family == socket.AF_INET )
		and ( cnt.type == socket.SOCK_STREAM )
		and ( flagShowUnconnected or ( cnt.status == 'ESTABLISHED' ) )
		):
			thr = PsutilAddSocketThread( node_process, cnt, grph, grph_lock )
			thr.start()
			threadsArr.append( thr )

	JoinThreads(threadsArr)

# TODO: We might, in the future, have one single object instead of two.
# TODO: Remove this hardcode !!!
# For example "socket_pair". Not sure.
def PsutilAddSocketToGraphOne(node_process,connect,grph):
	# sys.stdout.write('    ')
	if( ( connect.family == 2 )
	and ( connect.type == 1 )
	# and ( connect.status == 'ESTABLISHED' )
	):
		# Not sure of this test, maybe this rather depends on the psutil version.
		if sys.version_info >= (3,):
			lsocketNode = lib_common.gUriGen.AddrUri( connect.local_address[0], connect.local_address[1] )
			try:
				rsocketNode = lib_common.gUriGen.AddrUri( connect.remote_address[0], connect.remote_address[1] )
			except IndexError:
				rsocketNode = None
		else:
			lsocketNode = lib_common.gUriGen.AddrUri( connect.laddr[0], connect.laddr[1] )
			try:
				rsocketNode = lib_common.gUriGen.AddrUri( connect.raddr[0], connect.raddr[1] )
			except IndexError:
				rsocketNode = None

		# Il faudrait plutot une relation commutative.
		if rsocketNode != None:
			grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

		# PAS CERTAIN: Qu'est ce qui dit qu une des sockets aboutit au host ?
		grph.add( ( node_process, pc.property_has_socket, lsocketNode ) )
		grph.add( ( lsocketNode, pc.property_information, rdflib.Literal(connect.status) ) )

# On va peut-etre se debarrasser de ca si la version asynchrone est plus-rapide.
def PsutilAddSocketToGraph(node_process,connects,grph):
	for cnt in connects:
		PsutilAddSocketToGraphOne(node_process,cnt,grph)


