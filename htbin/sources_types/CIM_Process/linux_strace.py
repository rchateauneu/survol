#!/usr/bin/python

import os
import re
import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import lib_webserv

Usable = lib_util.UsableLinux

################################################################################

logFil = None

def LogMsg(str):
	logFil.write( "STrace p=%d %s\n" % (os.getpid(), str) )

################################################################################


# {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}
# {sa_family=AF_UNSPEC, sa_data="\0\0\0\0\0\0\0\0\0\0\0\0\0\0"}
def ParseSockAddrFromTcpDump( sock_addr ):
	LogMsg("ParseSockAddrFromTcpDump:"+sock_addr)
	regexSockAddr = r'{sa_family=([^,]*), sin_port=htons\(([0-9]*)\), sin_addr=inet_addr\("([^"]*)"\)}'

	matchSockAddr = re.match( regexSockAddr, sock_addr, re.M|re.I)
	if matchSockAddr:
		LogMsg( "ParseSockAddrFromTcpDump group=" + matchSockAddr.group(1) )
		if matchSockAddr.group(1) == "AF_INET":
			return lib_common.gUriGen.AddrUri( matchSockAddr.group(3), matchSockAddr.group(2) )
	return None

# [pid  8263] recvfrom(50, "DH\201\200\0\1\0\10\0\0\0\0\16d36aw3ue2ntmsq\ncloudfront\3net\0\0\1\0\1\300\f\0\1\0\1\0\0\0<\0\0046\346\0031\300\f\0\1\0\1\0\0\0<\0\0046\346\3\201\300\f\0\1\0\1\0\0\0<\0\0046\346\0G\300\f\0\1\0"..., 1024, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}, [16]) = 175
def parse_recvfrom(grph, node_process, tuple):
	try:
		LogMsg("parse_recvfrom"+str(tuple))
		sock_text = tuple[6]
	except IndexError:
		return
	socketNode = ParseSockAddrFromTcpDump( sock_text )
	if socketNode:
		grph.add( ( node_process, pc.property_has_socket, socketNode ) )

# [pid  8263] connect(50, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("54.230.3.49")}, 16) = 0
# [pid  8263] connect(50, {sa_family=AF_UNSPEC, sa_data="\0\0\0\0\0\0\0\0\0\0\0\0\0\0"}, 16) = 0
def parse_connect(grph, node_process, tuple):
	try:
		LogMsg("parse_connect"+str(tuple))
		sock_text = tuple[3]
	except IndexError:
		return
	socketNode = ParseSockAddrFromTcpDump( sock_text )
	if socketNode:
		grph.add( ( node_process, pc.property_has_socket, socketNode ) )

# [pid  7626] getpeername(59, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("199.16.156.230")}, [16]) = 0
def parse_getpeername(grph, node_process, tuple):
	try:
		LogMsg("parse_getpeername"+str(tuple))
		sock_text = tuple[3]
	except IndexError:
		return
	socketNode = ParseSockAddrFromTcpDump( sock_text )
	if socketNode:
		grph.add( ( node_process, pc.property_has_socket, socketNode ) )


# bind(70, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12)
def parse_bind(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# getsockname(70, {sa_family=AF_NETLINK, pid=7506, groups=00000000}, [12])
def parse_getsockname(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# sendto(70, "\24\0\0\0\26\0\1\3&\236\315S\0\0\0\0\0\0\0\0", 20, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12)
def parse_sendto(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# recvmsg(70, {msg_name(12)={sa_family=AF_NETLINK, pid=0, groups=00000000}, msg_iov(1)=[{"0\0\0\0\24\0\2\0&\236\315SR\35\0\0\2\10\200\376\1\0\0\0\10\0\1\0\177\0\0\1\10\0\2\0\177\0\0\1\7\0\3\0lo\0\0<\0\0\0\24\0\2\0&\236\315SR\35\0\0\2\30\200\0\3\0\0\0\10\0\1\0\300\250\1D\10\0\2\0\300\250\1D\10\0\4\0\300\250\1\377\t\0\3\0"..., 4096}], msg_controllen=0, msg_flags=0}, 0)
def parse_recvnsg(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# socket(PF_NETLINK, SOCK_RAW, 0)
def parse_socket(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# recv(48, 0xb52ff0fb, 1, MSG_PEEK)
def parse_recv(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# send(48, "GET /utils/Receiver.js HTTP/1.1\r\nHost: c5.zedo.com\r\nUser-Agent: Mozilla/5.0 (X11; U; Linux i686; fr;"..., 713, 0)
def parse_send(grph, node_process, tuple):
	# TODO: Adds a RDF node, otherwise this function is useless.
	return

# Map the inputs to the function blocks
# We should add all functions which might create RDF data, but more
# functions do not harm.
func_parsers = {
	"recvfrom"    : parse_recvfrom,
	"connect"     : parse_connect,
	"getpeername" : parse_getpeername,
	"bind"        : parse_bind,
	"getsockname" : parse_getsockname,
	"sendto"      : parse_sendto,
	"socket"      : parse_socket,
	"recv"        : parse_recv,
	"send"        : parse_send,
}

################################################################################
#
# Lors de l'ouverture d'une session HTTP vers www.google.it = 173.194.41.88, 
#  et autres adresses 173.194.41.x, voici quelques trames interessantes:
#
# socket(PF_INET, SOCK_DGRAM, IPPROTO_IP) = 55
# connect(55, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}, 28) = 0
# send(55, "\273Y\1\0\0\1\0\0\0\0\0\0\3www\6google\2it\0\0\34\0\1", 31, MSG_NOSIGNAL) = 31
# recvfrom(55, "\273Y\201\200\0\1\0\1\0\0\0\0\3www\6google\2it\0\0\34\0\1\300\f\0\34\0\1\0\0\0\236\0\20*\0\24P@\t\10\t\0\0\0\0\0\0\20\30", 1024, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}, [16]) = 59
# socket(PF_INET, SOCK_DGRAM, IPPROTO_IP) = 55
# C'est le gateway aupres duquel on a fait une requete DNS, port=53.
# connect(55, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}, 28) = 0
# send(55, "\260\345\1\0\0\1\0\0\0\0\0\0\3www\6google\2it\0\0\1\0\1", 31, MSG_NOSIGNAL) = 31
# Serait-ce le retour de la requete DNS, contenant plusieurs adresses ?
# recvfrom(55, "\260\345\201\200\0\1\0\4\0\0\0\0\3www\6google\2it\0\0\1\0\1\300\f\0\1\0\1\0\0\0\357\0\4\255\302)\177\300\f\0\1\0\1\0\0\0\357\0\4\255\302)w\300\f\0\1\0\1\0\0\0\357\0\4\255\302)o\300\f\0\1\0\1\0\0\0\357\0\4\255\302)x", 1024, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}, [16]) = 95
# Suivent plusieurs essais apparemment infructueux...
# socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 55
# connect(55, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("173.194.41.127")}, 16) = -1 EINPROGRESS (Operation now in progress)
# getsockopt(55, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
# send(55, "GET / HTTP/1.1\r\nHost: www.google.it\r\n ... "..., 377, 0) = 377
#
# Notons que la partie reseau peut probablement etre mieux analysee
# avec tcpdump car c'est fait pour. De plus, il faudrait, si une analyse
# dure sur plusieurs appeles, construire un objet qui contiendrait un historique.
# Peut-etre aussi faciliter l'ajout de plugins relatifs a une fonction.

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def STraceDeserialize( log_strm, grph, tuple):
	node_process = lib_common.gUriGen.PidUri(tuple[0])
	func = tuple[1]
	func_parsers[ func ]( grph, node_process, tuple )

	# This shows that the process has called this function,
	# but this shows only the functions which were kept,
	# so this is a bit experimental.
	# TODO: The library or the executable should be added !!
	# Luckily these are only system calls, so no ambiguity.
	node_func = lib_common.gUriGen.SymbolUri( func )
	grph.add( ( node_process, pc.property_calls, node_func ) )

################################################################################

# This parse the list of arguments separated by top-level commas,
# avoiding but commas between brackets or quotes.
def ParseArgs(args):
	# print("ParseArgs<-"+args)
	nbBracket = 0
	escaped = False
	vecArgs = []
	curr = ""
	for ch in args:
		if escaped:
			curr += ch
			escaped = False
			continue

		if ch == '\\':
			escaped = True
			continue

		if ch == '{':
			nbBracket += 1
		elif ch == '}':
			nbBracket -= 1
		elif ( ch == ',' ) and ( nbBracket == 0 ):
			vecArgs.append(curr.strip())
			curr = ""
			continue

		curr += ch

	# Add the last word.
	if curr != "":
		vecArgs.append(curr.strip())

	# print("ParseArgs->"+str(vecArgs))
	return vecArgs

# Unix only for the moment. Think about dtrace and ltrace.
# strace -f -F -v   -s100  -e trace=file -e trace=process -e trace=ipc -e trace=network -p 7681 2>&1 | grep -vw poll
# [pid  7609] recv(66, 0xb52ff0bb, 1, MSG_PEEK) = -1 EAGAIN (Resource temporarily unavailable)
# [pid  7755] socket(PF_NETLINK, SOCK_RAW, 0) = 66
# [pid  7755] bind(66, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 0
# [pid  7755] getsockname(66, {sa_family=AF_NETLINK, pid=7593, groups=00000000}, [12]) = 0
# [pid  7755] sendto(66, "\24\0\0\0\26\0\1\3\363\215\260S\0\0\0\0\0\0\0\0", 20, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 20
# [pid  7755] recvmsg(66, {msg_name(12)={sa_family=AF_NETLINK, pid=0, groups=00000000}, msg_iov(1)=[{"0\0\0\0\24\0\2\0\363\215\260S\251\35\0\0\2\10\200\376\1\0\0\0\10\0\1\0\177\0\0\1\10\0\2\0\177\0\0\1\7\0\3\0lo\0\0<\0\0\0\24\0\2\0\363\215\260S\251\35\0\0\2\30\200\0\2\0\0\0\10\0\1\0\300\250\1D\10\0\2\0\300\250\1D\10\0\4\0\300\250\1\377\t\0\3\0"..., 4096}], msg_controllen=0, msg_flags=0}, 0) = 108

def STraceEngine(sharedTupleQueue,entityId):
	global logFil
	logTmp = lib_common.TmpFile("strace","log")
	logFil = open( logTmp.Name, "w" )

	LogMsg("STraceEngine: entityId=" + str(entityId) )

	# Maybe the process is not running, or the pid is not an integer.
	try:
		pidOk = psutil.pid_exists( int(entityId) )
	except TypeError:
		pidOk = False

	if not pidOk:
		LogMsg("STraceEngine: entityId=" + str(entityId) + " not running")
		return "STraceEngine: Invalid process id:" + str(entityId)

	# This reduces the quantity of data.
	expressions = " -e trace=file -e trace=process -e trace=ipc -e trace=network "
	options = "-f -F -v -s100 " + expressions + " -p " + entityId
	# strace_cmd = "strace " + options + " 2>&1 | grep -vw poll"
	# strace_cmd = "strace " + options
	strace_cmd = "strace " + options + " 2>&1"
	LogMsg("STraceEngine: command=" + strace_cmd )

	# TODO: Must reach the end of line.
	# callRegex = r'\[pid ([^).*) ([^ ]*)\((.*)\) = [0-9]*'
	callRegex = r'\[pid ([^]]*)\] ([^(]*)\((.*)\) = [0-9]*'

	for lin in os.popen(strace_cmd):
		if not lin:
			LogMsg("STraceEngine: leaving execution loop" )
			break

		# TODO: What happens if we get.
		# Trace=attach: ptrace(PTRACE_ATTACH, ...): Operation not permitted
		LogMsg( "STraceEngine Lin=" + lin )


		if re.match( ".*Operation not permitted.*", lin ):
			LogMsg("STraceEngine: Operation not permitted" )
			return "STraceEngine: Operation not permitted pid=" + entityId
			

		matchCall = re.match( callRegex, lin, re.M|re.I)
		if not matchCall:
			continue

		# All the function calls are gathered under the same process,
		# even if this is the parent process. Could be a parameter.
		# Or we can carefully specify the actual process id.
		pid = matchCall.group(1)

		# Example: "getsockname"
		funcName = matchCall.group(2)

		# TODO: Later on we might store all functions calls to build or complete the call graph.
		# For the moment this just keeps track of functions calls
		# whose arguments can be parsed and whose results can generate
		# interesting RDF data.
		if not funcName in func_parsers:
			LogMsg( "Unknown function=" + lin )
			continue

		# Example: "66, {sa_family=AF_NETLINK, pid=7593, groups=00000000}, [12]"
		args = matchCall.group(3)

		vecArgs = ParseArgs( args )

		# The entity is the process id.
		lstResult = [ entityId, funcName ] + vecArgs

		# This builds a tuple from a list.
		sharedTupleQueue.put( tuple( lstResult ) )

	# TODO: IL FAUDRAIT LAISSER UN MESSAGE POUR LE PROCESS LECTEUR.
	# PEUT ETRE QIE CONVENTIONNELLEMENT, SI ON LAISSE DANS LA QUEUE 
	# AUTRE CHSOE QU UN TUPLE, C EST UN MESSAGE ???
	LogMsg( "Leaving." )

	return "THIS IS AN ERROR AND LEAVING MESSAGE"

################################################################################

# Pour tester, utiliser le process qui execute firefox-bin
# car il nous appartient et de plus est tres actif.

if __name__ == '__main__':
	lib_webserv.DoTheJob(STraceEngine,STraceDeserialize,__file__,"strace stack trace","LAYOUT_RECT")

