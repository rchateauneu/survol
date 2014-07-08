#!/usr/bin/python

import lib_common

import os
import cgi
import psutil
import rdflib
from lib_common import pc

import lib_webserv


# NOT TESTED YET
# NOT TESTED YET
# NOT TESTED YET
# NOT TESTED YET
# NOT TESTED YET



################################################################################

# {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}
# {sa_family=AF_UNSPEC, sa_data="\0\0\0\0\0\0\0\0\0\0\0\0\0\0"}
def ParseSockAddrFromTcpDump( sock_addr ):
	regexSockAddr = r'{sa_family=([^,]*), sin_port=htons\(([0-9])\), sin_addr=inet_addr\("([^"]*)"\)}'

	matchSockAddr = re.match( regexSockAddr, sock_addr, re.M|re.I)
	if matchSockAddr:
		if matchSockAddr.group(1) == "AF_INET":
			return lib_common.AddrUri( matchSockAddr.group(3), matchSockAddr.group(2) )
	return None


# [pid  8263] recvfrom(50, "DH\201\200\0\1\0\10\0\0\0\0\16d36aw3ue2ntmsq\ncloudfront\3net\0\0\1\0\1\300\f\0\1\0\1\0\0\0<\0\0046\346\0031\300\f\0\1\0\1\0\0\0<\0\0046\346\3\201\300\f\0\1\0\1\0\0\0<\0\0046\346\0G\300\f\0\1\0"..., 1024, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.254")}, [16]) = 175
def parse_recvfrom(grph, node_process, tuple):
	try:
		sock_text = tuple[6]
	except IndexError
		return
	socketNode = ParseSockAddrFromTcpDump( sock_text )
	if socketNode:
		grph.add( ( node_process, pc.property_has_socket_end, socketNode ) )


# [pid  8263] connect(50, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("54.230.3.49")}, 16) = 0
# [pid  8263] connect(50, {sa_family=AF_UNSPEC, sa_data="\0\0\0\0\0\0\0\0\0\0\0\0\0\0"}, 16) = 0
def parse_connect(grph, node_pid, tuple):
	try:
		sock_text = tuple[4]
	except IndexError
		return
	socketNode = ParseSockAddrFromTcpDump( sock_text )
	if socketNode:
		grph.add( ( node_process, pc.property_has_socket_end, socketNode ) )



# map the inputs to the function blocks
func_parsers = {
	"recvfrom" : parse_recvfrom,
	"connect"  : parse_connect,
}

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def STraceDeserialize(grph, tuple):
	node_process = lib_common.PidUri(tuple[0])
	func = tuple[1]
	func_parsers[ func ]( grph, node_process, tuple )

################################################################################

# This parse the list of arguments separated by top-level commas,
# avoiding but commas between brackets or quotes.
def ParseArgs(args):
	nbBracket = 0
	escaped = False
	vecArgs = []
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
		elif ch == '{':
			nbBracket -= 1
		elif ch == ',':
			if nbBracket == 0:
				vecArgs += curr
				curr = ""
				continue

		curr += ch




# Unix only for the moment. Think about dtrace and ltrace.
# strace -f -F -v   -s100  -e trace=file -e trace=process -e trace=ipc -e trace=network -p 7681 2>&1 | grep -vw poll
# [pid  7609] recv(66, 0xb52ff0bb, 1, MSG_PEEK) = -1 EAGAIN (Resource temporarily unavailable)
# [pid  7755] socket(PF_NETLINK, SOCK_RAW, 0) = 66
# [pid  7755] bind(66, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 0
# [pid  7755] getsockname(66, {sa_family=AF_NETLINK, pid=7593, groups=00000000}, [12]) = 0
# [pid  7755] sendto(66, "\24\0\0\0\26\0\1\3\363\215\260S\0\0\0\0\0\0\0\0", 20, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 20
# [pid  7755] recvmsg(66, {msg_name(12)={sa_family=AF_NETLINK, pid=0, groups=00000000}, msg_iov(1)=[{"0\0\0\0\24\0\2\0\363\215\260S\251\35\0\0\2\10\200\376\1\0\0\0\10\0\1\0\177\0\0\1\10\0\2\0\177\0\0\1\7\0\3\0lo\0\0<\0\0\0\24\0\2\0\363\215\260S\251\35\0\0\2\30\200\0\2\0\0\0\10\0\1\0\300\250\1D\10\0\2\0\300\250\1D\10\0\4\0\300\250\1\377\t\0\3\0"..., 4096}], msg_controllen=0, msg_flags=0}, 0) = 108

def STraceEngine(sharedTupleQueue,entityId):
	# This reduces the quantity of data.
	expressions = " -e trace=file -e trace=process -e trace=ipc -e trace=network "
	options = "-f -F -v -s100 " + expressions + " -p " + entityId
	strace_cmd = "strace " + options + " 2>&1 | grep -vw poll"
	print("TCPcommand=" + tcpdump_cmd)

	# TODO: Must reach the end of line.
	callRegex = r'(.*) ([^ ]*)\((.*)\) = [0-9]*'

	for lin in os.popen(strace_cmd):
		if not lin:
			break
		matchCall = re.match( callRegex, lin, re.M|re.I)
		if not matchCall:
			continue

		# Example: "getsockname"
		func = matchCall.group(1)

		# TODO: Later on we might store all functions calls to build or complete the call graph.
		# For the moment this just keeps track of functions calls whose arguments can be parsed.
		if not func in func_parsers:
			continue

		# Example: "66, {sa_family=AF_NETLINK, pid=7593, groups=00000000}, [12]"
		args = matchCall.group(2)

		vecArgs = ParseArgs( args )

		# The entity is the process id.
		lstResult = [ entityId, func ] + vecArgs

		# This builds a tuple from a list.
		theQ.put( tuple( lstResult ) )

################################################################################

# Conventional port number for TCP dump RDF generation.
STracePort = 34567

if __name__ == '__main__':
	lib_webserv.DoTheJob(STraceEngine,STracePort,STraceDeserialize,__file__)




