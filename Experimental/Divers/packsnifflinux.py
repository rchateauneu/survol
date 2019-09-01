#!/usr/bin/env python

import struct
import sys
import time
import os
import socket
import binascii
import pwd
import subprocess

def PrintIp(title,addr):
	try:
		host = socket.gethostbyaddr(addr)
		print("%s: %s %s" % ( title, addr, host[0] ) )
	except:
		exc = sys.exc_info()[1]
		print("%s: %s Caught: %s" % ( title, addr, exc ) )

def ThePort(hdr):
	return 256 * ord(hdr[0]) + ord(hdr[1])

def DoStuff():
	rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
	
	while True:
		#ifconfig eth0 promisc up
		receivedPacket=rawSocket.recv(2048)
	
		#Ethernet Header...
		ethernetHeader=receivedPacket[0:14]
		ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
		destinationIP= binascii.hexlify(ethrheader[0])
		sourceIP= binascii.hexlify(ethrheader[1])
		protocol= binascii.hexlify(ethrheader[2])
	
		# print("Destination: " + destinationIP)
		# print("Source: " + sourceIP)
		print("Protocol: "+ protocol)
	
		#IP Header... 
		ipHeader=receivedPacket[14:34]
		ipHdr=struct.unpack("!12s4s4s",ipHeader)
		destinationIP=socket.inet_ntoa(ipHdr[2])
		sourceIP=socket.inet_ntoa(ipHdr[1])
		PrintIp("Source:" , sourceIP)
		PrintIp("Destination:", destinationIP)
	
		#TCP Header...
		tcpHeader=receivedPacket[34:54]
		tcpHdr=struct.unpack("!2s2s16s",tcpHeader)
		try:
			time.sleep(1)
			# print("tcp1:%s" % str(tcpHdr[0]))
			# print("tcp2:%d" % int(tcpHdr[0]))
			# print("tcp3:%d" % tcpHdr[0].decode('hex') )
			sourcePort = ThePort(tcpHdr[0])
			# print("tcp4:%d" % sourcePort )
			# sourcePort=socket.inet_ntoa(tcpHdr[0])
	
			# sourcePort=socket.inet_ntoa( hex(tcpHdr[0])[2:].zfill(8).decode('hex') )
			# sourcePort=socket.inet_ntoa( int(tcpHdr[0]) )
			# sourcePort=socket.inet_ntoa( tcpHdr[0].zfill(8).decode('hex') )
	
			print("Source Port:%d" % sourcePort)
			# destinationPort=socket.inet_ntoa(tcpHdr[1])
			# destinationPort=socket.inet_ntoa(tcpHdr[1])
			destinationPort=ThePort(tcpHdr[1])
			print("Destination Port:%d" % destinationPort)
		except Exception:
			exc = sys.exc_info()[1]
			print("Caught:%s" % str(exc) )
	




def main(my_args=None):
	if my_args is None:
		my_args = sys.argv[1:]
	user_name, cwd = my_args[:2]
	args = my_args[2:]
	pw_record = pwd.getpwnam(user_name)
	user_name = pw_record.pw_name
	user_home_dir = pw_record.pw_dir
	user_uid = pw_record.pw_uid
	user_gid = pw_record.pw_gid
	env = os.environ.copy()
	env[ 'HOME'	 ]  = user_home_dir
	env[ 'LOGNAME'  ]  = user_name
	env[ 'PWD'	  ]  = cwd
	env[ 'USER'	 ]  = user_name
	report_ids('starting ' + str(args))
	the_func=demote(user_uid, user_gid)
	process = subprocess.Popen( args, preexec_fn=the_func, cwd=cwd, env=env)
	result = process.wait()
	report_ids('finished ' + str(args))
	print 'result', result


def demote(user_uid, user_gid):
	def result():
		report_ids('starting demotion')
		os.setgid(user_gid)
		report_ids('Now UID')
		os.setuid(user_uid)
		report_ids('finished demotion')
	return result


def report_ids(msg):
	print 'uid, gid = %d, %d; %s' % (os.getuid(), os.getgid(), msg)

# ./packsnifflinux.py root . ./packsnifflinux.py

if __name__ == '__main__':
	if len(sys.argv) == 1 :
		DoStuff()
	else:
		report_ids("Args="+str(sys.argv))
		main()
