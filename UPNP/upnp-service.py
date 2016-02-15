#!/usr/bin/python
 
# Python program that can send out M-SEARCH messages using SSDP (in server
# mode), or listen for SSDP messages (in client mode).
 
import sys
import socket
import re
from twisted.internet import reactor, task, defer
from twisted.internet.protocol import DatagramProtocol
 
SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900

MY_ADDR='0.1.2.3'
MY_PORT=8080


def bytes(str,enc):
	return str

gblsrv=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
gblsrv.bind( ('',SSDP_PORT ) )

class Helloer(DatagramProtocol):
    def __init__(self, host, port, msg ):
         self.m_host = host
	 self.m_port = port
	 self.m_msg = msg

    def startProtocol(self):

        self.transport.connect(self.m_host, self.m_port)
        print "can only send to %s / %d" % (self.m_host, self.m_port)
        # self.transport.write(self.m_msg)

	global M_ADDR
	global SSDP_PORT

	input_addr = [ MY_ADDR, SSDP_PORT ]
	print "Send from %s %d" % ( input_addr[0], input_addr[1] )

	try:
        	self.transport.write(self.m_msg, input_addr)
		print "Sending:", self.m_msg
	except AssertionError, e:
			print "Except:",e

    def datagramReceived(self, data, (host, port)):
        print "received %r from %s:%d" % (data, host, port)

    def connectionRefused(self):
        print "No one listening"

class UDPsender(DatagramProtocol):
     def __init__(self, onStart):
         self.onStart = onStart

     def startProtocol(self):
         print "StartProtocol"
         self.onStart.callback(self)

     def sendMsg(self, data, address):
         self.transport.write( bytes(data, 'UTF-8'), address)

class DatagramSender(object):
     def start(self):
         d = defer.Deferred()
         d.addCallback(self._listening)
         self._port = reactor.listenUDP(0, UDPsender(d))

     def _listening(self, proto):
         global myProto
         myProto = proto

     def sendMsg(self, data, address):
         global myProto
         myProto.sendMsg(data, address)

     def stop(self):
         self._call.stop()
         self._port.stopListening()

class Client(DatagramProtocol):
    def __init__(self, iface):
        self.iface = iface
        self.ssdp = reactor.listenMulticast(SSDP_PORT, self, listenMultiple=True)
        self.ssdp.setLoopbackMode(1)
        self.ssdp.joinGroup(SSDP_ADDR, interface=iface)
 
    def stop(self):
        self.ssdp.leaveGroup(SSDP_ADDR, interface=self.iface)
        self.ssdp.stopListening()
 
    def datagramReceived(self, datagram, address):
	global SSDP_PORT
        arr_split = datagram.rsplit( bytes('\r\n', 'UTF-8') )
	print("Received from:" , address)
        for lin in datagram.rsplit( bytes('\r\n', 'UTF-8') ):
            print( "    %s" % lin )

        first_bytes = datagram.rsplit( bytes('\r\n', 'UTF-8') )[0]
        # print( "Header:%s" % first_bytes )
        # first_line = str( first_bytes, 'UTF-8')
        first_line = str( first_bytes )

        # print( "port:%d", first_bytes )

        if re.match( r'M-SEARCH.*', first_line ) :
            RESPONSE1 = \
                "HTTP/1.1 200 OK\r\n" \
                "CACHE-CONTROL:max-age=1800\r\n" \
                "EXT: \r\n" \
                "LOCATION:http://%s:%d/services.xml\r\n" \
                "SERVER: EditParams\r\n" \
                "ST: urn:schemas-upnp-org:service:EdtPrm:1\r\n" \
                "USN: uuid:Abcdefgh::urn:schemas-upnp-org:service:EdtPrm:1\r\n\r\n"  % (MY_ADDR, MY_PORT)

		# HTTP/1.1 200 OK
		# DATE: Sat, 19 Oct 2013 16:42:50 GMT
		# SERVER: OpenRG/4.7.5.1.83.8.94.1.11 UPnP/1.0
		# CACHE-CONTROL: max-age=1800
		# LOCATION: http://192.168.1.254:2555/dslforum/UPnP_BThomeHub3.0A_c0ac54d00e28/desc.xml
		# EXT:
		# ST: urn:dslforum-org:service:LANEthernetInterfaceConfig:1
		# USN: uuid:UPnP_BThomeHub3.0A_c0ac54d00e28_br0::urn:dslforum-org:service:LANEthernetInterfaceConfig:1

            RESPONSE1 = \
		"HTTP/1.1 200 OK\r\n" \
		"DATE: Sat, 19 Oct 2013 16:42:50 GMT\r\n" \
		"SERVER: TAGADA OpenRG/4.7.5.1.83.8.94.1.11 UPnP/1.0\r\n" \
		"CACHE-CONTROL: max-age=1800\r\n" \
		"LOCATION: http://192.168.1.254:2555/dslforum/UPnP_BThomeHub3.0A_c0ac54d00e28/desc.xml\r\n" \
		"EXT:\r\n" \
		"ST: urn:dslforum-org:service:LANEthernetInterfaceConfig:1\r\n" \
		"USN: uuid:UPnP_BThomeHub3.0A_c0ac54d00e28_br0::urn:dslforum-org:service:LANEthernetInterfaceConfig:1\r\n\r\n"



	    print("Sending to ", address )
            # answer = Server(self.iface,address)
            # ds = DatagramSender()

            # ds = UDPsender()
            # ds.start()
            # ds.sendMsg(RESPONSE1, address)

            #hel = Helloer( address[0], address[1], RESPONSE1 )
	    #reactor.listenUDP(0, hel )

	    print("Sent to ", address)

            global gblsrv
	    gblsrv.sendto( RESPONSE1, address )
	    print "serveur actif"
            # reactor.run()
        # reactor.addSystemEventTrigger('before', 'shutdown', answer.stop)

 
def main(iface):
    obj = Client(iface)
    reactor.addSystemEventTrigger('before', 'shutdown', obj.stop)
 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print( "Usage: %s <IP of interface>" % (sys.argv[0], ) )
        sys.exit(1)
    MY_ADDR = sys.argv[1]
    reactor.callWhenRunning(main, MY_ADDR)
    reactor.run()
