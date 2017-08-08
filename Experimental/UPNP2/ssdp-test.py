#!/usr/bin/python
 
# Python program that can send out M-SEARCH messages using SSDP (in server
# mode), or listen for SSDP messages (in client mode).
 
import sys
from twisted.internet import reactor, task
from twisted.internet.protocol import DatagramProtocol

# http://developer.lgappstv.com/TV_HELP/index.jsp?topic=%2Flge.tvsdk.references.book%2Fhtml%2FUDAP%2FUDAP%2FM+SEARCH+Request.htm
# M-SEARCH * HTTP/1.1
# HOST: 239.255.255.250:1900
# MAN: "ssdp:discover"
# MX: Maximum time (in seconds) to wait for response of host
# ST: URN value of service to search
# USER-AGENT: OS/versionUDAP/2.0product/version

# Response:
# HTTP/1.1 200 OK
# CACHE-CONTROL: max-age = available time (in seconds) that Controller can communication with Host
# DATE: Time when the response is occurred
# EXT:
# LOCATION: HTTP that service can get description
# SERVER: OS/versionUDAP/2.0product/version
# ST: ST value that Controller requested
# USN: composite identifier of M-SEARCH response


# HTTP/1.1 200 OK from ('192.168.1.254', 1900)
# HTTP/1.1 200 OK
# DATE: Sun, 13 Oct 2013 13:20:13 GMT
# SERVER: OpenRG/4.7.5.1.83.8.94.1.11 UPnP/1.0
# CACHE-CONTROL: max-age=1800
# LOCATION: http://192.168.1.254:2555/dslforum/UPnP_BThomeHub3.0A_c0ac54d00e28/desc.xml
# EXT:
# ST: urn:dslforum-org:device:LANDevice:1
# USN: uuid:UPnP_BThomeHub3.0A_c0ac54d00e28_br0::urn:dslforum-org:device:LANDevice:1



SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900
 
MS = 'M-SEARCH * HTTP/1.1\r\nHOST: %s:%d\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' % (SSDP_ADDR, SSDP_PORT)
# MS = 'M-SEARCH * HTTP/1.1\r\nHOST: %s:%d\r\nMAN: "ssdp:tagada"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' % (SSDP_ADDR, SSDP_PORT)

class Base(DatagramProtocol):
	def datagramReceived(self, datagram, address):
		first_line = datagram.rsplit('\r\n')[0]
		print "Received %s from %r" % (first_line, address, )

		split_line = datagram.rsplit('\r\n')
		for lin in split_line:
			print "    Received %s" % lin
 
	def stop(self):
		pass
 
class Server(Base):
	def __init__(self, iface):
		self.iface = iface
		task.LoopingCall(self.send_msearch).start(10) # every X seconds
 
	def send_msearch(self):
		port = reactor.listenUDP(0, self, interface=self.iface)
		print "Sending M-SEARCH..."
		port.write(MS, (SSDP_ADDR, SSDP_PORT))
		reactor.callLater(2.5, port.stopListening) # MX + a wait margin
 
class Client(Base):
	def __init__(self, iface):
		self.iface = iface
		self.ssdp = reactor.listenMulticast(SSDP_PORT, self, listenMultiple=True)
		self.ssdp.setLoopbackMode(1)
		self.ssdp.joinGroup(SSDP_ADDR, interface=iface)
 
	def stop(self):
		self.ssdp.leaveGroup(SSDP_ADDR, interface=self.iface)
		self.ssdp.stopListening()
 
def main(mode, iface):
	klass = Server if mode == 'server' else Client
	obj = klass(iface)
	reactor.addSystemEventTrigger('before', 'shutdown', obj.stop)
 
if __name__ == "__main__":
	if len(sys.argv) != 3:
		print "Usage: %s <server|client> <IP of interface>" % (sys.argv[0], )
		sys.exit(1)
	mode, iface = sys.argv[1:]
	reactor.callWhenRunning(main, mode, iface)
	reactor.run()
