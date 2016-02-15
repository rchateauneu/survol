#!/usr/bin/python
 
import sys
from twisted.internet import reactor, task
from twisted.internet.protocol import DatagramProtocol

SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900

MY_ADDR='0.1.2.3'
MY_PORT=8080

class Notify(DatagramProtocol):
 
	def stop(self):
		pass
 
	def __init__(self, iface):
		self.iface = iface
		print "iface=" + str(iface)
		task.LoopingCall(self.send_notify).start(10) # every X seconds
 
	def send_notify(self):
		# NOTIFY * HTTP/1.1
		# HOST: 239.255.255.250:1900
		# SERVER: OpenRG/4.7.5.1.83.8.94.1.11 UPnP/1.0
		# CACHE-CONTROL: max-age=1800
		# LOCATION: http://192.168.1.254:2555/dslforum/UPnP_BThomeHub3.0A_c0ac54d00e28/desc.xml
		# NTS: ssdp:alive
		# NT: urn:dslforum-org:service:DeviceInfo:1
		# USN: uuid:UPnP_BThomeHub3.0A_c0ac54d00e28::urn:dslforum-org:service:DeviceInfo:1

		NOTIFY = \
		'NOTIFY * HTTP/1.1\r\n' \
		'HOST: 239.255.255.250:1900\r\n' \
		'SERVER: Tralala/2001 UPnP/1.0 product/1.1\r\n' \
		'CACHE-CONTROL: max-age=10\r\n' \
		'LOCATION: http://192.168.1.254:2555/dslforum/UPnP_BThomeHub3.0A_c0ac54d00e28/desc.xml\r\n' \
		'NTS: ssdp:alive\r\n' \
		'NT: urn:dslforum-org:service:DeviceInfo:1\r\n' \
		'USN: uuid:UPnP_BThomeHub3.0A_c0ac54d00e28::urn:dslforum-org:service:DeviceInfo:1\r\n\r\n'

		NOTIFY2 = \
		'NOTIFY * HTTP/1.1\r\n' \
		'HOST: 239.255.255.250:1900\r\n' \
		'CACHE-CONTROL: max-age=10\r\n' \
		'LOCATION: http://%s:%d/services.xml\r\n' \
		'NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n' \
		'NTS: ssdp:alive\r\n' \
		'Content-Length: 0\r\n' \
		'SERVER: Tralala/2001 UPnP/1.0 product/1.1\r\n' \
		'USN: uuid:TsoinTsoin\r\n\r\n' % (MY_ADDR, MY_PORT)

		port = reactor.listenUDP(0, self, interface=self.iface)
		print "Sending NOTIFY..."
		port.write(NOTIFY, (SSDP_ADDR, SSDP_PORT))
		reactor.callLater(2.5, port.stopListening) # MX + a wait margin
 
def main(iface):
	print "iface=" + str(iface)
	obj = Notify(iface)
	reactor.addSystemEventTrigger('before', 'shutdown', obj.stop)



if __name__ == "__main__":
	if len(sys.argv) != 2:
		print( "Usage: %s <IP of interface>" % (sys.argv[0], ) )
		sys.exit(1)
	MY_ADDR = sys.argv[1]

	reactor.callWhenRunning(main, MY_ADDR)
	reactor.run()
