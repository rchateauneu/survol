#!/usr/bin/python
 
# Python program that can send out M-SEARCH messages using SSDP (in server
# mode), or listen for SSDP messages (in client mode).
 
import socket
import binascii
import signal
import sys
import re
 
SSDP_GRP_ADDR = '239.255.255.250'
SSDP_PORT = 1900
#SSDP_ADDR = '224.1.1.1'
#SSDP_PORT = 1900

# Reconnu par personne.
# "ST: urn:schemas-upnp-org:service:XYZ_Connection:1\r\n"

# "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" \

# Il faut mettre le bon ST pour etre detecte par "Intel Device Sniffer".

 
def ProcessLoop(iface):
     RESPONSE_InternetGatewayDevice = \
          "HTTP/1.1 200 OK\r\n" \
          "CACHE-CONTROL: max-age=1800\r\n" \
          "DATE: Wed Jul 11 05:55:53 2012 GMT\r\n" \
          "EXT: \r\n" \
          "LOCATION: http://%s:%d/rev_description.xml\r\n" \
          "SERVER: POSIX, UPnP/1.0 linux/5.100.104.2\r\n" \
          "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" \
          "USN: uuid:Abcdefgh::urn:schemas-upnp-org:service:XYZ_Connection:1\r\n\r\n"  % (iface, 8000)

     RESPONSE_WFADevice = \
          "HTTP/1.1 200 OK\r\n" \
          "CACHE-CONTROL: max-age=1800\r\n" \
          "DATE: Wed Jul 11 05:55:53 2012 GMT\r\n" \
          "EXT: \r\n" \
          "LOCATION: http://%s:%d/rev_description.xml\r\n" \
          "SERVER: POSIX, UPnP/1.0 linux/5.100.104.2\r\n" \
          "ST: urn:schemas-wifialliance-org:device:WFADevice:1\r\n" \
          "USN: uuid:Abcdefgh::urn:schemas-upnp-org:service:XYZ_Connection:1\r\n\r\n"  % (iface, 8000)


     # Detected
     #RESPONSE_XXX = \
     #     "HTTP/1.1 200  OK\r\n" \
     #     "ST:  urn:schemas-upnp-org:service:XXX:1\r\n" \
     #     "USN:  uuid:bf75a4d6-a617-450e-bed8-08c4a22808bf::urn:schemas-upnp-org:service:XXX:1\r\n" \
     #     "EXT:  \r\n" \
     #     "CACHE-CONTROL:  max-age=900\r\n" \
     #     "SERVER:  Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n" \
     #     "LOCATION:  http://10.102.3.173:62968/\r\n" \
     #     "Content-Length: 0\r\n" \
     #     "\r\n"

     RESPONSE_XXX = \
          "HTTP/1.1 200  OK\r\n" \
          "ST:  urn:schemas-upnp-org:service:XXX:1\r\n" \
          "USN:  uuid:bf75a4d6-a617-450e-bed8-08c4a22808bf::urn:schemas-upnp-org:service:XXX:1\r\n" \
          "EXT:  \r\n" \
          "CACHE-CONTROL:  max-age=900\r\n" \
          "SERVER:  Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n" \
          "LOCATION:  http://%s:%d/rev_description.xml\r\n" \
          "Content-Length: 0\r\n" \
          "\r\n"  % (iface, 8000)



     # This creates a UDP socket.
     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
     try:
          # Allow multiple sockets to use the same PORT number
          # We will need that if several processes are data providers.
          sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
     except AttributeError:
           pass

     # On Windows, I get "[Errno 10049] The requested address is not valid in its context"
     # sock.bind((SSDP_GRP_ADDR, SSDP_PORT))
     sock.bind(('0.0.0.0', SSDP_PORT))

     # No need, to set multicast ttl on the receiver. Only for sender, and optional.
     # sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
     sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

     host = socket.gethostbyname(socket.gethostname())
     print("host=%s" % host)
     #sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
     #sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(SSDP_GRP_ADDR) + socket.inet_aton(host))
     sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(SSDP_GRP_ADDR) + socket.inet_aton(host))

     while 1:
          print("Message wait")
          try:
               data, addr = sock.recvfrom(1024)
          except socket.error, e:
               print( 'Exception', e )
          hexdata = binascii.hexlify(data)
          print( 'Addr=%s', addr )
          #print( 'Data = %s' % data )
          #print( 'hexdata = %s' % hexdata )
          #print( 'strData = %s' % str(data) )
          decod_str = data.decode("utf-8")
          print( 'decode = %s' % decod_str )

          if re.match( r'M-SEARCH.*', decod_str ) :
              print( "Sending answer to %s:%d" % addr )

              # sock.sendto( RESPONSE.encode("utf-8"), addr )

              # sockanswer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
              sockanswer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              sockanswer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              # sockanswer.bind(('0.0.0.0', 3333))
              #######################sockanswer.bind(('0.0.0.0', 1900))
              # sockanswer.bind(('localhost', 3333))
              sockanswer.sendto( RESPONSE_InternetGatewayDevice.encode("utf-8"), addr )
              sockanswer.sendto( RESPONSE_WFADevice.encode("utf-8"), addr )
              sockanswer.sendto( RESPONSE_XXX.encode("utf-8"), addr )
              

              # Do not close too early otherwise nothing is sent.
              # sockanswer.close()

def signal_handler(signal, frame):
     print('You pressed Ctrl+C!')
     sys.exit(0)

if __name__ == "__main__":
     print("Starting")
     signal.signal(signal.SIGINT, signal_handler)

     if len(sys.argv) != 2:
          print( "Usage: %s <IP of interface>" % (sys.argv[0], ) )
          sys.exit(1)
     iface = sys.argv[1]

     ProcessLoop(iface)
