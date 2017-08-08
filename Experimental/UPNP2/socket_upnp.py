#!/usr/bin/python
 
# Python program that can send out M-SEARCH messages using SSDP (in server
# mode), or listen for SSDP messages (in client mode).
 
import socket
import binascii
import signal
import sys
import re
import threading
import time

SSDP_GRP_ADDR = '239.255.255.250'
SSDP_PORT = 1900
#SSDP_ADDR = '224.1.1.1'
#SSDP_PORT = 1900

# POur etre vu dans UPNP inspector, il faut au moins un service,
# meme si on est un Basic device, meme si le service ne fonctionne pas.
# mais ca prend du temps oour etre detecte.

# Reconnu par personne.
# "ST: urn:schemas-upnp-org:service:XYZ_Connection:1\r\n"

# "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" \

# Il faut mettre le bon ST pour etre detecte par "Intel Device Sniffer".

# URL = "/rev_description.xml"
URL = ""

RESPONSE_ALL= \
'HTTP/1.1 200  OK\r\n' \
'ST:  uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d\r\n' \
'USN:  uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d\r\n' \
'EXT:  \r\n' \
'CACHE-CONTROL:  max-age=900\r\n' \
'SERVER:  Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION:  http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'

RESPONSE_LIGHT= \
'HTTP/1.1 200  OK\r\n' \
'ST:  urn:schemas-upnp-org:device:Basic:1\r\n' \
'USN:  uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d::urn:schemas-upnp-org:device:Basic:1\r\n' \
'EXT:  \r\n' \
'CACHE-CONTROL:  max-age=900\r\n' \
'SERVER:  Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION:  http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'

RESPONSE_DIMMING= \
'HTTP/1.1 200  OK\r\n' \
'ST:  urn:schemas-upnp-org:service:Potentiometre:1\r\n' \
'USN:  uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d::urn:schemas-upnp-org:service:Potentiometre:1\r\n' \
'EXT:  \r\n' \
'CACHE-CONTROL:  max-age=900\r\n' \
'SERVER:  Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION:  http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'


NOTIFY_ALL= \
'NOTIFY * HTTP/1.1\r\n' \
'NT: upnp:rootdevice\r\n' \
'CACHE-CONTROL: max-age=900\r\n' \
'HOST: 239.255.255.250:1900\r\n' \
'NTS: ssdp:alive\r\n' \
'USN: uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d::upnp:rootdevice\r\n' \
'SERVER: Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION: http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'

## DEVICE, NOT SERVICE !!!

NOTIFY_LIGHT= \
'NOTIFY * HTTP/1.1\r\n' \
'NT: urn:schemas-upnp-org:device:Basic:1\r\n' \
'CACHE-CONTROL: max-age=900\r\n' \
'HOST: 239.255.255.250:1900\r\n' \
'NTS: ssdp:alive\r\n' \
'USN: uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d::urn:schemas-upnp-org:device:Basic:1\r\n' \
'SERVER: Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION: http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'

NOTIFY_DIMMING= \
'NOTIFY * HTTP/1.1\r\n' \
'NT: urn:schemas-upnp-org:service:Potentiometre:1\r\n' \
'CACHE-CONTROL: max-age=900\r\n' \
'HOST: 239.255.255.250:1900\r\n' \
'NTS: ssdp:alive\r\n' \
'USN: uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d::urn:schemas-upnp-org:service:Potentiometre:1\r\n' \
'SERVER: Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION: http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'

NOTIFY_LAST= \
'NOTIFY * HTTP/1.1\r\n' \
'NT: uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d\r\n' \
'CACHE-CONTROL: max-age=900\r\n' \
'HOST: 239.255.255.250:1900\r\n' \
'NTS: ssdp:alive\r\n' \
'USN: uuid:066dd4d8-589b-4ad2-8237-d3b517b8e47d\r\n' \
'SERVER: Windows NT/5.0, UPnP/1.0, Intel CLR SDK/1.0\r\n' \
'LOCATION: http://%s:%d/%s\r\n' \
'Content-Length: 0\r\n' \
'\r\n'

# 'LOCATION: http://%s:%d/rev_description.xml\r\n' \
 
def ProcessLoop(iface):
     print("Location=%s:%d" % (iface, 8000) )
     cnt=0

     # This creates a UDP socket.
     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
     try:
          # Allow multiple sockets to use the same PORT number
          # We will need that if several processes are data providers.
          sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
     except AttributeError:
           pass

     sock.bind(('0.0.0.0', SSDP_PORT))

     # No need, to set multicast ttl on the receiver. Only for sender, and optional.
     # sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32) 
     sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

     #sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))

     # Surprisingly, this works.
     #mreq = struct.pack('4sl', socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
     #sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, mreq)
     
     sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(SSDP_GRP_ADDR) + socket.inet_aton(iface))

     while 1:
          cnt = cnt + 1
          print("Message %d wait" % cnt)
          try:
               data, addr = sock.recvfrom(1024)
          except socket.error as e:
               print( 'Exception', e )
          print( 'Addr=%s', addr )

          decod_str = data.decode("utf-8")
          print( 'decode = %s' % decod_str )

          if re.match( r'M-SEARCH.*', decod_str ) :
              print( "Sending answer to %s:%d" % addr )

              sockanswer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              sockanswer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              sockanswer.sendto( ( RESPONSE_ALL     % (iface, 8000, URL) ).encode("utf-8"), addr )
              sockanswer.sendto( ( RESPONSE_DIMMING % (iface, 8000, URL) ).encode("utf-8"), addr )
              sockanswer.sendto( ( RESPONSE_LIGHT   % (iface, 8000, URL) ).encode("utf-8"), addr )
              
              # Do not close too early otherwise nothing is sent.
              # sockanswer.close()


# Also used when leaving.
socknotify = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
try:
     # Allow multiple sockets to use the same PORT number
     # We will need that if several processes are data providers.
     socknotify.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
except AttributeError:
      pass

socknotify.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 3) 

def func_notify(iface):
     global SSDP_GRP_ADDR
     global SSDP_PORT
     
     notify_cnt = 0

     while 1:
          print( "Notifying %d" % notify_cnt )
          notify_cnt = notify_cnt + 1
          socknotify.sendto( ( NOTIFY_ALL     % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_ALL     % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_DIMMING % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_DIMMING % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_LAST    % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_LAST    % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_LIGHT   % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          socknotify.sendto( ( NOTIFY_LIGHT   % (iface, 8000, URL) ).encode("utf-8") , ( SSDP_GRP_ADDR, SSDP_PORT) )
          time.sleep(30)

# Ca apparanti dans Upnp inspector apres tres longtemps.

def send_notify_bye():
     global SSDP_GRP_ADDR
     global SSDP_PORT
     
     NOTIFY_BYE = \
          'NOTIFY * HTTP/1.1\r\n' \
          'NT: uuid:ba7f8f36-96b7-4224-ada4-f921efe554ec\r\n' \
          'HOST: 239.255.255.250:1900\r\n' \
          'NTS: ssdp:byebye\r\n' \
          'USN: uuid:ba7f8f36-96b7-4224-ada4-f921efe554ec\r\n' \
          'Content-Length: 0\r\n' \
          '\r\n'

     print( "Last notify" )
     socknotify.sendto( NOTIFY_BYE.encode("utf-8"), ( SSDP_GRP_ADDR, SSDP_PORT) )
          
def signal_handler(signal, frame):
     print('Leaving.')
     send_notify_bye()
     time.sleep(1)
     sys.exit(0)

if __name__ == "__main__":
     print("Starting")
     signal.signal(signal.SIGINT, signal_handler)

     host = socket.gethostbyname(socket.gethostname())
     print("host=%s" % host)

     iface = host # sys.argv[1]

     thread_notify = threading.Thread(target = func_notify, args = (iface, ) )
     # So all the threads exit when the main thread(non-daemon) exits.
     thread_notify.daemon = True
     thread_notify.start()

     ProcessLoop(iface)
