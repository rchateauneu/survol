import pcap
import dpkt

# Apparently nothing is portable enough...


#import pcap
#for ts, pkt in pcap.pcap():
#	print ts, `pkt`


pc = pcap.pcap()     # construct pcap object
pc.setfilter('icmp') # filter out unwanted packets
for timestamp, packet in pc:
    print( dpkt.ethernet.Ethernet(packet) ) 