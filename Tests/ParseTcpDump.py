import os
import sys


# 22:39:52.319429 STP 802.1d, Config, Flags [none], bridge-id 8000.18:62:2c:63:98:6b.8000, length 43
# 22:39:54.319476 STP 802.1d, Config, Flags [none], bridge-id 8000.18:62:2c:63:98:6b.8000, length 43
# 22:39:56.698326 IP Unknown-00-18-e7-08-02-81.home.47676 > BThomehub.home.domain: 52407+ PTR? 68.1.168.192.in-addr.arpa. (43)

while 1:
	try:
		line = sys.stdin.readline()
	except KeyboardInterrupt:
		break

	if not line:
		break

	print line
	spl = line.split(' ')

	print("Select="+spl[1])
	
	# 22:39:56.713245 IP BThomehub.home.domain > Unknown-00-18-e7-08-02-81.home.47676: 52407* 1/0/0 (87)
	if spl[1] == 'IP':
		laddr = spl[2]
		raddr = spl[4][:-1]
		print('IP:' + raddr + " " + laddr)
	# 22:39:56.319537 STP 802.1d, Config, Flags [none], bridge-id 8000.18:62:2c:63:98:6b.8000, length 43
	elif spl[1] == 'STP':
		bridge = spl[7]
		print('Spanning Tree Protocol:'+bridge)
	elif spl[1] == 'arp':
		# 22:14:28.425307 arp reply BThomehub.home is-at 18:62:2c:63:98:6a (oui Unknown)
		if spl[2] == 'reply':
			host = spl[3]
			hub = spl[5]
			print('Arp:' + host + " at " + hub)
		# 22:14:07.435267 arp who-has pcvero.home tell BThomehub.home
		elif spl[2] == 'who-has':
			who = spl[3]
			hub = spl[5]
			print('Arp:' + who + " tell " + hub)


